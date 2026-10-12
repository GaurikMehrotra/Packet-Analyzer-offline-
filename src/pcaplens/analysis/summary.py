"""Streaming pipeline with bounded retained metadata and explicit completeness."""

from collections import Counter
from collections.abc import Callable
import json
from pathlib import Path
from typing import Any

from pcaplens import __version__
from pcaplens.dissect import dns, http, tls
from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.dissect.ipv4 import Fragments
from pcaplens.dissect.registry import dissect
from pcaplens.filter.evaluator import evaluate
from pcaplens.filter.parser import parse as parse_filter
from pcaplens.flows.table import Flow, FlowTable
from pcaplens.formats.open import file_hash, packets
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits
from pcaplens.output.anonymize import Anonymizer
from pcaplens.output.redact import redact
from pcaplens.output.sanitize import sanitize


def analyze(
    path: Path,
    limits: Limits | None = None,
    *,
    checksum: bool = False,
    overlap: str = "first",
    expression: str | None = None,
    redaction: bool = True,
    anonymize: bool = False,
    on_progress: Callable[[int], None] | None = None,
) -> dict[str, Any]:
    limits = limits or Limits()
    predicate = parse_filter(expression, limits) if expression else None
    warnings = WarningLog(limits.max_warnings)
    try:
        initial_stat = path.stat()
        initial_identity: tuple[int, int, int, int] | None = (
            initial_stat.st_dev,
            initial_stat.st_ino,
            initial_stat.st_size,
            initial_stat.st_mtime_ns,
        )
    except OSError:
        initial_identity = None
    fragments = Fragments(limits, warnings)
    counts: Counter[str] = Counter()
    hierarchy: Counter[str] = Counter()
    talkers: Counter[str] = Counter()
    timeline: Counter[int] = Counter()
    metadata: dict[str, list[dict[str, Any]]] = {
        key: [] for key in ("flows", "dns", "http", "tls", "arp")
    }
    suppressed: Counter[str] = Counter()
    count = size = original_size = scanned = 0
    first: int | None = None
    last: int | None = None
    metadata_bytes = 0

    def retain(section: str, item: dict[str, Any]) -> None:
        nonlocal metadata_bytes
        item_size = len(json.dumps(item, ensure_ascii=True))
        if (
            len(metadata[section]) < limits.max_metadata
            and metadata_bytes + item_size <= limits.max_metadata_bytes
        ):
            metadata_bytes += item_size
            metadata[section].append(item)
        else:
            suppressed[section] += 1

    def application(
        section: str, data: bytes, context: dict[str, Any], methods: list[str] | None = None
    ) -> list[dict[str, Any]]:
        try:
            if section == "dns":
                retain(section, {**context, **dns.parse(data, limits)})
                return []
            else:
                values = (
                    http.parse(data, limits, warnings, methods)
                    if section == "http"
                    else tls.parse(data, limits)
                )
                for value in values:
                    retain(section, {**context, **value})
                return values
        except ParseError as error:
            warnings.add(error.warning)
        return []

    def finished(flow: Flow, reason: str) -> None:
        context: dict[str, Any] = {
            "a": {"ip": flow.key[1][0], "port": flow.key[1][1]},
            "b": {"ip": flow.key[2][0], "port": flow.key[2][1]},
        }
        requests: dict[int, list[str]] = {0: [], 1: []}
        for direction, stream in enumerate(flow.streams):
            for offset, data in stream.runs():
                if data.startswith(http.METHODS):
                    location = {
                        **context,
                        "direction": direction,
                        "stream_offset": offset,
                        "stream_limited": stream.limited,
                        "timestamp_ns": flow.first,
                    }
                    parsed = application("http", data, location)
                    requests[direction].extend(
                        message["method"] for message in parsed if not message["response"]
                    )
        for direction, stream in enumerate(flow.streams):
            for offset, data in stream.runs():
                location = {
                    **context,
                    "direction": direction,
                    "stream_offset": offset,
                    "stream_limited": stream.limited,
                    "timestamp_ns": flow.first,
                }
                if 53 in (flow.key[1][1], flow.key[2][1]):
                    reader = ByteReader(data)
                    messages = 0
                    try:
                        while reader.remaining:
                            messages += 1
                            if messages > limits.max_metadata:
                                raise ParseError("metadata_limit", "TCP DNS message cap reached")
                            application("dns", reader.take(reader.u16()), location)
                    except ParseError as error:
                        warnings.add(error.warning)
                if data.startswith(b"HTTP/1."):
                    application("http", data, location, requests[1 - direction])
                if data.startswith(b"\x16\x03"):
                    application("tls", data, location)
        retain("flows", flow.export(reason))

    table = FlowTable(limits, warnings, finished, overlap)
    for capture in packets(path, limits, warnings):
        scanned += 1
        if on_progress and scanned % 128 == 0:
            on_progress(scanned)
        packet = dissect(capture, limits, warnings, fragments, checksum)
        # Per-packet application signatures are evidence, not port-based certainty.
        dns_message: dict[str, Any] | None = None
        if packet.transport and 53 in (packet.sport, packet.dport):
            try:
                if packet.transport == "udp":
                    dns_message = dns.parse(packet.payload, limits)
                    packet.protocols.append("dns")
                elif packet.payload:
                    reader = ByteReader(packet.payload)
                    dns.parse(reader.take(reader.u16()), limits)
                    packet.protocols.append("dns")
            except ParseError as error:
                if packet.transport == "udp":
                    warnings.add(error.warning)
                # TCP messages can span segments; diagnose after reassembly, not prematurely.
        elif packet.payload.startswith(http.METHODS + (b"HTTP/1.",)):
            packet.protocols.append("http")
        elif packet.payload.startswith(b"\x16\x03"):
            packet.protocols.append("tls")
        if predicate and not evaluate(predicate, packet):
            continue
        count += 1
        size += packet.captured_length
        original_size += packet.original_length
        first = packet.timestamp_ns if first is None else min(first, packet.timestamp_ns)
        last = packet.timestamp_ns if last is None else max(last, packet.timestamp_ns)
        counts.update(packet.protocols)
        for index in range(1, len(packet.protocols) + 1):
            hierarchy["/".join(packet.protocols[:index])] += 1
        for address in (packet.src, packet.dst):
            if address:
                if address not in talkers and len(talkers) >= limits.max_flows:
                    suppressed["talkers"] += 1
                else:
                    talkers[address] += packet.captured_length
        second = packet.timestamp_ns // 1_000_000_000
        if second in timeline or len(timeline) < limits.max_metadata:
            timeline[second] += packet.captured_length
        else:
            suppressed["timeline"] += 1
        if "arp" in packet.protocols:
            retain(
                "arp",
                {
                    "timestamp_ns": packet.timestamp_ns,
                    "src": packet.src,
                    "dst": packet.dst,
                    **packet.metadata,
                },
            )
        if dns_message is not None:
            retain(
                "dns",
                {
                    "src": packet.src,
                    "dst": packet.dst,
                    "timestamp_ns": packet.timestamp_ns,
                    **dns_message,
                },
            )
        table.add(packet)
    if on_progress:
        on_progress(scanned)
    fragments.finish()
    table.finish()
    capture_hash: str | None = None
    try:
        capture_hash = file_hash(path, limits.max_capture_bytes)
        final_stat = path.stat()
        if initial_identity != (
            final_stat.st_dev,
            final_stat.st_ino,
            final_stat.st_size,
            final_stat.st_mtime_ns,
        ):
            capture_hash = None
            warnings.record(
                "capture_changed",
                "Capture changed during analysis; hash does not identify the analyzed bytes",
            )
    except ParseError as error:
        warnings.add(error.warning)
    except OSError:
        warnings.record("capture_io", "Capture unavailable during hashing")
    if suppressed:
        warnings.record("metadata_limit", "Retained metadata truncated; see suppressed counters")
    result: dict[str, Any] = {
        "scan": {
            "tool_version": __version__,
            "file_name": path.name,
            "sha256": capture_hash,
            "limits": limits.model_dump(),
            "checksum": checksum,
            "overlap_policy": overlap,
            "filter": expression,
            "redacted": redaction,
            "anonymized": anonymize,
        },
        "summary": {
            "scanned_packets": scanned,
            "packets": count,
            "captured_bytes": size,
            "original_bytes": original_size,
            "first_ns": first,
            "last_ns": last,
            "duration_seconds": (last - first) / 1e9
            if first is not None and last is not None
            else 0,
            "flow_instances": table.total,
            "reassembly_peak_accounted_bytes": table.budget.peak,
        },
        "protocols": dict(sorted(counts.items())),
        "hierarchy": dict(sorted(hierarchy.items())),
        "talkers": [
            {"ip": ip, "endpoint_bytes": value}
            for ip, value in sorted(talkers.items(), key=lambda item: (-item[1], item[0]))
        ],
        "timeline": [
            {"second": sec, "captured_bytes": value} for sec, value in sorted(timeline.items())
        ],
        "suppressed": dict(sorted(suppressed.items())),
        "warnings": warnings.export(),
        **metadata,
    }
    if redaction:
        result = redact(result)
    if anonymize:
        result = Anonymizer().apply(result)
    for section in metadata:
        result[section].sort(key=lambda row: repr(sorted(row.items())))
    return dict(sanitize(result))

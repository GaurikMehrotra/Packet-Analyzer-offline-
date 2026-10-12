"""Offline tshark field/summary/stream oracle; no live flags or payload exports."""

import argparse
import collections
import csv
import io
import json
import re
import shutil
import subprocess
import threading
from pathlib import Path

from compare import agreement
from pcaplens.analysis.summary import analyze
from pcaplens.dissect.errors import WarningLog
from pcaplens.dissect.ipv4 import Fragments
from pcaplens.dissect.registry import dissect
from pcaplens.flows.table import FlowTable, FlowKey
from pcaplens.formats.open import packets
from pcaplens.limits import Limits
from pcaplens.output.redact import redact
from pcaplens.output.sanitize import sanitize, text

FIELDS = [
    "frame.number",
    "frame.len",
    "frame.cap_len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.a",
    "http.request.method",
    "http.request.uri",
    "tcp.stream",
]
MAP = {"eth": "ethernet", "ip": "ipv4", "raw": None, "ethertype": None, "ipv6.hopopts": None}
SUPPORTED = {
    "ethernet",
    "sll",
    "vlan",
    "arp",
    "ipv4",
    "ipv6",
    "icmp",
    "icmpv6",
    "tcp",
    "udp",
    "dns",
    "http",
    "tls",
    "unknown",
    "unsupported",
}


def run(tool: str, *arguments: str) -> str:
    process = subprocess.Popen(
        [tool, *(["-n"] if "-r" in arguments else []), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    output = bytearray()
    capped = threading.Event()

    def drain():
        assert process.stdout is not None
        while chunk := process.stdout.read(65536):
            if len(output) + len(chunk) > 64 * 1024 * 1024:
                capped.set()
                process.kill()
                break
            output.extend(chunk)

    thread = threading.Thread(target=drain, daemon=True)
    thread.start()
    try:
        code = process.wait(timeout=60)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise
    finally:
        thread.join(timeout=5)
        if process.stdout:
            process.stdout.close()
    if capped.is_set():
        raise RuntimeError(
            "tshark output exceeded the 64 MiB oracle cap; use a smaller authorized capture"
        )
    if code:
        raise RuntimeError(
            f"tshark exited {code}; verify the installed version's documentation and capture validity"
        )
    return output.decode("utf-8", errors="replace")


def stream_bytes(path: Path, limits: Limits) -> dict[FlowKey, list[list[bytes]]]:
    values = collections.defaultdict(list)
    warnings = WarningLog(limits.max_warnings)
    fragments = Fragments(limits, warnings)

    def finished(flow, reason):
        if flow.streams:
            values[flow.key].append(
                [b"".join(data for _, data in stream.runs()) for stream in flow.streams]
            )

    table = FlowTable(limits, warnings, finished)
    for capture in packets(path, limits, warnings):
        table.add(dissect(capture, limits, warnings, fragments))
    table.finish()
    return values


def followed(tool: str, path: Path, index: int) -> tuple[list[bytes], list[str]]:
    output = run(tool, "-r", str(path), "-q", "-z", f"follow,tcp,raw,{index}")
    nodes = re.findall(r"^Node [01]: (.+)$", output, re.M)
    directions = [bytearray(), bytearray()]
    for line in output.splitlines():
        if re.fullmatch(r"\t?[0-9a-fA-F]+", line):
            directions[int(line.startswith("\t"))].extend(bytes.fromhex(line.strip()))
    return [bytes(value) for value in directions], nodes


def evaluate(tool: str, path: Path) -> dict:
    output = run(
        tool,
        "-2",
        "-r",
        str(path),
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "quote=d",
        *[argument for field in FIELDS for argument in ("-e", field)],
    )
    rows = [dict(zip(FIELDS, row)) for row in csv.reader(io.StringIO(output), delimiter="\t")]
    ours = analyze(path, redaction=False)
    counts = collections.Counter()
    hierarchy = collections.Counter()
    conversations = collections.defaultdict(lambda: [0, 0, 0])
    questions = collections.Counter()
    answers = collections.Counter()
    requests = collections.Counter()
    for row in rows:
        protocols = [MAP.get(protocol, protocol) for protocol in row["frame.protocols"].split(":")]
        protocols = [protocol for protocol in protocols if protocol]
        protocols = [p for i, p in enumerate(protocols) if i == 0 or p != protocols[i - 1]]
        counts.update(set(protocols))
        for index in range(1, len(protocols) + 1):
            hierarchy["/".join(protocols[:index])] += 1
        src, dst = row["ip.src"] or row["ipv6.src"], row["ip.dst"] or row["ipv6.dst"]
        for protocol in ("tcp", "udp"):
            if row[protocol + ".srcport"]:
                # Nested/tunneled protocol occurrences are outside the supported scope.
                endpoints = sorted(
                    [(src, int(row[protocol + ".srcport"])), (dst, int(row[protocol + ".dstport"]))]
                )
                key = repr((protocol, *endpoints))
                conversations[key][0] += 1
                conversations[key][1] += int(row["frame.len"])
                conversations[key][2] += int(row["frame.cap_len"])
        questions.update(filter(None, row["dns.qry.name"].split(",")))
        answers.update(filter(None, row["dns.a"].split(",")))
        if row["http.request.method"]:
            requests[(row["http.request.method"] + " " + row["http.request.uri"])] += 1
    our_conversations = collections.defaultdict(lambda: [0, 0, 0])
    for flow in ours["flows"]:
        endpoints = sorted(
            [(flow["a"]["ip"], flow["a"]["port"]), (flow["b"]["ip"], flow["b"]["port"])]
        )
        key = repr((flow["protocol"], *endpoints))
        our_conversations[key][0] += sum(flow["packets"])
        our_conversations[key][1] += sum(flow["original_bytes"])
        our_conversations[key][2] += sum(flow["captured_bytes"])
    explanation = (
        "pcaplens counts only implemented parser layers and application signatures. tshark may add data/extension layers, "
        "recognize more protocols, or dissect different fragment/stream completion packets. Inspect the named path before attributing correctness."
    )
    checks = [
        agreement(
            "packet_count",
            {"packets": ours["summary"]["packets"]},
            {"packets": len(rows)},
            "A difference indicates truncation, a configured limit, or unsupported container behavior; investigate the warnings.",
        ),
        agreement(
            "protocol_counts",
            {
                key: ours["protocols"].get(key, 0)
                for key in (counts.keys() | ours["protocols"].keys()) & SUPPORTED
            },
            {key: counts[key] for key in (counts.keys() | ours["protocols"].keys()) & SUPPORTED},
            explanation,
        ),
        agreement("protocol_hierarchy", ours["hierarchy"], dict(hierarchy), explanation),
        agreement(
            "conversation_packets",
            {key: value[0] for key, value in our_conversations.items()},
            {key: value[0] for key, value in conversations.items()},
            "Only packets with decoded transport endpoints are assigned. Fragment buffers, tuple reuse, eviction, or timeout may split conversations.",
        ),
        agreement(
            "conversation_bytes",
            {key: value[1] for key, value in our_conversations.items()},
            {key: value[1] for key, value in conversations.items()},
            "Original frame lengths match tshark conversation wire-byte totals; fragment attribution and retention limits can differ. Captured bytes are scored separately.",
        ),
        agreement(
            "conversation_captured_bytes",
            {key: value[2] for key, value in our_conversations.items()},
            {key: value[2] for key, value in conversations.items()},
            "Captured bytes use frame.cap_len, distinct from original frame.len when snaplen truncates packets.",
        ),
        agreement(
            "dns_queries",
            dict(
                collections.Counter(
                    q["name"] for message in ours["dns"] for q in message["questions"]
                )
            ),
            dict(questions),
            "Counts include queries repeated in responses. Compression, fragments, TCP gaps or parser limits require inspection.",
        ),
        agreement(
            "dns_a_answers",
            dict(
                collections.Counter(
                    record["value"]
                    for message in ours["dns"]
                    for record in message["records"]
                    if record["type"] == "A"
                )
            ),
            dict(answers),
            "Only A records are scored in this field; other DNS types have ground-truth tests.",
        ),
        agreement(
            "http_requests",
            dict(
                collections.Counter(
                    message["method"] + " " + message["url"]
                    for message in ours["http"]
                    if not message["response"]
                )
            ),
            dict(requests),
            "Raw request URI comparison uses explicit redaction opt-out in memory; default CLI exports redact query values.",
        ),
    ]
    # Compare stream bytes in memory; output hashes/equality only, no extracted bytes.
    our_streams = stream_bytes(path, Limits())
    stream_ids = sorted({int(row["tcp.stream"]) for row in rows if row["tcp.stream"]})
    stream_checks = []
    for index in stream_ids:
        reference, nodes = followed(tool, path, index)
        expected_nodes = sorted(nodes)
        actual_meta = next(
            (
                f
                for f in ours["flows"]
                if f["protocol"] == "tcp"
                and sorted([f"{f['a']['ip']}:{f['a']['port']}", f"{f['b']['ip']}:{f['b']['port']}"])
                == expected_nodes
            ),
            None,
        )
        if actual_meta is None:
            stream_checks.append(
                {
                    "stream": index,
                    "direction": None,
                    "equal": False,
                    "explanation": "No retained pcaplens conversation matches these endpoints; inspect limits or unsupported protocols.",
                }
            )
            continue
        directions = (
            [0, 1]
            if nodes and nodes[0] == f"{actual_meta['a']['ip']}:{actual_meta['a']['port']}"
            else [1, 0]
        )
        for direction, ours_direction in enumerate(directions):
            key = (
                "tcp",
                (actual_meta["a"]["ip"], actual_meta["a"]["port"]),
                (actual_meta["b"]["ip"], actual_meta["b"]["port"]),
            )
            instances = our_streams.get(key, [])
            exact = (
                len(instances) == 1
                and instances[0][ours_direction] == reference[direction]
                and actual_meta["streams"][ours_direction]["gap_bytes"] == 0
                and not actual_meta["streams"][ours_direction]["limited"]
            )
            stream_checks.append(
                {
                    "stream": index,
                    "direction": direction,
                    "equal": exact,
                    "reference_bytes": len(reference[direction]),
                    "explanation": None
                    if exact
                    else "Gaps, overlap policy, stream caps, or tuple reuse differ; inspect follow metadata and packet sequence fields.",
                }
            )
    tables = run(tool, "-r", str(path), "-q", "-z", "io,phs", "-z", "conv,tcp", "-z", "conv,udp")
    table_protocol = ""
    table_packets = {}
    table_bytes = {}
    rounded_byte_rows = 0
    for line in tables.splitlines():
        if line.strip() in ("TCP Conversations", "UDP Conversations"):
            table_protocol = line.strip().split()[0].lower()
        if "<->" not in line or not table_protocol:
            continue
        tokens = line.split()
        if len(tokens) < 12:
            raise RuntimeError(
                "Unexpected tshark conversation table layout; consult installed documentation"
            )
        endpoints = []
        for endpoint in (tokens[0], tokens[2]):
            address, port = endpoint.rsplit(":", 1)
            endpoints.append((address.strip("[]"), int(port)))
        key = repr((table_protocol, *sorted(endpoints)))
        table_packets[key] = int(tokens[9])
        if tokens[11] == "bytes":
            table_bytes[key] = int(tokens[10])
        else:
            rounded_byte_rows += 1
    checks.extend(
        [
            agreement(
                "conversation_table_packets",
                {key: value[0] for key, value in our_conversations.items()},
                table_packets,
                "Actual -z conv,tcp/udp packet totals, matched by canonical numeric endpoints.",
            ),
            agreement(
                "conversation_table_exact_bytes",
                {key: our_conversations[key][1] for key in table_bytes if key in our_conversations},
                table_bytes,
                "Actual -z conv wire-byte totals. Rows printed in rounded kB/MB units are separately marked unmeasured; exact field-derived bytes remain available.",
            ),
        ]
    )
    truth = json.loads(
        (Path(__file__).resolve().parents[1] / "fixtures/ground_truth/expected.json").read_text()
    )
    synthetic = ours["scan"]["sha256"] in truth["hashes"].values()
    for check in checks:
        for difference in check["differences"]:
            difference["status"] = "unexplained"
            if synthetic and check["field"] == "protocol_hierarchy":
                if difference["key"] == "ethernet/ipv4/data":
                    difference.update(
                        status="verified_scope_difference",
                        explanation="tshark exposes the payloads of two non-final IPv4 fragments as data. pcaplens records IPv4 and buffers them until the datagram completes; it has no opaque data layer.",
                    )
                elif difference["key"] == "ethernet/ipv4/tcp/http/data":
                    difference.update(
                        status="verified_scope_difference",
                        explanation="tshark's frame.protocols adds data for the five-byte synthetic HTTP response body. pcaplens retains its length and SHA-256 under HTTP metadata rather than creating a body-protocol hierarchy node.",
                    )
    return {
        "file": path.name,
        "checks": checks,
        "streams": stream_checks,
        "warnings": ours["warnings"],
        "reference_tables": tables.splitlines(),
        "conversation_table_rounded_byte_rows_unmeasured": rounded_byte_rows,
        "reference_normalization": {
            "aliases_and_transparent_layers": MAP,
            "counts": "packets containing a layer, not repeated record occurrences",
            "consecutive_duplicate_layers": "collapsed",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("captures", type=Path, nargs="+")
    parser.add_argument("--tshark", default=shutil.which("tshark"))
    parser.add_argument("--output", type=Path, default=Path("results/oracle.json"))
    parser.add_argument(
        "--no-redact", action="store_true", help="Explicitly retain sensitive disagreement text"
    )
    args = parser.parse_args()
    if not args.tshark:
        parser.error("Install tshark or specify --tshark; no oracle result has been fabricated")
    registry = run(args.tshark, "-G", "fields")
    available = {
        line.split("\t")[2]
        for line in registry.splitlines()
        if line.startswith("F\t") and len(line.split("\t")) > 2
    }
    missing = set(FIELDS) - available
    if missing:
        parser.error(
            f"Installed tshark does not register fields: {sorted(missing)}; consult tshark -h and -G fields"
        )
    result = {
        "tshark_version": run(args.tshark, "--version").splitlines()[0],
        "scope": "offline; exact comparisons; empty fields are unmeasured; raw evidence local only",
        "captures": [evaluate(args.tshark, capture) for capture in args.captures],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    result = sanitize(result if args.no_redact else redact(result))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        text(
            f"Saved {args.output}; inspect every differences entry. Public-capture reports must remain ignored."
        )
    )


if __name__ == "__main__":
    main()

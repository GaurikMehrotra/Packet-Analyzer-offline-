"""DNS questions/records with visited-offset compression-loop rejection."""

import ipaddress
import hashlib
from typing import Any

from pcaplens.dissect.errors import ParseError
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits

TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
}


def name(reader: ByteReader, limits: Limits) -> str:
    position = reader.position
    end: int | None = None
    seen: set[int] = set()
    labels: list[str] = []
    wire_length = 1
    hops = 0
    while True:
        if position in seen:
            raise ParseError("dns_loop", "DNS compression pointer loop", position)
        seen.add(position)
        size = reader.at(position, 1)[0]
        if size & 0xC0 == 0xC0:
            hops += 1
            if hops > limits.max_dns_hops:
                raise ParseError("dns_hop_limit", "DNS compression hop cap exceeded")
            pointer = int.from_bytes(reader.at(position, 2), "big") & 0x3FFF
            if end is None:
                end = position + 2
            position = pointer
            continue
        if size & 0xC0:
            raise ParseError("dns_label", "Unsupported DNS label encoding")
        position += 1
        if size == 0:
            reader.position = end if end is not None else position
            return ".".join(labels)
        wire_length += size + 1
        if wire_length > 255:
            raise ParseError("dns_name_length", "DNS name exceeds 255 wire bytes")
        label = reader.at(position, size)
        labels.append(label.decode("ascii", errors="backslashreplace"))
        position += size


def parse(data: bytes, limits: Limits) -> dict[str, Any]:
    reader = ByteReader(data)
    ident, flags, qd, an, ns, ar = reader.unpack("!6H")
    if qd + an + ns + ar > limits.max_dns_records:
        raise ParseError("dns_record_limit", "DNS record budget exceeded")
    questions: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    for _ in range(qd):
        label = name(reader, limits)
        kind, cls = reader.u16(), reader.u16()
        questions.append({"name": label, "type": TYPES.get(kind, str(kind)), "class": cls})
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            label = name(reader, limits)
            kind, cls, ttl, length = reader.unpack("!HHIH")
            start = reader.position
            raw = reader.take(length)
            value: Any = {"length": length, "sha256": hashlib.sha256(raw).hexdigest()}
            nested = ByteReader(data)
            nested.position = start
            if kind in (1, 28):
                expected = 4 if kind == 1 else 16
                if length != expected:
                    raise ParseError("dns_rdata", "Invalid address record length")
                value = str(ipaddress.ip_address(raw))
            elif kind in (2, 5, 12):
                value = name(nested, limits)
            elif kind == 15:
                value = {"preference": nested.u16(), "exchange": name(nested, limits)}
            elif kind == 33:
                priority, weight, port = nested.unpack("!HHH")
                value = {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": name(nested, limits),
                }
            elif kind == 6:
                mname, rname = name(nested, limits), name(nested, limits)
                numbers = nested.unpack("!5I")
                value = {"mname": mname, "rname": rname, "timers": list(numbers)}
            elif kind == 16:
                texts = ByteReader(raw)
                values: list[str] = []
                while texts.remaining:
                    if len(values) >= limits.max_options:
                        raise ParseError("option_limit", "DNS TXT string count exceeded")
                    values.append(texts.take(texts.u8()).decode("utf-8", errors="replace"))
                value = values
            if kind in (2, 5, 6, 12, 15, 33) and nested.position != start + length:
                raise ParseError("dns_rdata", "DNS record does not match declared RDATA length")
            records.append(
                {
                    "section": section,
                    "name": label,
                    "type": TYPES.get(kind, str(kind)),
                    "class": cls,
                    "ttl": ttl,
                    "value": value,
                }
            )
    return {
        "id": ident,
        "response": bool(flags & 0x8000),
        "rcode": flags & 15,
        "truncated": bool(flags & 0x200),
        "questions": questions,
        "records": records,
    }

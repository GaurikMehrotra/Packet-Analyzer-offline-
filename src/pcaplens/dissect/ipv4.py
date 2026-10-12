"""IPv4 header parsing and bounded, overlap-rejecting fragment reassembly."""

import ipaddress
from collections import OrderedDict
from dataclasses import dataclass, field

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits
from pcaplens.models import Packet


def checksum(data: bytes) -> int:
    reader = ByteReader(data + (b"\0" if len(data) % 2 else b""))
    total = 0
    while reader.remaining:
        total += reader.u16()
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def parse(
    reader: ByteReader, packet: Packet, verify: bool, warnings: WarningLog, limits: Limits
) -> tuple[int, bytes, int, bool, int]:
    start = reader.position
    version_ihl, _, length, ident, fragment, ttl, proto, _, src, dst = reader.unpack(
        "!BBHHHBBH4s4s"
    )
    ihl = (version_ihl & 15) * 4
    if version_ihl >> 4 != 4 or ihl < 20 or length < ihl:
        raise ParseError("ipv4_header", "Invalid IPv4 version or lengths")
    opts = ByteReader(reader.take(ihl - 20))
    count = 0
    while opts.remaining:
        count += 1
        if count > limits.max_options:
            raise ParseError("option_limit", "IPv4 option count exceeded")
        code = opts.u8()
        if code == 0:
            break
        if code != 1:
            size = opts.u8()
            if size < 2:
                raise ParseError("ipv4_option", "Invalid IPv4 option length")
            opts.take(size - 2)
    packet.protocols.append("ipv4")
    packet.src, packet.dst = str(ipaddress.IPv4Address(src)), str(ipaddress.IPv4Address(dst))
    packet.metadata.update({"ip.ttl": ttl, "ip.id": ident})
    if verify and checksum(reader.at(start, ihl)):
        warnings.record("checksum", "IPv4 header checksum mismatch; offload may affect capture")
    payload = reader.take(length - ihl)
    return proto, payload, (fragment & 0x1FFF) * 8, bool(fragment & 0x2000), ident


@dataclass
class FragmentSet:
    timestamp: int
    pieces: dict[int, bytes] = field(default_factory=dict)
    end: int | None = None
    header_length: int = 20


class Fragments:
    def __init__(self, limits: Limits, warnings: WarningLog) -> None:
        self.limits, self.warnings = limits, warnings
        self.items: OrderedDict[tuple[str, str, int, int], FragmentSet] = OrderedDict()
        self.used = 0

    def discard(self, key: tuple[str, str, int, int], reason: str) -> None:
        old = self.items.pop(key)
        self.used -= sum(map(len, old.pieces.values()))
        self.warnings.record(reason, "IPv4 fragment set discarded; datagram incomplete")

    def add(
        self,
        packet: Packet,
        proto: int,
        data: bytes,
        offset: int,
        more: bool,
        ident: int,
        header_length: int = 20,
    ) -> bytes | None:
        for key, value in list(self.items.items()):
            if packet.timestamp_ns - value.timestamp > self.limits.fragment_timeout * 1_000_000_000:
                self.discard(key, "fragment_timeout")
        key = packet.src, packet.dst, proto, ident
        if not data or offset + len(data) > 65535 - 20 or (more and len(data) % 8):
            raise ParseError("fragment_length", "Invalid IPv4 fragment length")
        if key not in self.items:
            if len(self.items) >= self.limits.max_fragment_buffers:
                self.discard(next(iter(self.items)), "fragment_limit")
            self.items[key] = FragmentSet(packet.timestamp_ns)
        value = self.items[key]
        if offset == 0:
            value.header_length = header_length
        if offset + len(data) > 65535 - value.header_length or any(
            pos + len(piece) > 65535 - value.header_length for pos, piece in value.pieces.items()
        ):
            self.discard(key, "fragment_length")
            return None
        for pos, old in value.pieces.items():
            if pos == offset and old == data:
                return None
            if pos < offset + len(data) and offset < pos + len(old):
                self.discard(key, "fragment_overlap")
                return None
        if (
            self.used + len(data) > self.limits.max_fragment_bytes
            or len(value.pieces) >= self.limits.max_segment_count
        ):
            self.discard(key, "fragment_bytes_limit")
            return None
        end = offset + len(data)
        if (value.end is not None and end > value.end) or (
            not more
            and (
                value.end is not None
                and value.end != end
                or any(p + len(v) > end for p, v in value.pieces.items())
            )
        ):
            self.discard(key, "fragment_conflict")
            return None
        value.pieces[offset] = data
        self.used += len(data)
        if not more:
            value.end = end
        cursor = 0
        ordered = sorted(value.pieces.items())
        for pos, piece in ordered:
            if pos != cursor:
                return None
            cursor += len(piece)
        if cursor != value.end:
            return None
        result = b"".join(piece for _, piece in ordered)
        self.items.pop(key)
        self.used -= len(result)
        return result

    def finish(self) -> None:
        for key in list(self.items):
            self.discard(key, "fragment_incomplete")

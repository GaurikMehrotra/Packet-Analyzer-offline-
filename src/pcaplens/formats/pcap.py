"""Streaming classic PCAP with both byte orders and timestamp precisions."""

from collections.abc import Iterator

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.reader_base import ByteReader, StreamReader
from pcaplens.limits import Limits
from pcaplens.models import CapturePacket

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1000),
    b"\xa1\xb2\xc3\xd4": (">", 1000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


def read(
    source: StreamReader, magic: bytes, limits: Limits, warnings: WarningLog
) -> Iterator[CapturePacket]:
    endian, multiplier = MAGIC[magic]
    major, minor, _, _, snaplen, network = ByteReader(source.take(20)).unpack(endian + "HHiiII")
    if (major, minor) != (2, 4) or not 0 < snaplen <= limits.max_packet_length:
        raise ParseError("pcap_header", "Unsupported version or snaplen")
    link = network & 0xFFFF
    for _ in range(limits.max_packets):
        raw = source.take(16, eof=True)
        if not raw:
            return
        sec, fraction, captured, original = ByteReader(raw).unpack(endian + "IIII")
        if (
            captured > snaplen
            or captured > limits.max_packet_length
            or original < captured
            or original > limits.max_packet_length
        ):
            raise ParseError("packet_length", "Invalid captured/original length", source.position)
        if fraction >= 1_000_000_000 // multiplier:
            raise ParseError("timestamp", "Invalid timestamp fraction", source.position)
        yield CapturePacket(
            sec * 1_000_000_000 + fraction * multiplier, source.take(captured), original, link
        )
    if source.take(1, eof=True):
        warnings.record("packet_limit", "Stopped at maximum packets")

"""UDP length bounds and optional pseudo-header checksum validation."""

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.dissect.ipv4 import checksum
from pcaplens.formats.reader_base import ByteReader
from pcaplens.models import Packet


def parse(
    reader: ByteReader, packet: Packet, verify: bool, warnings: WarningLog, pseudo: bytes
) -> None:
    sport, dport, size, check = reader.unpack("!HHHH")
    if size < 8 or size > len(reader.data):
        raise ParseError("udp_length", "Invalid UDP length")
    packet.sport, packet.dport = sport, dport
    packet.transport = "udp"
    packet.protocols.append("udp")
    packet.payload = reader.take(size - 8)
    if verify and check and checksum(pseudo + reader.at(0, size)):
        warnings.record("checksum", "UDP checksum mismatch; capture offload is possible")
    if verify and not check and "ipv6" in packet.protocols:
        warnings.record("checksum", "IPv6 UDP checksum missing")

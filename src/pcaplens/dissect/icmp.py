"""ICMP/ICMPv6 common fields; embedded datagrams remain uninterpreted."""

from pcaplens.dissect.errors import WarningLog
from pcaplens.dissect.ipv4 import checksum
from pcaplens.formats.reader_base import ByteReader
from pcaplens.models import Packet


def parse(
    reader: ByteReader,
    packet: Packet,
    v6: bool,
    verify: bool,
    warnings: WarningLog,
    pseudo: bytes = b"",
) -> None:
    kind, code, _ = reader.unpack("!BBH")
    packet.protocols.append("icmpv6" if v6 else "icmp")
    packet.metadata.update({"icmp.type": kind, "icmp.code": code})
    if kind in ((128, 129) if v6 else (0, 8)):
        ident, sequence = reader.unpack("!HH")
        packet.metadata.update({"icmp.identifier": ident, "icmp.sequence": sequence})
    else:
        reader.take(4)
    if verify and checksum(pseudo + reader.data):
        warnings.record("checksum", "ICMP checksum mismatch; capture offload is possible")

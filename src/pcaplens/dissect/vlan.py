"""Bounded 802.1Q/802.1ad tag stack."""

from pcaplens.dissect.errors import ParseError
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits
from pcaplens.models import Packet


def parse(reader: ByteReader, kind: int, packet: Packet, limits: Limits) -> int:
    tags: list[int] = []
    while kind in (0x8100, 0x88A8):
        if len(tags) >= limits.max_headers:
            raise ParseError("header_limit", "VLAN stack exceeds header budget")
        tags.append(reader.u16() & 0xFFF)
        kind = reader.u16()
    if tags:
        packet.protocols.append("vlan")
        packet.metadata["vlans"] = tags
    return kind

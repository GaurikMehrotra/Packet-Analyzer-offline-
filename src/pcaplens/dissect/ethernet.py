"""Ethernet II: destination(6), source(6), EtherType(2)."""

from pcaplens.formats.reader_base import ByteReader
from pcaplens.models import Packet


def parse(reader: ByteReader, packet: Packet) -> int:
    packet.metadata["mac.dst"] = reader.take(6).hex(":")
    packet.metadata["mac.src"] = reader.take(6).hex(":")
    packet.protocols.append("ethernet")
    return reader.u16()

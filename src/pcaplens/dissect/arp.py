"""ARP lengths are validated; Ethernet/IPv4 address mapping only."""

import ipaddress

from pcaplens.formats.reader_base import ByteReader
from pcaplens.models import Packet


def parse(reader: ByteReader, packet: Packet) -> None:
    hardware, protocol, hlen, plen, operation = reader.unpack("!HHBBH")
    sender_hw, sender_ip = reader.take(hlen), reader.take(plen)
    target_hw, target_ip = reader.take(hlen), reader.take(plen)
    packet.protocols.append("arp")
    packet.metadata["arp.operation"] = operation
    if (hardware, protocol, hlen, plen) == (1, 0x800, 6, 4):
        packet.src = str(ipaddress.IPv4Address(sender_ip))
        packet.dst = str(ipaddress.IPv4Address(target_ip))
        packet.metadata.update(
            {"arp.mac": sender_hw.hex(":"), "arp.target_mac": target_hw.hex(":")}
        )

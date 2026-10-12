"""Dispatch by declared types, never by arbitrary Python code."""

import ipaddress
import struct

from pcaplens.dissect import arp, ethernet, icmp, ipv4, ipv6, tcp, udp, vlan
from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits
from pcaplens.models import CapturePacket, Packet


def dissect(
    capture: CapturePacket,
    limits: Limits,
    warnings: WarningLog,
    fragments: ipv4.Fragments,
    verify: bool = False,
) -> Packet:
    packet = Packet(capture.timestamp_ns, len(capture.data), capture.original_length)
    reader = ByteReader(capture.data)
    warning_index, warning_count = len(warnings.items), warnings.count
    try:
        if capture.link_type == 1:
            kind = vlan.parse(reader, ethernet.parse(reader, packet), packet, limits)
        elif capture.link_type == 113:
            packet.protocols.append("sll")
            packet_type, hardware, address_length = reader.unpack("!HHH")
            address = reader.take(8)
            if address_length > 8:
                raise ParseError("sll_header", "Linux SLL address length exceeds fixed field")
            packet.metadata.update({"sll.packet_type": packet_type, "sll.hardware": hardware})
            if address_length == 6:
                packet.metadata["mac.src"] = ByteReader(address).take(6).hex(":")
            kind = reader.u16()
        elif capture.link_type in (101, 228, 229):
            version = reader.at(0, 1)[0] >> 4
            if capture.link_type in (228, 229) and version != (
                4 if capture.link_type == 228 else 6
            ):
                raise ParseError(
                    "link_protocol", "Raw IP version does not match declared link type"
                )
            kind = {4: 0x800, 6: 0x86DD}.get(version, 0)
        else:
            packet.protocols.append("unsupported")
            warnings.record("link_type", f"Unsupported link type {capture.link_type}")
            return packet
        if kind == 0x806:
            arp.parse(reader, packet)
            return packet
        if kind == 0x800:
            ip_start = reader.position
            proto, payload, offset, more, ident = ipv4.parse(
                reader, packet, verify, warnings, limits
            )
            if offset or more:
                packet.metadata["fragment"] = True
                header_length = (reader.at(ip_start, 1)[0] & 15) * 4
                result = fragments.add(packet, proto, payload, offset, more, ident, header_length)
                if result is None:
                    return packet
                payload = result
                packet.metadata["fragment_reassembled"] = True
            pseudo = (
                ipaddress.ip_address(packet.src).packed
                + ipaddress.ip_address(packet.dst).packed
                + struct.pack("!BBH", 0, proto, len(payload))
            )
        elif kind == 0x86DD:
            proto, payload = ipv6.parse(reader, packet, limits, warnings)
            pseudo = (
                ipaddress.ip_address(packet.src).packed
                + ipaddress.ip_address(packet.dst).packed
                + struct.pack("!I3xB", len(payload), proto)
            )
        else:
            packet.protocols.append("unknown")
            return packet
        transport = ByteReader(payload)
        if proto == 6:
            tcp.parse(transport, packet, limits, verify, warnings, pseudo)
        elif proto == 17:
            # UDP's declared length, rather than trailing IP padding, belongs in the pseudo-header.
            size = int.from_bytes(transport.at(4, 2), "big")
            udp_pseudo = (
                pseudo[:-2] + struct.pack("!H", size)
                if kind == 0x800
                else (pseudo[:-8] + struct.pack("!I3xB", size, proto))
            )
            udp.parse(transport, packet, verify, warnings, udp_pseudo)
        elif proto in (1, 58):
            icmp.parse(
                transport, packet, proto == 58, verify, warnings, pseudo if proto == 58 else b""
            )
        elif proto != 59:
            packet.protocols.append("unknown")
    except ParseError as error:
        warnings.add(error.warning)
        packet.metadata["parse_incomplete"] = True
    finally:
        packet.warnings = warnings.items[warning_index:]
        packet.warnings_suppressed = warnings.count - warning_count - len(packet.warnings)
    return packet

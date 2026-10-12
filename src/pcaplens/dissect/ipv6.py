"""IPv6 and bounded extension headers. Non-atomic IPv6 fragments are skipped."""

import ipaddress

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits
from pcaplens.models import Packet


def parse(
    reader: ByteReader, packet: Packet, limits: Limits, warnings: WarningLog
) -> tuple[int, bytes]:
    version, length, following, hop, src, dst = reader.unpack("!IHBB16s16s")
    if version >> 28 != 6:
        raise ParseError("ipv6_header", "Invalid IPv6 version")
    packet.protocols.append("ipv6")
    packet.src, packet.dst = str(ipaddress.IPv6Address(src)), str(ipaddress.IPv6Address(dst))
    packet.metadata["ip.ttl"] = hop
    payload = ByteReader(reader.take(length))
    count = 0
    while following in (0, 43, 44, 51, 60):
        count += 1
        if count > limits.max_ipv6_extensions:
            raise ParseError("ipv6_extension_limit", "IPv6 extension chain exceeds budget")
        kind = following
        following, size = payload.u8(), payload.u8()
        if kind == 44:
            field = payload.u16()
            payload.take(4)
            if field & 0xFFF9:
                warnings.record("ipv6_fragment", "Non-atomic IPv6 fragments unsupported")
                return 59, b""
        elif kind == 51:
            size_bytes = (size + 2) * 4
            if size_bytes < 12:
                raise ParseError("ipv6_extension", "Invalid AH header length")
            payload.take(size_bytes - 2)
        else:
            extension = ByteReader(payload.take((size + 1) * 8 - 2))
            if kind in (0, 60):
                options = 0
                while extension.remaining:
                    options += 1
                    if options > limits.max_options:
                        raise ParseError("option_limit", "IPv6 option count exceeds budget")
                    code = extension.u8()
                    if code != 0:
                        extension.take(extension.u8())
    if length == 0:
        warnings.record("ipv6_jumbo", "IPv6 jumbograms unsupported")
    packet.metadata["ipv6.extensions"] = count
    return following, payload.take(payload.remaining)

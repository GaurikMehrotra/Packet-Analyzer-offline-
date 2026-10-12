"""Section-aware PCAPNG: SHB, IDB, EPB, obsolete PB and SPB."""

from collections.abc import Iterator

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.reader_base import ByteReader, StreamReader
from pcaplens.limits import Limits
from pcaplens.models import CapturePacket

SHB = b"\x0a\x0d\x0d\x0a"


def options(raw: bytes, endian: str, limits: Limits) -> list[tuple[int, bytes]]:
    reader = ByteReader(raw)
    result: list[tuple[int, bytes]] = []
    while reader.remaining:
        code, length = reader.unpack(endian + "HH")
        if code == 0:
            if length != 0:
                raise ParseError("option", "Invalid end-of-options")
            return result
        if len(result) >= limits.max_options:
            raise ParseError("option_limit", "Too many PCAPNG options")
        value = reader.take(length)
        reader.take((-length) % 4)
        result.append((code, value))
    return result


def read(
    source: StreamReader, magic: bytes, limits: Limits, warnings: WarningLog
) -> Iterator[CapturePacket]:
    endian = "<"
    interfaces: list[tuple[int, int, int, int]] = []
    count = 0
    blocks = 0
    kind_raw = magic
    while kind_raw:
        blocks += 1
        if blocks > limits.max_blocks:
            raise ParseError("block_limit", "PCAPNG block count exceeds budget")
        length_raw = source.take(4)
        if kind_raw == SHB:
            bom = source.take(4)
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ParseError("byte_order", "Invalid PCAPNG byte-order magic")
            length = ByteReader(length_raw).unpack(endian + "I")[0]
            if length < 28 or length % 4 or length > limits.max_block_length:
                raise ParseError("block_length", "Invalid section block length")
            rest = ByteReader(source.take(length - 12))
            major, minor = rest.unpack(endian + "HH")
            rest.take(8)
            if (major, minor) != (1, 0):
                raise ParseError("pcapng_version", "Unsupported section version")
            options(rest.take(rest.remaining - 4), endian, limits)
            if rest.unpack(endian + "I")[0] != length:
                raise ParseError("block_trailer", "Section length mismatch")
            interfaces.clear()
        else:
            kind = ByteReader(kind_raw).unpack(endian + "I")[0]
            length = ByteReader(length_raw).unpack(endian + "I")[0]
            if length < 12 or length % 4 or length > limits.max_block_length:
                raise ParseError("block_length", "Invalid PCAPNG block length")
            reader = ByteReader(source.take(length - 8))
            body = ByteReader(reader.take(length - 12))
            if reader.unpack(endian + "I")[0] != length:
                raise ParseError("block_trailer", "PCAPNG block length mismatch")
            if kind == 1:
                if len(interfaces) >= limits.max_interfaces:
                    raise ParseError("interface_limit", "Too many capture interfaces")
                link, _, snaplen = body.unpack(endian + "HHI")
                if snaplen > limits.max_packet_length:
                    raise ParseError("packet_length", "Interface snaplen exceeds limit")
                resolution, offset = 1_000_000, 0
                for code, value in options(body.take(body.remaining), endian, limits):
                    if code == 9:
                        if len(value) != 1:
                            raise ParseError("timestamp", "Invalid timestamp resolution option")
                        exponent = ByteReader(value).u8()
                        resolution = 2 ** (exponent & 127) if exponent & 128 else 10**exponent
                    if code == 14:
                        if len(value) != 8:
                            raise ParseError("timestamp", "Invalid timestamp offset option")
                        offset = ByteReader(value).unpack(endian + "q")[0]
                interfaces.append((link, snaplen, resolution, offset))
            elif kind in (2, 3, 6):
                if count >= limits.max_packets:
                    warnings.record("packet_limit", "Stopped at maximum packets")
                    return
                if kind == 3:
                    interface, stamp = 0, 0
                    original = body.unpack(endian + "I")[0]
                    if not interfaces:
                        raise ParseError("interface", "Packet without interface")
                    snaplen = interfaces[0][1]
                    captured = min(original, snaplen) if snaplen else original
                    warnings.record("timestamp_missing", "Simple packet block has no timestamp")
                else:
                    if kind == 2:
                        interface, _ = body.unpack(endian + "HH")
                    else:
                        interface = body.unpack(endian + "I")[0]
                    hi, lo, captured, original = body.unpack(endian + "IIII")
                    stamp = (hi << 32) | lo
                if interface >= len(interfaces):
                    raise ParseError("interface", "Unknown packet interface")
                link, snaplen, resolution, offset = interfaces[interface]
                if (
                    captured > limits.max_packet_length
                    or original > limits.max_packet_length
                    or captured > original
                    or (snaplen and captured > snaplen)
                ):
                    raise ParseError("packet_length", "Invalid PCAPNG packet length")
                packet = body.take(captured)
                body.take((-captured) % 4)
                if kind != 3:
                    options(body.take(body.remaining), endian, limits)
                elif body.remaining:
                    raise ParseError("block_length", "Unexpected simple packet block bytes")
                count += 1
                yield CapturePacket(
                    stamp * 1_000_000_000 // resolution + offset * 1_000_000_000,
                    packet,
                    original,
                    link,
                    interface,
                )
            else:
                warnings.record("unknown_block", f"Skipped PCAPNG block type {kind}")
        kind_raw = source.take(4, eof=True)

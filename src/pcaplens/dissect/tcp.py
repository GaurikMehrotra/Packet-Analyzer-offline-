"""TCP fixed header and bounded TLV options."""

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.dissect.ipv4 import checksum
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits
from pcaplens.models import Packet


def parse(
    reader: ByteReader,
    packet: Packet,
    limits: Limits,
    verify: bool,
    warnings: WarningLog,
    pseudo: bytes,
) -> None:
    sport, dport, seq, ack, offset, flags, window, _, urgent = reader.unpack("!HHIIBBHHH")
    size = (offset >> 4) * 4
    if size < 20:
        raise ParseError("tcp_header", "TCP data offset below fixed header")
    opts = ByteReader(reader.take(size - 20))
    count = 0
    options: list[dict[str, object]] = []
    while opts.remaining:
        count += 1
        if count > limits.max_options:
            raise ParseError("option_limit", "TCP option count exceeds budget")
        kind = opts.u8()
        if kind == 0:
            options.append({"kind": "end"})
            break
        if kind == 1:
            options.append({"kind": "nop"})
        else:
            length = opts.u8()
            if length < 2:
                raise ParseError("tcp_option", "Invalid TCP option length")
            value = ByteReader(opts.take(length - 2))
            option: dict[str, object] = {"kind": kind, "length": length}
            expected = {2: 4, 3: 3, 4: 2, 8: 10}.get(kind)
            if expected is not None and length != expected:
                raise ParseError("tcp_option", "Invalid known TCP option length")
            if kind == 2:
                option["mss"] = value.u16()
            elif kind == 3:
                option["window_scale"] = value.u8()
            elif kind == 8:
                option["timestamp"], option["timestamp_echo"] = value.u32(), value.u32()
            elif kind == 5:
                if value.remaining % 8:
                    raise ParseError("tcp_option", "Invalid SACK block length")
                option["sack_blocks"] = [value.unpack("!II") for _ in range(value.remaining // 8)]
            options.append(option)
    packet.sport, packet.dport, packet.seq, packet.ack, packet.flags = sport, dport, seq, ack, flags
    packet.transport = "tcp"
    packet.protocols.append("tcp")
    packet.metadata.update({"tcp.window": window, "tcp.urgent": urgent, "tcp.options": options})
    packet.payload = reader.take(reader.remaining)
    if verify and checksum(pseudo + reader.data):
        warnings.record("checksum", "TCP checksum mismatch; capture offload is possible")

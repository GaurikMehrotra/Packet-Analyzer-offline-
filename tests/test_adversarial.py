"""Resource floods and structured properties complement random mutations."""

import struct

from hypothesis import given, settings, strategies as st

from pcaplens.analysis.summary import analyze
from pcaplens.dissect import dns
from pcaplens.dissect.errors import WarningLog
from pcaplens.dissect.ipv4 import Fragments
from pcaplens.dissect.registry import dissect
from pcaplens.filter.evaluator import evaluate
from pcaplens.filter.parser import parse
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits
from pcaplens.models import CapturePacket, Packet


def test_tiny_fragment_flood():
    limits = Limits(max_fragment_buffers=4, max_fragment_bytes=64, max_warnings=2)
    warnings = WarningLog(2)
    fragments = Fragments(limits, warnings)
    packet = Packet(0, 0, 0, src="192.0.2.1", dst="198.51.100.1")
    for ident in range(10000):
        fragments.add(packet, 17, b"abcdefgh", 0, True, ident)
        assert fragments.used <= 64
        assert len(fragments.items) <= 4
    assert warnings.count == 9996
    assert len(warnings.items) == 2
    fragments.finish()
    assert fragments.used == 0


@given(
    st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=20),
        min_size=1,
        max_size=5,
    )
)
@settings(max_examples=200, derandomize=True)
def test_dns_compression_roundtrip(labels):
    encoded = b"".join(bytes([len(label)]) + label.encode() for label in labels) + b"\0"
    reader = ByteReader(encoded + b"\xc0\0")
    reader.position = len(encoded)
    assert dns.name(reader, Limits()) == ".".join(labels)
    assert reader.position == len(encoded) + 2


@given(st.integers(0, 65535), st.integers(0, 65535), st.booleans())
@settings(max_examples=200, derandomize=True)
def test_filter_grammar_semantics(left, right, negate):
    packet = Packet(0, 54, 54, protocols=["ipv4", "tcp"], sport=left, dport=right, transport="tcp")
    expression = f"{'not ' if negate else ''}(tcp and port {left})"
    assert evaluate(parse(expression), packet) is not negate


def test_all_packet_truncations(fixtures):
    from pcaplens.formats.open import packets

    warnings = WarningLog(100)
    captures = list(packets(fixtures / "protocols-le-us.pcap", Limits(), warnings))
    for capture in captures:
        for cut in range(len(capture.data)):
            data = capture.data[:cut]
            warnings = WarningLog(2)
            dissect(
                CapturePacket(0, data, len(capture.data), 1),
                Limits(),
                warnings,
                Fragments(Limits(), warnings),
                True,
            )


def test_oversized_option_length(generator):
    from scapy.all import IP, TCP

    data = bytearray(
        bytes(
            generator.ethernet(IP(src=generator.A, dst=generator.B) / TCP(options=[("MSS", 1460)]))
        )
    )
    data[55] = 255
    warnings = WarningLog(10)
    dissect(
        CapturePacket(0, bytes(data), len(data), 1),
        Limits(),
        warnings,
        Fragments(Limits(), warnings),
    )
    assert "truncated" in [w.code for w in warnings.items]


def test_nonregular_input(tmp_path):
    result = analyze(tmp_path)
    assert result["summary"]["packets"] == 0
    assert result["warnings"]["items"][0]["code"] == "capture_size_limit"


def test_malformed_udp_and_ipv6_fragment(generator):
    from scapy.all import IP, IPv6, UDP, Raw
    from scapy.layers.inet6 import IPv6ExtHdrFragment

    frame = bytes(generator.ethernet(IP(src=generator.A, dst=generator.B) / UDP(len=7) / Raw(b"a")))
    warnings = WarningLog(10)
    dissect(
        CapturePacket(0, frame, len(frame), 1), Limits(), warnings, Fragments(Limits(), warnings)
    )
    assert "udp_length" in [w.code for w in warnings.items]
    frame = bytes(
        generator.ethernet(
            IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment(m=1) / Raw(b"abcdefgh")
        )
    )
    warnings = WarningLog(10)
    packet = dissect(
        CapturePacket(0, frame, len(frame), 1), Limits(), warnings, Fragments(Limits(), warnings)
    )
    assert not packet.transport
    assert warnings.items[0].code == "ipv6_fragment"


def test_no_infinite_section_headers(generator, tmp_path):
    header = generator.block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1), "<")
    path = tmp_path / "sections.pcapng"
    path.write_bytes(header * 10000)
    result = analyze(path, Limits(max_blocks=10))
    assert result["summary"]["packets"] == 0
    assert result["warnings"]["items"][0]["code"] == "block_limit"

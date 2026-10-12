import gzip
import io
import struct
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.open import LimitedGzip, packets
from pcaplens.limits import Limits
from pcaplens.formats.pcapng import options


@pytest.mark.parametrize(
    "name",
    [
        "protocols-le-us.pcap",
        "protocols-be-us.pcap",
        "protocols-le-ns.pcap",
        "protocols-be-ns.pcap",
    ],
)
def test_pcap_variants(fixtures, name):
    warnings = WarningLog(100)
    result = list(packets(fixtures / name, Limits(), warnings))
    assert len(result) == 14
    assert result[1].timestamp_ns - result[0].timestamp_ns == 100000000
    assert result[0].link_type == 1
    assert warnings.count == 0


@pytest.mark.parametrize("name", ["interfaces-le.pcapng", "interfaces-be.pcapng"])
def test_multiple_interfaces(fixtures, name):
    warnings = WarningLog(100)
    result = list(packets(fixtures / name, Limits(), warnings))
    assert [p.interface for p in result] == [0, 1]
    assert result[1].timestamp_ns - result[0].timestamp_ns == 100000000
    assert warnings.count == 0


@pytest.mark.parametrize(
    "name,code",
    [
        ("truncated.pcap", "truncated"),
        ("huge-length.pcap", "packet_length"),
        ("wrong-endian.pcap", "pcap_header"),
        ("block-mismatch.pcapng", "block_trailer"),
    ],
)
def test_malformed_format(fixtures, name, code):
    warnings = WarningLog(100)
    list(packets(fixtures / name, Limits(), warnings))
    assert code in [w.code for w in warnings.items]


@given(st.integers(0, 1500))
@settings(max_examples=150, derandomize=True)
def test_truncation_never_raises(fixtures, cut):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "trunc.pcap"
        path.write_bytes((fixtures / "protocols-le-us.pcap").read_bytes()[:cut])
        warnings = WarningLog(10)
        list(packets(path, Limits(), warnings))


def test_gzip(fixtures, tmp_path):
    path = tmp_path / "capture.pcap.gz"
    path.write_bytes(gzip.compress((fixtures / "protocols-le-us.pcap").read_bytes(), mtime=0))
    warnings = WarningLog(100)
    assert len(list(packets(path, Limits(), warnings))) == 14
    assert warnings.count == 0


@pytest.mark.parametrize(
    "limits", [Limits(max_decompressed_bytes=10), Limits(max_decompression_ratio=1)]
)
def test_gzip_bomb(limits):
    compressed = gzip.compress(b"a" * 100000, mtime=0)
    stream = LimitedGzip(io.BytesIO(compressed), limits, len(compressed))
    with pytest.raises(ParseError, match="cap"):
        while stream.read(32):
            pass
    assert stream.used <= stream.cap + 1


def test_packet_and_interface_block_limits(fixtures):
    for name, limits, code in [
        ("protocols-le-us.pcap", Limits(max_packets=1), "packet_limit"),
        ("protocols-le-us.pcap", Limits(max_packet_length=100), "pcap_header"),
        ("interfaces-le.pcapng", Limits(max_interfaces=1), "interface_limit"),
        ("interfaces-le.pcapng", Limits(max_block_length=24), "block_length"),
    ]:
        warnings = WarningLog(100)
        list(packets(fixtures / name, limits, warnings))
        assert code in [w.code for w in warnings.items]


def test_pcapng_sections_and_binary_resolution(generator, tmp_path):
    frame = generator.tcp(1, flags="S")
    little = generator.pcapng([frame])
    big = generator.pcapng([frame], ">")
    path = tmp_path / "sections.pcapng"
    path.write_bytes(little + big)
    warnings = WarningLog(100)
    assert [p.interface for p in packets(path, Limits(), warnings)] == [0, 0]
    body = struct.pack("<HHI", 1, 0, 262144) + struct.pack("<HH", 9, 1) + b"\x8a\0\0\0\0\0\0\0"
    header = generator.block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1), "<")
    epb = (
        struct.pack("<IIIII", 0, 0, 1024, len(frame), len(frame))
        + frame
        + b"\0" * ((-len(frame)) % 4)
    )
    path.write_bytes(header + generator.block(1, body, "<") + generator.block(6, epb, "<"))
    result = list(packets(path, Limits(), warnings))
    assert result[0].timestamp_ns == 1000000000


def test_options_capture_and_block_caps(fixtures):
    raw = struct.pack("<HH", 2, 1) + b"a\0\0\0"
    assert options(raw + b"\0" * 4, "<", Limits(max_options=1)) == [(2, b"a")]
    with pytest.raises(ParseError, match="options"):
        options(raw * 2, "<", Limits(max_options=1))
    for name, limits, code in [
        ("interfaces-le.pcapng", Limits(max_blocks=1), "block_limit"),
        ("protocols-le-us.pcap", Limits(max_capture_bytes=100), "capture_size_limit"),
    ]:
        warnings = WarningLog(10)
        assert not list(packets(fixtures / name, limits, warnings))
        assert warnings.items[0].code == code


def test_obsolete_and_simple_blocks(generator, tmp_path):
    frame = generator.tcp(1, flags="S")
    section_and_interfaces = generator.pcapng([])
    pad = b"\0" * ((-len(frame)) % 4)
    simple = generator.block(3, struct.pack("<I", len(frame)) + frame + pad, "<")
    obsolete = generator.block(
        2, struct.pack("<HHIIII", 1, 0, 0, 1000000000, len(frame), len(frame)) + frame + pad, "<"
    )
    path = tmp_path / "blocks.pcapng"
    path.write_bytes(section_and_interfaces + simple + obsolete)
    warnings = WarningLog(10)
    result = list(packets(path, Limits(), warnings))
    assert [p.interface for p in result] == [0, 1]
    assert result[1].timestamp_ns == 1000000000
    assert warnings.items[0].code == "timestamp_missing"


def test_declared_original_length_is_capped(generator, tmp_path):
    frame = generator.tcp(100, flags="S")
    data = bytearray(generator.pcap([frame]))
    data[36:40] = struct.pack("<I", 0xFFFFFFFF)
    path = tmp_path / "original.pcap"
    path.write_bytes(data)
    warnings = WarningLog(10)
    assert list(packets(path, Limits(), warnings)) == []
    assert warnings.items[0].code == "packet_length"

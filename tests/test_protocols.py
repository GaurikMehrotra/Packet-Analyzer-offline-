import struct

import pytest
from hypothesis import given, settings, strategies as st

from pcaplens.analysis.summary import analyze
from pcaplens.dissect import dns, http, tls
from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.dissect.ipv4 import Fragments
from pcaplens.dissect.registry import dissect
from pcaplens.formats.open import packets
from pcaplens.limits import Limits
from pcaplens.models import CapturePacket


def test_ground_truth(fixtures):
    result = analyze(fixtures / "protocols-le-us.pcap", checksum=True)
    assert result["warnings"]["count"] == 0
    assert result["protocols"] == {
        "arp": 1,
        "dns": 3,
        "ethernet": 14,
        "http": 2,
        "icmp": 1,
        "icmpv6": 1,
        "ipv4": 12,
        "ipv6": 1,
        "tcp": 6,
        "udp": 3,
        "vlan": 1,
    }
    assert sorted(q["name"] for m in result["dns"] for q in m["questions"]) == [
        "fragment.test",
        "synthetic.test",
        "synthetic.test",
    ]
    assert [r["value"] for m in result["dns"] for r in m["records"]] == ["203.0.113.7"]
    assert result["http"][0]["headers"]["authorization"] == "[REDACTED]"
    assert result["http"][1]["body"]["encoded_length"] == 5
    assert result["arp"][0]["arp.mac"] == "02:00:00:00:00:01"


def test_tls_metadata(fixtures):
    result = analyze(fixtures / "tls.pcap", checksum=True)
    assert result["warnings"]["count"] == 0
    client, server = result["tls"]
    assert client["sni"] == ["synthetic.test"]
    assert client["alpn"] == ["http/1.1"]
    assert client["versions"] == [772, 771]
    assert client["cipher_suites"] == [4865, 49199]
    assert server["versions"] == [772]


@pytest.mark.parametrize("name", ["raw-ip.pcap", "sll.pcap"])
def test_link_types(fixtures, name):
    result = analyze(fixtures / name, checksum=True)
    assert result["protocols"]["icmp"] == 1
    assert result["warnings"]["count"] == 0


def test_unsupported_and_dns_loop(fixtures):
    assert analyze(fixtures / "unsupported.pcap")["protocols"] == {"unsupported": 1}
    result = analyze(fixtures / "dns-loop.pcap")
    assert result["warnings"]["items"][0]["code"] == "dns_loop"


@given(st.binary(max_size=512))
@settings(max_examples=300, derandomize=True)
def test_arbitrary_packet_and_dns(data):
    warnings = WarningLog(10)
    dissect(
        CapturePacket(0, data, len(data), 1),
        Limits(),
        warnings,
        Fragments(Limits(), warnings),
        True,
    )
    reader_limits = Limits(max_dns_hops=4, max_dns_records=8)
    try:
        dns.parse(data, reader_limits)
    except ParseError:
        pass


def test_checksum_warning(fixtures):
    warnings = WarningLog(100)
    capture = next(packets(fixtures / "protocols-le-us.pcap", Limits(), warnings))
    data = bytearray(capture.data)
    data[24] ^= 1
    dissect(
        CapturePacket(0, bytes(data), len(data), 1),
        Limits(),
        warnings,
        Fragments(Limits(), warnings),
        True,
    )
    assert "checksum" in [w.code for w in warnings.items]


def test_dns_pointer_limit_and_record_budget():
    from pcaplens.formats.reader_base import ByteReader

    chain = b"\xc0\x02\xc0\x04\0"
    with pytest.raises(ParseError, match="hop"):
        dns.name(ByteReader(chain), Limits(max_dns_hops=1))
    with pytest.raises(ParseError, match="record"):
        dns.parse(struct.pack("!6H", 0, 0, 2, 0, 0, 0), Limits(max_dns_records=1))


def test_dns_compressed_records():
    label = b"\x09synthetic\x04test\0"
    data = struct.pack("!6H", 1, 0x8180, 1, 2, 0, 0) + label + b"\0\x01\0\x01"
    data += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 2) + b"\xc0\x0c"
    data += (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 28, 1, 60, 16)
        + bytes.fromhex("20010db8000000000000000000000001")
    )
    parsed = dns.parse(data, Limits())
    assert parsed["records"][0]["value"] == "synthetic.test"
    assert parsed["records"][1]["value"] == "2001:db8::1"


def test_http_chunked_and_ambiguity():
    warnings = WarningLog(10)
    parsed = http.parse(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        Limits(),
        warnings,
    )
    assert parsed[0]["body"]["encoded_length"] == 3
    with pytest.raises(ParseError, match="Conflicting"):
        http.parse(
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            Limits(),
            warnings,
        )
    with pytest.raises(ParseError, match="coexist"):
        http.parse(
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
            Limits(),
            warnings,
        )


def test_http_limits_and_gzip():
    import gzip

    warnings = WarningLog(10)
    http.parse(b"GET / HTTP/1.1\r\nX: " + b"a" * 100, Limits(max_http_header=32), warnings)
    assert warnings.items[0].code == "http_header_limit"
    with pytest.raises(ParseError, match="count"):
        http.parse(b"GET / HTTP/1.1\r\nA: a\r\nB: b\r\n\r\n", Limits(max_headers=1), warnings)
    compressed = gzip.compress(b"abc", mtime=0)
    assert http.body_hash(compressed, "gzip", Limits())["decoded_length"] == 3
    with pytest.raises(ParseError, match="cap"):
        http.body_hash(
            gzip.compress(b"a" * 100000, mtime=0), "gzip", Limits(max_decompression_ratio=1)
        )


def test_tls_handshake_budget(generator):
    with pytest.raises(ParseError, match="cap"):
        tls.parse(generator.client_hello(), Limits(max_tls_handshake=10))


@pytest.mark.parametrize(
    "limit,code",
    [
        ("max_ipv6_extensions", "ipv6_extension_limit"),
        ("max_headers", "header_limit"),
        ("max_options", "option_limit"),
    ],
)
def test_protocol_count_budgets(generator, limit, code):
    from scapy.all import Dot1Q, Ether, IP, IPv6, TCP
    from scapy.layers.inet6 import IPv6ExtHdrHopByHop

    if limit == "max_ipv6_extensions":
        frame = bytes(
            generator.ethernet(
                IPv6(src="2001:db8::1", dst="2001:db8::2")
                / IPv6ExtHdrHopByHop()
                / IPv6ExtHdrHopByHop()
            )
        )
    elif limit == "max_headers":
        frame = bytes(
            Ether(src=generator.MAC_A, dst=generator.MAC_B)
            / Dot1Q(vlan=1)
            / Dot1Q(vlan=2)
            / IP(src=generator.A, dst=generator.B)
        )
    else:
        frame = bytes(
            generator.ethernet(
                IP(src=generator.A, dst=generator.B) / TCP(options=[("NOP", None), ("NOP", None)])
            )
        )
    limits = Limits(**{limit: 1})
    warnings = WarningLog(10)
    dissect(CapturePacket(0, frame, len(frame), 1), limits, warnings, Fragments(limits, warnings))
    assert code in [w.code for w in warnings.items]

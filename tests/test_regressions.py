"""Targeted framing, option, and output regressions."""

import gzip
import hashlib
import json
import struct
import subprocess
import sys

import pytest

from pcaplens.analysis.summary import analyze
from pcaplens.analysis.timeline import series
from pcaplens.dissect import dns, http, tls
from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.dissect.ipv4 import Fragments
from pcaplens.dissect.registry import dissect
from pcaplens.limits import Limits
from pcaplens.models import CapturePacket, Packet
from pcaplens.output.html_report import render
from pcaplens.settings import Settings


def test_fragment_total_includes_first_header_length():
    warnings = WarningLog(10)
    fragments = Fragments(Limits(), warnings)
    packet = Packet(timestamp_ns=0, captured_length=0, original_length=0)
    packet.src, packet.dst = "192.0.2.10", "198.51.100.20"
    assert fragments.add(packet, 17, b"12345678", 65504, False, 1) is None
    assert fragments.used == 8
    assert fragments.add(packet, 17, b"abcdefgh", 0, True, 1, 60) is None
    assert fragments.used == 0
    assert warnings.items[-1].code == "fragment_length"


def test_tcp_known_options(generator):
    from scapy.all import IP, TCP

    frame = bytes(
        generator.ethernet(
            IP(src=generator.A, dst=generator.B)
            / TCP(options=[("MSS", 1460), ("WScale", 7), ("Timestamp", (100, 50))])
        )
    )
    warnings = WarningLog(10)
    packet = dissect(
        CapturePacket(0, frame, len(frame), 1), Limits(), warnings, Fragments(Limits(), warnings)
    )
    options = packet.metadata["tcp.options"]
    assert options[0]["mss"] == 1460
    assert options[1]["window_scale"] == 7
    assert options[2]["timestamp"] == 100
    assert warnings.count == 0


def test_dns_mx_srv_soa_txt():
    label = b"\x09synthetic\x04test\0"
    pointer = b"\xc0\x0c"
    records = [
        (15, b"\0\x0a" + pointer),
        (33, struct.pack("!HHH", 1, 2, 443) + pointer),
        (6, pointer + pointer + struct.pack("!5I", 1, 2, 3, 4, 5)),
        (16, b"\x09synthetic"),
    ]
    data = struct.pack("!6H", 1, 0x8180, 1, len(records), 0, 0) + label + b"\0\x01\0\x01"
    for kind, value in records:
        data += pointer + struct.pack("!HHIH", kind, 1, 60, len(value)) + value
    values = dns.parse(data, Limits())["records"]
    assert values[0]["value"] == {"preference": 10, "exchange": "synthetic.test"}
    assert values[1]["value"]["port"] == 443
    assert values[2]["value"]["timers"] == [1, 2, 3, 4, 5]
    assert values[3]["value"] == ["synthetic"]


def test_http_gzip_no_body_export():
    body = gzip.compress(b"password=synthetic-only", mtime=0)
    data = (
        b"POST / HTTP/1.1\r\nContent-Encoding: gzip\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    values = http.parse(data, Limits(), WarningLog(10))
    assert "synthetic-only" not in json.dumps(values)
    assert (
        values[0]["body"]["decoded_sha256"]
        == hashlib.sha256(b"password=synthetic-only").hexdigest()
    )


def test_http_interim_and_upgrade():
    data = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    values = http.parse(data, Limits(), WarningLog(10), ["HEAD"])
    assert [value["status"] for value in values] == [100, 200]
    assert all(value["request_method_context"] == "HEAD" for value in values)
    values = http.parse(
        b"HTTP/1.1 200 OK\r\n\r\nopaque-tunnel", Limits(), WarningLog(10), ["CONNECT"]
    )
    assert values[0]["upgraded_protocol_not_parsed"]
    assert values[0]["body"]["encoded_length"] == 0


def test_tls_record_count_limit():
    data = b"\x14\x03\x03\0\x01\x01" * 2
    with pytest.raises(ParseError, match="records"):
        tls.parse(data, Limits(max_headers=1))


def test_timeline_gap_and_report(fixtures):
    stamps, values = series(
        [{"second": 1, "captured_bytes": 10}, {"second": 1000000000, "captured_bytes": 20}]
    )
    assert len(stamps) == 4
    assert values == [10, 0, 0, 20]
    result = analyze(fixtures / "protocols-le-us.pcap")
    html = render(result)
    assert "<svg " in html
    assert "<script" not in html
    assert 'src="http' not in html


def test_settings_and_malformed_yaml(fixtures, tmp_path):
    assert Settings.load(fixtures.parent / "configs/default.yaml") == Settings()
    path = tmp_path / "invalid.yaml"
    path.write_text("{unfinished")
    for model in (Limits, Settings):
        with pytest.raises(ValueError, match="Malformed"):
            model.load(path)


def test_framework_error_sanitization(fixtures):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from pcaplens.cli import main; main()",
            "summary",
            str(fixtures / "protocols-le-us.pcap"),
            "--overlap",
            "\x1b[31m",
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert "\x1b" not in result.stdout + result.stderr


def test_capture_change_invalidates_hash(fixtures, tmp_path, monkeypatch):
    import importlib

    module = importlib.import_module("pcaplens.analysis.summary")
    path = tmp_path / "changing.pcap"
    path.write_bytes((fixtures / "protocols-le-us.pcap").read_bytes())

    def changed(path, maximum):
        path.write_bytes(path.read_bytes() + b"changed")
        return "synthetic-placeholder-hash"

    monkeypatch.setattr(module, "file_hash", changed)
    result = module.analyze(path)
    assert result["scan"]["sha256"] is None
    assert "capture_changed" in [w["code"] for w in result["warnings"]["items"]]


def test_progress_and_typed_warning_result(fixtures):
    counts = []
    result = analyze(fixtures / "protocols-le-us.pcap", on_progress=counts.append)
    assert counts[-1] == result["summary"]["scanned_packets"] == 14
    warnings = WarningLog(1)
    fragments = Fragments(Limits(), warnings)
    packet = dissect(CapturePacket(0, b"bad", 3, 1), Limits(), warnings, fragments)
    assert packet.warnings[0].code == "truncated"


def test_port_does_not_prove_dns_and_tcp_dns_reassembles(generator, tmp_path):
    from scapy.all import DNS, DNSQR

    path = tmp_path / "dns-tcp.pcap"
    path.write_bytes(generator.pcap([generator.tcp(100, flags="S", ack=0, port=53)]))
    result = analyze(path)
    assert "dns" not in result["protocols"]
    message = bytes(DNS(qd=DNSQR(qname="synthetic.test")))
    framed = struct.pack("!H", len(message)) + message
    path.write_bytes(
        generator.pcap(
            [
                generator.tcp(100, flags="S", ack=0, port=53),
                generator.tcp(101, framed[:12], port=53),
                generator.tcp(113, framed[12:], port=53),
            ]
        )
    )
    result = analyze(path)
    assert result["dns"][0]["questions"][0]["name"] == "synthetic.test"
    assert result["warnings"]["count"] == 0

import json

import pytest
from hypothesis import given, settings, strategies as st
from typer.testing import CliRunner

from pcaplens.analysis.summary import analyze
from pcaplens.cli import app
from pcaplens.filter.evaluator import evaluate
from pcaplens.filter.lexer import FilterError
from pcaplens.filter.parser import parse
from pcaplens.limits import Limits
from pcaplens.models import Packet
from pcaplens.output import csv_out, html_report, json_out
from pcaplens.output.anonymize import Anonymizer
from pcaplens.output.redact import redact
from pcaplens.output.sanitize import sanitize


@pytest.mark.parametrize(
    "expression,expected",
    [
        ("tcp and port 443", True),
        ("ip.src == 192.0.2.10 and not dns", True),
        ("not arp", True),
        ("ip.src in 192.0.2.0/24 and tcp.flags >= 2", True),
        ("udp.port == 443", False),
        ("port != 443", False),
        ("(arp or dns) and tcp", False),
        ("ipv6 or tcp and port 80", False),
    ],
)
def test_filters(expression, expected):
    packet = Packet(
        0,
        60,
        60,
        protocols=["ethernet", "ipv4", "tcp"],
        src="192.0.2.10",
        dst="198.51.100.20",
        sport=12345,
        dport=443,
        transport="tcp",
        flags=2,
    )
    assert evaluate(parse(expression), packet) is expected


@pytest.mark.parametrize(
    "expression",
    [
        "__import__(os)",
        "tcp; print(1)",
        "port = 4",
        "(",
        "tcp and",
        "ip.src == nope",
        "length in 1",
        "port -1",
    ],
)
def test_reject_hostile_filter(expression):
    with pytest.raises(FilterError):
        parse(expression)


@given(st.text(max_size=500))
@settings(max_examples=500, derandomize=True)
def test_filter_fuzz(expression):
    try:
        node = parse(expression)
        assert isinstance(evaluate(node, Packet(0, 0, 0)), bool)
    except FilterError:
        pass


@pytest.mark.parametrize(
    "expression,limits",
    [
        ("not not tcp", Limits(max_filter_depth=1)),
        ("tcp and udp", Limits(max_filter_tokens=1)),
        ("tcp" * 100, Limits(max_filter_tokens=1)),
    ],
)
def test_filter_limits(expression, limits):
    with pytest.raises(FilterError):
        parse(expression, limits)


def test_safe_outputs():
    value = {
        "evil": "\x1b[31m<script>alert(1)</script>\x00\u202e",
        "authorization": "synthetic-only",
        "cookie": "synthetic-only",
        "url": "/?token=synthetic-only&x=other",
    }
    cleaned = sanitize(redact(value))
    assert "\x1b" not in cleaned["evil"] and "\u202e" not in cleaned["evil"]
    assert cleaned["authorization"] == "[REDACTED]"
    assert "synthetic-only" not in json_out.render(cleaned)
    assert "<script>" not in html_report.render(cleaned)
    assert "&lt;script&gt;" in html_report.render(cleaned)
    for dangerous in ("=1+1", "+cmd", "-1+2", "@SUM(1)", "  =cmd", "\t=cmd"):
        assert csv_out.cell(dangerous).startswith("'")
    assert csv_out.cell("plain") == "plain"


def test_anonymization(fixtures):
    anonymizer = Anonymizer(b"synthetic-unit-test-key")
    assert anonymizer.string("192.0.2.10") == anonymizer.string("192.0.2.10")
    assert anonymizer.string("02:00:00:00:00:01").startswith("mac_")
    value = anonymizer.string("ip.src == 192.0.2.10 and mac 02:00:00:00:00:01; [2001:db8::1]:443")
    assert (
        "192.0.2.10" not in value
        and "02:00:00:00:00:01" not in value
        and "2001:db8::1" not in value
    )
    result = analyze(fixtures / "protocols-le-us.pcap", anonymize=True)
    assert "192.0.2.10" not in json.dumps(result)
    assert "02:00:00:00:00:01" not in json.dumps(result)


def test_cli_smoke(fixtures, tmp_path):
    runner = CliRunner(mix_stderr=False)
    assert runner.invoke(app, ["--help"]).exit_code == 0
    for name in (
        "summary",
        "flows",
        "dns",
        "http",
        "tls",
        "follow",
        "export",
        "detect",
        "hierarchy",
        "talkers",
    ):
        result = runner.invoke(app, [name, str(fixtures / "protocols-le-us.pcap")])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["scan"]["redacted"]
    result = runner.invoke(
        app, ["filter", str(fixtures / "protocols-le-us.pcap"), "--expression", "tcp"]
    )
    assert json.loads(result.stdout)["summary"]["packets"] == 6
    path = tmp_path / "report.html"
    result = runner.invoke(
        app, ["report", str(fixtures / "protocols-le-us.pcap"), "--output", str(path)]
    )
    assert result.exit_code == 0
    assert "<!doctype html>" in path.read_text()
    assert (
        runner.invoke(
            app, ["report", str(fixtures / "protocols-le-us.pcap"), "--output", str(path)]
        ).exit_code
        == 1
    )
    result = runner.invoke(app, ["summary", str(fixtures / "truncated.pcap")])
    assert result.exit_code == 2
    assert json.loads(result.stdout)["warnings"]["count"] > 0


def test_head_response_and_config(fixtures, tmp_path):
    from pcaplens.dissect.http import parse as parse_http
    from pcaplens.dissect.errors import WarningLog

    response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    values = parse_http(response, Limits(), WarningLog(10), ["HEAD"])
    assert values[0]["body"]["encoded_length"] == 0
    settings = tmp_path / "settings.yaml"
    settings.write_text("checksum: true\nanonymize: true\noverlap_policy: last\n")
    result = CliRunner(mix_stderr=False).invoke(
        app, ["summary", str(fixtures / "protocols-le-us.pcap"), "--settings", str(settings)]
    )
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["scan"]["checksum"] and data["scan"]["anonymized"]
    assert data["scan"]["overlap_policy"] == "last"


def test_no_oracle_imports_in_source(fixtures):
    import ast

    for path in (fixtures.parent / "src/pcaplens").rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    alias.name.split(".")[0] not in {"scapy", "dpkt"} for alias in node.names
                )
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in {"scapy", "dpkt"}

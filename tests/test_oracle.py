"""Explicit opt-in: offline tshark comparisons on synthetic input only."""

import json
import os
import subprocess
import sys

import pytest


@pytest.mark.oracle
def test_tshark_streams_and_fields(fixtures, tmp_path):
    tool = os.environ.get("PCAPLENS_TSHARK")
    if not tool:
        pytest.skip("Set PCAPLENS_TSHARK to the installed offline tshark executable")
    output = tmp_path / "oracle.json"
    subprocess.run(
        [
            sys.executable,
            str(fixtures.parent / "eval/oracle_tshark.py"),
            str(fixtures / "protocols-le-us.pcap"),
            str(fixtures / "reassembly.pcap"),
            "--tshark",
            tool,
            "--output",
            str(output),
        ],
        check=True,
        timeout=60,
    )
    result = json.loads(output.read_text())
    for capture in result["captures"]:
        assert all(stream["equal"] for stream in capture["streams"])
        for field in capture["checks"]:
            if field["field"] != "protocol_hierarchy":
                assert not field["differences"], field
            else:
                assert all(item["key"].endswith("/data") for item in field["differences"])

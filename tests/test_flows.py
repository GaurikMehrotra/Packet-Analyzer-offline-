import hashlib
import json

import pytest

from pcaplens.analysis.summary import analyze
from pcaplens.dissect.errors import WarningLog
from pcaplens.dissect.ipv4 import Fragments
from pcaplens.flows.reassembly import MemoryBudget, Stream, distance
from pcaplens.flows.table import FlowTable
from pcaplens.limits import Limits
from pcaplens.models import Packet


def stream(limits=None, policy="first"):
    limits = limits or Limits()
    warnings = WarningLog(100)
    budget = MemoryBudget(limits.max_reassembly_total)
    return Stream(limits, budget, warnings, policy), budget, warnings


def test_out_of_order_wrap_retransmission():
    value, budget, _ = stream()
    value.add(0xFFFFFFFD, b"", syn=True)
    value.add(0, b"CD")
    value.add(0xFFFFFFFE, b"AB")
    value.add(0, b"CD")
    assert value.runs() == [(0, b"ABCD")]
    assert value.retransmissions == 1
    assert distance(0, 0xFFFFFFFE) == 2
    assert distance(0xFFFFFFFE, 0) == -2
    value.close()
    assert budget.used == 0


@pytest.mark.parametrize(
    "policy,expected", [("first", b"ABC"), ("last", b"AZC"), ("reject", b"ABC")]
)
def test_overlap(policy, expected):
    value, _, warnings = stream(policy=policy)
    value.add(100, b"ABC")
    value.add(101, b"Z")
    assert value.runs() == [(0, expected)]
    assert value.overlaps == 1
    if policy == "reject":
        assert warnings.items[0].code == "tcp_overlap"


def test_gaps_and_midstream_prepend():
    value, _, _ = stream()
    value.add(105, b"FG")
    value.add(100, b"AB")
    assert value.runs() == [(0, b"AB"), (5, b"FG")]
    assert value.metadata()["gap_bytes"] == 3


@pytest.mark.parametrize(
    "limits",
    [Limits(max_stream_bytes=2), Limits(max_reassembly_total=3), Limits(max_segment_count=1)],
)
def test_reassembly_caps(limits):
    value, budget, warnings = stream(limits)
    value.add(100, b"A")
    value.add(101, b"BC")
    assert value.limited
    assert budget.used <= limits.max_reassembly_total
    assert len(value.data) <= limits.max_stream_bytes
    assert warnings.items[-1].code == "reassembly_limit"


def test_ground_truth_stream_hashes(fixtures):
    truth = json.loads((fixtures / "ground_truth/expected.json").read_text())
    result = analyze(fixtures / "reassembly.pcap")
    flow = result["flows"][0]
    assert flow["state"] == "established_observed"
    assert sum(flow["packets"]) == 8
    assert flow["streams"][0]["retransmission_estimate"] == 1
    for index, key in enumerate(("a_to_b_hex", "b_to_a_hex")):
        assert (
            flow["streams"][index]["runs"][0]["sha256"]
            == hashlib.sha256(bytes.fromhex(truth["reassembly"][key])).hexdigest()
        )


def test_flow_timeout_eviction_and_timing_cap():
    completed = []
    limits = Limits(max_flows=1, flow_timeout=1, max_timing_samples=1)
    warnings = WarningLog(10)
    table = FlowTable(limits, warnings, lambda flow, reason: completed.append(flow.export(reason)))

    def packet(time, port):
        return Packet(
            time, 60, 60, src="192.0.2.1", dst="198.51.100.1", sport=port, dport=80, transport="tcp"
        )

    table.add(packet(0, 1000))
    table.add(packet(1, 1000))
    assert len(next(iter(table.items.values())).times) == 1
    table.add(packet(2, 1001))
    assert completed[-1]["reason"] == "evicted"
    table.add(packet(3_000_000_000, 1002))
    assert completed[-1]["reason"] == "timeout"
    table.finish()
    assert table.budget.used == 0


def test_fragment_caps_overlap_and_timeout():
    warnings = WarningLog(100)
    limits = Limits(max_fragment_buffers=1, max_fragment_bytes=8, fragment_timeout=1)
    fragments = Fragments(limits, warnings)
    packet = Packet(0, 0, 0, src="192.0.2.1", dst="198.51.100.1")
    fragments.add(packet, 17, b"ABCDEFGH", 0, True, 1)
    fragments.add(packet, 17, b"ABCDEFGH", 0, True, 2)
    assert len(fragments.items) == 1
    assert "fragment_limit" in [w.code for w in warnings.items]
    fragments.add(packet, 17, b"IJKL", 8, False, 2)
    assert fragments.used == 0
    assert "fragment_bytes_limit" in [w.code for w in warnings.items]
    fragments.add(packet, 17, b"ABCDEFGH", 0, True, 3)
    fragments.add(packet, 17, b"bad", 0, False, 3)
    assert "fragment_overlap" in [w.code for w in warnings.items]
    fragments.add(packet, 17, b"ABCDEFGH", 0, True, 4)
    packet.timestamp_ns = 2_000_000_000
    fragments.add(packet, 17, b"ABCDEFGH", 0, True, 5)
    assert "fragment_timeout" in [w.code for w in warnings.items]
    assert fragments.used <= 8


def test_fragment_piece_count():
    limits = Limits(max_segment_count=1)
    warnings = WarningLog(10)
    fragments = Fragments(limits, warnings)
    packet = Packet(0, 0, 0, src="192.0.2.1", dst="198.51.100.1")
    fragments.add(packet, 17, b"ABCDEFGH", 0, True, 1)
    fragments.add(packet, 17, b"IJKL", 8, False, 1)
    assert fragments.used == 0
    assert warnings.items[0].code == "fragment_bytes_limit"


@pytest.mark.parametrize("limits", [Limits(max_metadata=1), Limits(max_metadata_bytes=1)])
def test_retained_metadata_limits(fixtures, limits):
    result = analyze(fixtures / "protocols-le-us.pcap", limits)
    assert result["suppressed"]
    assert "metadata_limit" in [w["code"] for w in result["warnings"]["items"]]


def test_talker_and_timeline_caps(fixtures):
    result = analyze(fixtures / "protocols-le-us.pcap", Limits(max_flows=1, max_metadata=1))
    assert len(result["talkers"]) <= 1
    assert len(result["timeline"]) <= 1
    assert result["suppressed"]["timeline"] > 0


@pytest.mark.parametrize("closing,state", [(1, "fin_observed"), (4, "reset")])
def test_fin_rst_and_tuple_reuse(closing, state):
    completed = []
    limits = Limits()
    warnings = WarningLog(10)
    table = FlowTable(limits, warnings, lambda flow, reason: completed.append(flow.export(reason)))

    def packet(stamp, seq, flags, payload=b""):
        return Packet(
            stamp,
            60,
            60,
            src="192.0.2.1",
            dst="198.51.100.1",
            sport=12345,
            dport=80,
            transport="tcp",
            seq=seq,
            flags=flags,
            payload=payload,
        )

    table.add(packet(0, 100, 2))
    table.add(packet(1, 101, 16, b"abc"))
    table.add(packet(2, 104, closing))
    table.add(packet(3, 1000, 2))
    assert completed[0]["reason"] == "tuple_reuse"
    assert completed[0]["state"] == state
    assert table.budget.used == 0
    assert table.total == 2
    table.finish()


def test_total_budget_is_shared_across_streams():
    limits = Limits(max_reassembly_total=3)
    budget = MemoryBudget(3)
    warnings = WarningLog(10)
    first, second = [Stream(limits, budget, warnings) for _ in range(2)]
    first.add(0, b"A")
    second.add(0, b"B")
    assert budget.used == 2 and second.limited
    assert second.runs() == []
    first.close()
    second.close()
    assert budget.used == 0


def test_negative_timestamps_do_not_expire_relative_to_epoch_zero():
    completed = []
    table = FlowTable(Limits(), WarningLog(10), lambda flow, reason: completed.append(reason))
    for stamp in (-100_000_000_000, -99_000_000_000):
        table.add(
            Packet(
                stamp,
                60,
                60,
                src="192.0.2.1",
                dst="198.51.100.1",
                sport=1000,
                dport=80,
                transport="tcp",
            )
        )
    assert table.total == 1 and not completed
    table.finish()

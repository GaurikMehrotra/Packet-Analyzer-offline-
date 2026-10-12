"""Bounded bidirectional five-tuples, LRU eviction, and light TCP state."""

from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pcaplens.dissect.errors import WarningLog
from pcaplens.flows.reassembly import MemoryBudget, Stream
from pcaplens.limits import Limits
from pcaplens.models import Packet

FlowKey = tuple[str, tuple[str, int], tuple[str, int]]


def key_for(packet: Packet) -> FlowKey:
    endpoints = sorted([(packet.src, packet.sport), (packet.dst, packet.dport)])
    return packet.transport, endpoints[0], endpoints[1]


@dataclass
class Flow:
    key: FlowKey
    first: int
    last: int
    packets: list[int] = field(default_factory=lambda: [0, 0])
    captured_bytes: list[int] = field(default_factory=lambda: [0, 0])
    original_bytes: list[int] = field(default_factory=lambda: [0, 0])
    flags: int = 0
    streams: list[Stream] = field(default_factory=list)
    syn: bool = False
    syn_initiator: int | None = None
    syn_ack: bool = False
    established: bool = False
    times: list[int] = field(default_factory=list)

    def export(self, reason: str) -> dict[str, Any]:
        return {
            "protocol": self.key[0],
            "a": {"ip": self.key[1][0], "port": self.key[1][1]},
            "b": {"ip": self.key[2][0], "port": self.key[2][1]},
            "first_ns": self.first,
            "last_ns": self.last,
            "duration_seconds": max(0, self.last - self.first) / 1e9,
            "packets": self.packets,
            "captured_bytes": self.captured_bytes,
            "original_bytes": self.original_bytes,
            "reason": reason,
            "state": (
                "reset"
                if self.flags & 4
                else "fin_observed"
                if self.flags & 1
                else "established_observed"
                if self.established
                else "partial"
            ),
            "times_ns": self.times,
            "timing_samples_suppressed": sum(self.packets) - len(self.times),
            "syn_initiator": self.syn_initiator,
            "streams": [stream.metadata() for stream in self.streams],
        }


class FlowTable:
    def __init__(
        self,
        limits: Limits,
        warnings: WarningLog,
        finished: Callable[[Flow, str], None],
        policy: str = "first",
    ) -> None:
        self.limits, self.warnings, self.finished, self.policy = limits, warnings, finished, policy
        self.items: OrderedDict[FlowKey, Flow] = OrderedDict()
        self.budget = MemoryBudget(limits.max_reassembly_total)
        self.total = 0
        self.watermark: int | None = None

    def remove(self, key: FlowKey, reason: str) -> None:
        flow = self.items.pop(key)
        self.finished(flow, reason)
        for stream in flow.streams:
            stream.close()

    def add(self, packet: Packet) -> None:
        if not packet.transport:
            return
        self.watermark = (
            packet.timestamp_ns
            if self.watermark is None
            else max(self.watermark, packet.timestamp_ns)
        )
        for old_key, flow in list(self.items.items()):
            if self.watermark - flow.last > self.limits.flow_timeout * 1_000_000_000:
                self.remove(old_key, "timeout")
        key = key_for(packet)
        if key in self.items and packet.flags & 2 and not packet.flags & 16:
            flow = self.items[key]
            if flow.flags & 5:
                self.remove(key, "tuple_reuse")
        if key not in self.items:
            if len(self.items) >= self.limits.max_flows:
                self.warnings.record("flow_limit", "LRU flow eviction; conversation may split")
                self.remove(next(iter(self.items)), "evicted")
            flow = Flow(key, packet.timestamp_ns, packet.timestamp_ns)
            if packet.transport == "tcp":
                flow.streams = [
                    Stream(self.limits, self.budget, self.warnings, self.policy) for _ in range(2)
                ]
            self.items[key] = flow
            self.total += 1
        flow = self.items[key]
        self.items.move_to_end(key)
        direction = int((packet.src, packet.sport) != key[1])
        flow.first, flow.last = (
            min(flow.first, packet.timestamp_ns),
            max(flow.last, packet.timestamp_ns),
        )
        flow.packets[direction] += 1
        flow.captured_bytes[direction] += packet.captured_length
        flow.original_bytes[direction] += packet.original_length
        if len(flow.times) < self.limits.max_timing_samples:
            flow.times.append(packet.timestamp_ns)
        flow.flags |= packet.flags
        flow.syn |= bool(packet.flags & 2 and not packet.flags & 16)
        if packet.flags & 2 and not packet.flags & 16 and flow.syn_initiator is None:
            flow.syn_initiator = direction
        flow.syn_ack |= bool(packet.flags & 2 and packet.flags & 16)
        flow.established |= bool(
            flow.syn and flow.syn_ack and packet.flags & 16 and not packet.flags & 2
        )
        if flow.streams:
            flow.streams[direction].add(packet.seq, packet.payload, bool(packet.flags & 2))

    def finish(self) -> None:
        for key in list(self.items):
            self.remove(key, "end_of_capture")

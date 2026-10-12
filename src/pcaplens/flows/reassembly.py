"""Bounded TCP sequence-space reconstruction; no payload export API."""

import hashlib

from pcaplens.dissect.errors import WarningLog
from pcaplens.limits import Limits

MODULUS = 1 << 32
HALF = 1 << 31


def distance(sequence: int, origin: int) -> int:
    """Signed serial distance; ordering beyond half the sequence space is ambiguous."""
    return (sequence - origin + HALF) % MODULUS - HALF


class MemoryBudget:
    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.used = 0
        self.peak = 0

    def reserve(self, amount: int) -> bool:
        if self.used + amount > self.maximum:
            return False
        self.used += amount
        self.peak = max(self.peak, self.used)
        return True


class Stream:
    def __init__(
        self, limits: Limits, budget: MemoryBudget, warnings: WarningLog, policy: str = "first"
    ) -> None:
        if policy not in ("first", "last", "reject"):
            raise ValueError("Overlap policy must be first, last, or reject")
        self.limits, self.budget, self.warnings, self.policy = limits, budget, warnings, policy
        self.origin: int | None = None
        self.anchored = False
        self.data = bytearray()
        self.present = bytearray()
        self.segments = 0
        self.retransmissions = 0
        self.overlaps = 0
        self.limited = False

    def add(self, sequence: int, payload: bytes, syn: bool = False) -> None:
        start_sequence = (sequence + int(syn)) % MODULUS
        if self.origin is None:
            self.origin = start_sequence
            self.anchored = syn
        if not payload:
            return
        offset = distance(start_sequence, self.origin)
        prepend = max(0, -offset)
        if prepend and self.anchored:
            self.warnings.record("sequence_before_syn", "Segment precedes known stream origin")
            return
        new_length = max(len(self.data) + prepend, offset + prepend + len(payload))
        if (
            new_length > self.limits.max_stream_bytes
            or self.segments >= self.limits.max_segment_count
            or not self.budget.reserve(2 * (new_length - len(self.data)))
        ):
            self.limited = True
            self.warnings.record(
                "reassembly_limit", "TCP stream bytes, segments, or total cap reached"
            )
            return
        self.segments += 1
        if prepend:
            self.data[:0] = b"\0" * prepend
            self.present[:0] = b"\0" * prepend
            self.origin = start_sequence
            offset = 0
        self.data.extend(b"\0" * (new_length - len(self.data)))
        self.present.extend(b"\0" * (new_length - len(self.present)))
        overlap = any(self.present[offset : offset + len(payload)])
        if overlap:
            self.retransmissions += 1
            self.overlaps += 1
            if self.policy == "reject":
                self.warnings.record("tcp_overlap", "Overlapping TCP segment rejected")
                return
        for index, value in enumerate(payload, offset):
            if not self.present[index] or self.policy == "last":
                self.data[index] = value
                self.present[index] = 1

    def runs(self) -> list[tuple[int, bytes]]:
        """Return contiguous observed runs, never bridge unknown gaps."""
        result: list[tuple[int, bytes]] = []
        index = 0
        while index < len(self.data):
            if not self.present[index]:
                index += 1
                continue
            start = index
            while index < len(self.data) and self.present[index]:
                index += 1
            result.append((start, bytes(self.data[start:index])))
        return result

    def metadata(self) -> dict[str, object]:
        runs = self.runs()
        return {
            "origin": self.origin,
            "syn_observed": self.anchored,
            "captured_bytes": sum(self.present),
            "gap_bytes": len(self.data) - sum(self.present),
            "limited": self.limited,
            "overlap_policy": self.policy,
            "retransmission_estimate": self.retransmissions,
            "runs": [
                {"offset": pos, "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                for pos, data in runs
            ],
        }

    def close(self) -> None:
        self.budget.used -= 2 * len(self.data)
        self.data.clear()
        self.present.clear()

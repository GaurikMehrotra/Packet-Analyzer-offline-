"""Typed packet records; payloads stay transient and never enter reports."""

from dataclasses import dataclass, field
from typing import Any
from pcaplens.dissect.errors import ParseWarning


@dataclass(frozen=True)
class CapturePacket:
    timestamp_ns: int
    data: bytes
    original_length: int
    link_type: int
    interface: int = 0


@dataclass
class Packet:
    timestamp_ns: int
    captured_length: int
    original_length: int
    protocols: list[str] = field(default_factory=list)
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    transport: str = ""
    payload: bytes = b""
    seq: int = 0
    ack: int = 0
    flags: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[ParseWarning] = field(default_factory=list)
    warnings_suppressed: int = 0

    def fields(self) -> dict[str, Any]:
        return {
            "ip.src": self.src,
            "ip.dst": self.dst,
            "tcp.port": (self.sport, self.dport),
            "udp.port": (self.sport, self.dport),
            "port": (self.sport, self.dport),
            "tcp.flags": self.flags,
            "length": self.captured_length,
            **{name: True for name in self.protocols},
        }

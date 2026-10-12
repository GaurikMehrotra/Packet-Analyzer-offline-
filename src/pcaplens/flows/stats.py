"""Conversation aggregation helpers used by evaluation."""

from typing import Any


def aggregate(flows: list[dict[str, Any]]) -> dict[str, tuple[int, int]]:
    result: dict[str, tuple[int, int]] = {}
    for flow in flows:
        key = f"{flow['protocol']}:{flow['a']['ip']}:{flow['a']['port']}-{flow['b']['ip']}:{flow['b']['port']}"
        packets, size = result.get(key, (0, 0))
        result[key] = packets + sum(flow["packets"]), size + sum(flow["captured_bytes"])
    return result

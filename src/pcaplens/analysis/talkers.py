"""Endpoint traffic totals count a packet at both endpoints."""

from typing import Any


def top(result: dict[str, Any], count: int = 10) -> list[dict[str, Any]]:
    return list(result["talkers"][: max(0, count)])

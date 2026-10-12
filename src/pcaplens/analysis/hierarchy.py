"""Protocol-path counts include each observed parser layer."""

from typing import Any


def rows(result: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"path": key, "packets": value} for key, value in sorted(result["hierarchy"].items())]

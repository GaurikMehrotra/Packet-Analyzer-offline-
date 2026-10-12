"""Deterministically ordered JSON metadata export."""

import json
from typing import Any

from pcaplens.output.sanitize import sanitize


def render(value: Any) -> str:
    return json.dumps(sanitize(value), sort_keys=True, indent=2, ensure_ascii=True) + "\n"

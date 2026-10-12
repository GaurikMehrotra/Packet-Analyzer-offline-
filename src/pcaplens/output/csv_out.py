"""CSV exports neutralize formula prefixes even after leading whitespace."""

import csv
import io
import json
from typing import Any

from pcaplens.output.sanitize import text


def cell(value: Any) -> str:
    result = text(
        json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    )
    return "'" + result if result.lstrip().startswith(("=", "+", "-", "@")) else result


def render(rows: list[dict[str, Any]]) -> str:
    output = io.StringIO(newline="")
    fields = sorted({key for row in rows for key in row})
    writer = csv.writer(output)
    writer.writerow([cell(key) for key in fields])
    for row in rows:
        writer.writerow([cell(row.get(key, "")) for key in fields])
    return output.getvalue()

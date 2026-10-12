"""Rich renders untrusted values as plain Text, never markup."""

import json
from typing import Any

from rich.table import Table
from rich.text import Text

from pcaplens.output.sanitize import text


def render(rows: list[dict[str, Any]]) -> Table:
    fields = sorted({key for row in rows for key in row})
    table = Table()
    for key in fields:
        table.add_column(Text(text(key)))
    for row in rows:
        table.add_row(*(Text(text(json.dumps(row.get(key, ""), sort_keys=True))) for key in fields))
    return table

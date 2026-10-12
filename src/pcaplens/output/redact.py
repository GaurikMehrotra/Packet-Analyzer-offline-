"""Conservative metadata redaction; bodies are never retained."""

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE = re.compile(
    r"authorization|cookie|password|passwd|secret|token|api[-_]?key|credential", re.I
)


def url(value: str) -> str:
    try:
        parts = urlsplit(value)
        # Drop userinfo and fragments; redact all query values conservatively.
        netloc = parts.netloc.rsplit("@", 1)[-1]
        query = urlencode(
            [(key, "[REDACTED]") for key, _ in parse_qsl(parts.query, keep_blank_values=True)]
        )
        return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except ValueError:
        return "[REDACTED malformed URL]"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]"
            if SENSITIVE.search(str(key))
            else url(item)
            if key == "url" and isinstance(item, str)
            else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    if isinstance(value, str) and SENSITIVE.search(value) and ("=" in value or ":" in value):
        return "[REDACTED sensitive text]"
    return value

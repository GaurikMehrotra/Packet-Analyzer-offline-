"""Strip C0/C1 controls and Unicode formatting controls from all output strings."""

import unicodedata
from typing import Any

ASCII_CONTROLS = dict.fromkeys([*range(32), 127])


def text(value: str) -> str:
    if value.isascii():
        return value.translate(ASCII_CONTROLS)
    return "".join(char for char in value if unicodedata.category(char) not in ("Cc", "Cf", "Cs"))


def sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return text(value)
    if isinstance(value, dict):
        return {text(str(key)): sanitize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    return value

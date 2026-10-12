"""Bounded diagnostics for untrusted input."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ParseWarning:
    code: str
    message: str
    offset: int = 0


class ParseError(ValueError):
    def __init__(self, code: str, message: str, offset: int = 0) -> None:
        super().__init__(message)
        self.warning = ParseWarning(code, message, offset)


class WarningLog:
    """Retain a limited diagnostic sample and count all suppressed warnings."""

    def __init__(self, maximum: int) -> None:
        self.maximum = maximum
        self.items: list[ParseWarning] = []
        self.count = 0

    def add(self, warning: ParseWarning) -> None:
        self.count += 1
        if len(self.items) < self.maximum:
            self.items.append(warning)

    def record(self, code: str, message: str, offset: int = 0) -> None:
        self.add(ParseWarning(code, message, offset))

    def export(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "suppressed": self.count - len(self.items),
            "items": [asdict(item) for item in self.items],
        }

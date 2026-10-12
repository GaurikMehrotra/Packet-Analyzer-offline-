"""Validated analysis defaults, separate from resource budgets."""

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    checksum: bool = False
    overlap_policy: Literal["first", "last", "reject"] = "first"
    redact: bool = True
    anonymize: bool = False
    scan_ports: int = Field(default=20, ge=2, le=65536)
    scan_window_seconds: int = Field(default=60, ge=1, le=86400)
    dns_length: int = Field(default=80, ge=1, le=255)
    dns_entropy: float = Field(default=4.0, ge=0, le=16)
    beacon_min_intervals: int = Field(default=5, ge=2, le=10000)
    beacon_cv: float = Field(default=0.1, ge=0, le=10)

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        if path is None:
            return cls()
        if path.stat().st_size > 65536:
            raise ValueError("Settings config exceeds 64 KiB")
        with path.open(encoding="utf-8") as source:
            try:
                return cls.model_validate(yaml.safe_load(source))
            except yaml.YAMLError as error:
                raise ValueError("Malformed settings YAML") from error

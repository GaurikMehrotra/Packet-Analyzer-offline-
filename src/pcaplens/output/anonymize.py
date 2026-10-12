"""Consistent per-run keyed pseudonyms. Never persist the random key."""

import hashlib
import hmac
import ipaddress
import re
import secrets
from typing import Any

MAC = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
MAC_EMBEDDED = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![0-9a-fA-F])")
IPV4_EMBEDDED = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_EMBEDDED = re.compile(r"(?<![\w:])[0-9a-fA-F]*:[0-9a-fA-F:]+")


class Anonymizer:
    def __init__(self, key: bytes | None = None) -> None:
        self.key = key or secrets.token_bytes(32)

    def pseudonym(self, value: str) -> str:
        category = ""
        normalized = value
        if MAC.fullmatch(value):
            category, normalized = "mac", value.lower()
        else:
            try:
                address = ipaddress.ip_address(value)
                category, normalized = "ip", str(address)
            except ValueError:
                return value
        digest = hmac.new(self.key, (category + normalized).encode(), hashlib.sha256).hexdigest()[
            :24
        ]
        return category + "_" + digest

    def string(self, value: str) -> str:
        exact = self.pseudonym(value)
        if exact != value:
            return exact
        value = MAC_EMBEDDED.sub(lambda match: self.pseudonym(match.group()), value)
        value = IPV4_EMBEDDED.sub(lambda match: self.pseudonym(match.group()), value)
        return IPV6_EMBEDDED.sub(lambda match: self.pseudonym(match.group()), value)

    def apply(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.string(value)
        if isinstance(value, dict):
            return {self.string(str(key)): self.apply(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.apply(item) for item in value]
        return value

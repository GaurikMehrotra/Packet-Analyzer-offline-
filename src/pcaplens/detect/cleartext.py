"""Credential-header presence is reported without copying secret values."""

from typing import Any
from urllib.parse import parse_qsl, urlsplit

from pcaplens.output.redact import SENSITIVE


def detect(result: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for message in result["http"]:
        fields = [key for key in message["headers"] if SENSITIVE.search(key)]
        try:
            fields.extend(
                key
                for key, _ in parse_qsl(urlsplit(message.get("url", "")).query)
                if SENSITIVE.search(key)
            )
        except ValueError:
            pass
        if fields:
            alerts.append(
                {
                    "heuristic": "cleartext_sensitive_fields",
                    "evidence": {"field_names": sorted(fields)},
                    "uncertainty": "Presence does not establish that a value is a valid credential; values withheld.",
                }
            )
    return alerts

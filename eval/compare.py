"""Exact field agreement: empty comparisons are unmeasured, not 100 percent."""

from typing import Any


def agreement(
    name: str, actual: dict[str, Any], reference: dict[str, Any], explanation: str
) -> dict[str, Any]:
    keys = sorted(actual.keys() | reference.keys())
    differences = [
        {
            "key": key,
            "pcaplens": actual.get(key),
            "tshark": reference.get(key),
            "explanation": explanation,
        }
        for key in keys
        if actual.get(key) != reference.get(key)
    ]
    return {
        "field": name,
        "compared": len(keys),
        "agreed": len(keys) - len(differences),
        "agreement_percent": 100 * (len(keys) - len(differences)) / len(keys) if keys else None,
        "differences": differences,
    }

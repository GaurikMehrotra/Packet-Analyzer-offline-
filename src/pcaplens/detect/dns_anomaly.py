"""Name-length/entropy and NXDOMAIN-rate evidence, without verdicts."""

import math
from collections import Counter
from typing import Any


def entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values()) if value else 0


def detect(
    result: dict[str, Any], length: int = 80, threshold: float = 4.0
) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for message in result["dns"]:
        for question in message["questions"]:
            value = question["name"]
            score = entropy(value)
            if len(value) >= length or score >= threshold:
                alerts.append(
                    {
                        "heuristic": "dns_name",
                        "evidence": {"name": value, "length": len(value), "entropy": score},
                        "uncertainty": "Long or diverse names also occur in legitimate services.",
                    }
                )
    responses = [item for item in result["dns"] if item["response"]]
    failures = sum(item["rcode"] == 3 for item in responses)
    if len(responses) >= 5 and failures / len(responses) >= 0.5:
        alerts.append(
            {
                "heuristic": "dns_nxdomain",
                "evidence": {"responses": len(responses), "nxdomain": failures},
                "uncertainty": "Aggregate rate may mix unrelated clients; configuration errors are possible.",
            }
        )
    return alerts

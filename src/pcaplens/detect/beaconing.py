"""Low interval variability is timing evidence, not proof of beaconing."""

import statistics
from typing import Any


def detect(result: dict[str, Any], minimum: int = 5, cv: float = 0.1) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for flow in result["flows"]:
        times = sorted(set(flow["times_ns"]))
        intervals = [b - a for a, b in zip(times, times[1:])]
        if len(intervals) >= minimum:
            mean = statistics.mean(intervals)
            variation = statistics.pstdev(intervals) / mean if mean else 0.0
            if variation <= cv:
                alerts.append(
                    {
                        "heuristic": "periodic_timing",
                        "evidence": {
                            "a": flow["a"],
                            "b": flow["b"],
                            "intervals": len(intervals),
                            "cv": variation,
                        },
                        "uncertainty": "Polling, keepalives, and sampled capture timing can look periodic.",
                    }
                )
    return alerts

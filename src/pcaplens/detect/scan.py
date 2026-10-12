"""Distinct destination ports after observed SYNs in a bounded time window."""

from collections import Counter, defaultdict, deque
from typing import Any


def detect(
    result: dict[str, Any], ports: int = 20, window_seconds: int = 60
) -> list[dict[str, Any]]:
    events: dict[tuple[str, str], list[tuple[int, int]]] = defaultdict(list)
    for flow in result["flows"]:
        initiator = flow.get("syn_initiator")
        if flow["protocol"] != "tcp" or initiator is None:
            continue
        endpoints = flow["a"], flow["b"]
        source, target = endpoints[initiator], endpoints[1 - initiator]
        events[(source["ip"], target["ip"])].append((flow["first_ns"], target["port"]))
    alerts: list[dict[str, Any]] = []
    for (source, target), values in sorted(events.items()):
        observed: deque[tuple[int, int]] = deque()
        counts: Counter[int] = Counter()
        for stamp, port in sorted(values):
            while observed and stamp - observed[0][0] > window_seconds * 1_000_000_000:
                _, old_port = observed.popleft()
                counts[old_port] -= 1
                if not counts[old_port]:
                    del counts[old_port]
            observed.append((stamp, port))
            counts[port] += 1
            if len(counts) >= ports:
                alerts.append(
                    {
                        "heuristic": "port_scan",
                        "evidence": {
                            "source_ip": source,
                            "target_ip": target,
                            "distinct_destination_ports": len(counts),
                            "threshold": ports,
                            "window_seconds": window_seconds,
                        },
                        "uncertainty": "SYN port diversity can reflect authorized scanning or legitimate fanout; missing or evicted flows reduce evidence.",
                    }
                )
                break
    return alerts

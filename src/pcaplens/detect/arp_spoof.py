"""ARP mapping changes may indicate failover, mobility, or spoofing."""

from typing import Any


def detect(result: dict[str, Any]) -> list[dict[str, Any]]:
    observed: dict[str, str] = {}
    alerts: list[dict[str, Any]] = []
    for packet in sorted(result["arp"], key=lambda item: item["timestamp_ns"]):
        ip, mac = packet["src"], packet.get("arp.mac", "")
        if ip and mac and ip in observed and observed[ip] != mac:
            alerts.append(
                {
                    "heuristic": "arp_mapping_change",
                    "evidence": {"ip": ip, "previous_mac": observed[ip], "new_mac": mac},
                    "uncertainty": "Failover, address reuse, and legitimate mobility are alternative explanations.",
                }
            )
        if ip and mac:
            observed[ip] = mac
    return alerts

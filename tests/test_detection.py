from pcaplens.detect import arp_spoof, beaconing, cleartext, dns_anomaly, scan


def test_detectors_evidence_without_values():
    a, b = {"ip": "192.0.2.1", "port": 1000}, {"ip": "198.51.100.1", "port": 80}
    flows = [
        {
            "protocol": "tcp",
            "syn_initiator": 0,
            "first_ns": 0,
            "a": a,
            "b": {**b, "port": port},
            "times_ns": [p * 1000000000 for p in range(10)],
        }
        for port in range(20)
    ]
    result = {
        "flows": flows,
        "dns": [{"response": False, "rcode": 0, "questions": [{"name": "synthetic" * 20}]}],
        "arp": [
            {"timestamp_ns": 0, "src": a["ip"], "arp.mac": "02:00:00:00:00:01"},
            {"timestamp_ns": 1, "src": a["ip"], "arp.mac": "02:00:00:00:00:02"},
        ],
        "http": [{"headers": {"authorization": "synthetic-only"}, "url": "/?token=synthetic-only"}],
    }
    for detector in (
        scan.detect,
        dns_anomaly.detect,
        beaconing.detect,
        arp_spoof.detect,
        cleartext.detect,
    ):
        alerts = detector(result)
        assert alerts
        assert all(
            "evidence" in alert and "uncertainty" in alert and "heuristic" in alert
            for alert in alerts
        )
        assert "synthetic-only" not in repr(alerts)

"""Labeled synthetic heuristic evaluation, threshold sensitivity and timing jitter."""

import argparse
import csv
import importlib.util
import json
import random
import string
import struct
import tempfile
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, IP, UDP

from pcaplens.analysis.summary import analyze
from pcaplens.detect import arp_spoof, beaconing, cleartext, dns_anomaly, scan


def metrics(truth: list[bool], predicted: list[bool]) -> dict:
    tp = sum(a and b for a, b in zip(truth, predicted))
    fp = sum(not a and b for a, b in zip(truth, predicted))
    fn = sum(a and not b for a, b in zip(truth, predicted))
    tn = sum(not a and not b for a, b in zip(truth, predicted))
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "false_positive_rate": fp / (fp + tn) if fp + tn else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20250317)
    parser.add_argument("--cases", type=int, default=20)
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument(
        "--lab-manifest",
        type=Path,
        help="User-authored JSON labels for authorized local lab captures",
    )
    args = parser.parse_args()
    if args.cases < 2:
        parser.error("At least two cases required")
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "fixture_generator", root / "fixtures/generate_fixtures.py"
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    rng = random.Random(args.seed)
    rows = []
    cases = []
    with tempfile.TemporaryDirectory(prefix="pcaplens-detection-") as directory:
        path = Path(directory) / "synthetic.pcap"
        for family in ("scan", "dns", "beacon", "arp", "cleartext"):
            for index in range(args.cases):
                label = index % 2 == 0
                jitter = (index // 2 % 3) * 0.1
                if family == "scan":
                    frames = [
                        generator.tcp(100, flags="S", ack=0, port=1000 + p)
                        for p in range(40 if label or index % 4 == 1 else 3)
                    ]
                elif family == "dns":
                    name = (
                        (
                            "".join(
                                rng.choice(string.ascii_lowercase + string.digits)
                                for _ in range(50)
                            )
                            + ".synthetic.test"
                        )
                        if label
                        else "synthetic.test"
                    )
                    frames = [
                        bytes(
                            generator.ethernet(
                                IP(src=generator.A, dst=generator.B)
                                / UDP(sport=53000, dport=53)
                                / DNS(qd=DNSQR(qname=name))
                            )
                        )
                    ]
                elif family == "arp":
                    # Negative failover cases intentionally share the observable mapping-change evidence.
                    frames = [
                        bytes(
                            generator.ethernet(ARP(hwsrc=mac, psrc=generator.A, pdst=generator.B))
                        )
                        for mac in [
                            generator.MAC_A,
                            "02:00:00:00:00:03" if label or index % 4 == 1 else generator.MAC_A,
                        ]
                    ]
                elif family == "cleartext":
                    header = (
                        b"Authorization: Bearer synthetic-only\r\n"
                        if label
                        else b"Accept: text/plain\r\n"
                    )
                    frames = [generator.tcp(100, b"GET / HTTP/1.1\r\n" + header + b"\r\n")]
                else:
                    frames = [generator.tcp(100 + 2 * p, b"xx") for p in range(10)]
                content = generator.pcap(frames)
                if family == "beacon":
                    value = bytearray(content)
                    offset = 24
                    clock = 0.0
                    for frame in frames:
                        clock += 1 + rng.uniform(-jitter, jitter) if label else rng.uniform(0.1, 3)
                        seconds = int(clock)
                        value[offset : offset + 8] = struct.pack(
                            "<II", generator.EPOCH + seconds, int((clock - seconds) * 1e6)
                        )
                        offset += 16 + len(frame)
                    content = bytes(value)
                path.write_bytes(content)
                result = analyze(path)
                cases.append({"family": family, "label": label, "jitter": jitter, "result": result})
    lab_count = 0
    lab_failures = []
    if args.lab_manifest:
        if args.lab_manifest.stat().st_size > 65536:
            parser.error("Lab manifest exceeds 64 KiB")
        entries = json.loads(args.lab_manifest.read_text())
        if not isinstance(entries, list) or len(entries) > 1000:
            parser.error("Manifest must be a list of at most 1000 labeled cases")
        for index, entry in enumerate(entries):
            if (
                entry.get("family") not in ("scan", "dns", "beacon", "arp", "cleartext")
                or type(entry.get("label")) is not bool
            ):
                parser.error("Each case requires family, boolean label, and relative capture file")
            capture = args.lab_manifest.parent / entry["file"]
            result = analyze(capture)
            if result["warnings"]["count"]:
                lab_failures.append(
                    {
                        "case": index,
                        "warning_codes": [w["code"] for w in result["warnings"]["items"]],
                    }
                )
                continue
            lab_count += 1
            cases.append(
                {
                    "family": entry["family"],
                    "label": entry["label"],
                    "jitter": None,
                    "result": result,
                    "lab": True,
                }
            )
    for family in ("scan", "dns", "beacon", "arp", "cleartext"):
        parameters = (
            (10, 20, 50)
            if family == "scan"
            else (3.0, 4.0, 5.0)
            if family == "dns"
            else (0.05, 0.1, 0.3)
            if family == "beacon"
            else (None,)
        )
        subset = [case for case in cases if case["family"] == family and not case.get("lab")]
        for parameter in parameters:

            def prediction(case):
                result = case["result"]
                if family == "scan":
                    return bool(scan.detect(result, int(parameter)))
                if family == "dns":
                    return bool(dns_anomaly.detect(result, threshold=float(parameter)))
                if family == "beacon":
                    return bool(beaconing.detect(result, cv=float(parameter)))
                return bool(
                    arp_spoof.detect(result) if family == "arp" else cleartext.detect(result)
                )

            lab_subset = [case for case in cases if case["family"] == family and case.get("lab")]
            if lab_subset:
                rows.append(
                    {
                        "family": family,
                        "threshold": parameter,
                        "scope": "user-labeled authorized lab, case-level",
                        **metrics(
                            [case["label"] for case in lab_subset],
                            [prediction(case) for case in lab_subset],
                        ),
                    }
                )
            rows.append(
                {
                    "family": family,
                    "threshold": parameter,
                    "scope": "synthetic, case-level",
                    **metrics(
                        [case["label"] for case in subset], [prediction(case) for case in subset]
                    ),
                }
            )
            if family == "beacon":
                for jitter in sorted({case["jitter"] for case in subset}):
                    selected = [case for case in subset if case["jitter"] == jitter]
                    rows.append(
                        {
                            "family": "beacon_jitter",
                            "threshold": parameter,
                            "scope": f"synthetic jitter={jitter}",
                            **metrics(
                                [case["label"] for case in selected],
                                [prediction(case) for case in selected],
                            ),
                        }
                    )
    args.output.mkdir(parents=True, exist_ok=True)
    document = {
        "seed": args.seed,
        "cases_per_family": args.cases,
        "labels": "Synthetic generation intent; not real-world maliciousness",
        "lab_captures": {
            "evaluated": lab_count,
            "excluded_due_to_warnings": lab_failures,
            "status": "supplied" if args.lab_manifest else "not supplied, not evaluated",
        },
        "rows": rows,
    }
    (args.output / "detection.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n"
    )
    with (args.output / "detection.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    defaults = {"scan": 20, "dns": 4.0, "beacon": 0.1, "arp": None, "cleartext": None}
    selected = [
        row
        for row in rows
        if row["scope"] == "synthetic, case-level"
        and row["threshold"] == defaults.get(row["family"])
        and row["family"] in defaults
    ]
    figure, axes = plt.subplots(figsize=(8, 4))
    for offset, field in enumerate(("tp", "fp", "fn", "tn")):
        axes.bar(
            [index + offset * 0.2 for index in range(len(selected))],
            [row[field] for row in selected],
            width=0.2,
            label=field.upper(),
        )
    axes.set_xticks(
        [index + 0.3 for index in range(len(selected))], [row["family"] for row in selected]
    )
    axes.set(
        ylabel="Synthetic cases", title="Toy-label confusion counts; no deployment accuracy claim"
    )
    axes.legend()
    figure.tight_layout()
    figure.savefig(args.output / "detection.png")
    plt.close(figure)
    figure, axes = plt.subplots(figsize=(7, 4))
    for threshold in (0.05, 0.1, 0.3):
        selected = sorted(
            [
                row
                for row in rows
                if row["family"] == "beacon_jitter" and row["threshold"] == threshold
            ],
            key=lambda row: row["scope"],
        )
        axes.plot(
            [float(row["scope"].split("=")[1]) for row in selected],
            [row["recall"] for row in selected],
            marker="o",
            label=f"CV threshold {threshold}",
        )
    axes.set(
        xlabel="Uniform interval jitter amplitude (seconds)",
        ylabel="Synthetic recall",
        title="Sensitivity to timing jitter",
    )
    axes.legend()
    figure.tight_layout()
    figure.savefig(args.output / "detection_jitter.png")
    plt.close(figure)
    print(
        f"Saved synthetic detection metrics to {args.output}; no lab or deployment accuracy claim"
    )


if __name__ == "__main__":
    main()

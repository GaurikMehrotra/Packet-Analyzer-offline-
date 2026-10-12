"""Measured full-analysis versus dpkt parse-only throughput and parameter ablations."""

import argparse
import cProfile
import csv
import importlib.util
import json
import hashlib
import platform
import pstats
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import dpkt
import psutil

from pcaplens import __version__
from pcaplens.analysis.summary import analyze
from pcaplens.limits import Limits


def worker(path: Path, engine: str, settings: dict) -> dict:
    process = psutil.Process()
    peak = [process.memory_info().rss]
    done = threading.Event()

    def sample():
        while not done.wait(0.002):
            peak[0] = max(peak[0], process.memory_info().rss)

    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    started = time.perf_counter()
    try:
        if engine == "dpkt":
            count = 0
            with path.open("rb") as source:
                for _, frame in dpkt.pcap.Reader(source):
                    dpkt.ethernet.Ethernet(frame)
                    count += 1
            warnings, flows, used, digest = 0, None, None, None
        else:
            options = {key: settings[key] for key in ("checksum", "overlap") if key in settings}
            limits = Limits(**{key: value for key, value in settings.items() if key not in options})
            result = analyze(path, limits, **options)
            count = result["summary"]["packets"]
            warnings, flows = result["warnings"]["count"], result["summary"]["flow_instances"]
            used = result["summary"]["reassembly_peak_accounted_bytes"]
            digest = hashlib.sha256(
                json.dumps([flow["streams"] for flow in result["flows"]], sort_keys=True).encode()
            ).hexdigest()
    finally:
        done.set()
        thread.join()
    elapsed = time.perf_counter() - started
    peak[0] = max(peak[0], process.memory_info().rss)
    return {
        "engine": engine,
        "settings": settings,
        "packets": count,
        "file_bytes": path.stat().st_size,
        "seconds": elapsed,
        "packets_per_second": count / elapsed,
        "decimal_MB_per_second": path.stat().st_size / 1e6 / elapsed,
        "sampled_peak_rss_bytes": peak[0],
        "warnings": warnings,
        "flows": flows,
        "reassembly_peak_accounted_bytes": used,
        "stream_metadata_sha256": digest,
    }


def generate(path: Path, count: int) -> None:
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "fixture_generation", root / "fixtures/generate_fixtures.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import struct

    # Many flows, payload data and timestamp gaps expose flow caps and timeout effects.
    with path.open("wb") as output:
        output.write(module.pcap([]))
        for index in range(count):
            frame = module.tcp(
                (index // 128) % 10 * 16,
                f"synthetic-{index % 3:06d}".encode(),
                port=1000 + index % 128,
            )
            output.write(struct.pack("<IIII", module.EPOCH + index, 0, len(frame), len(frame)))
            output.write(frame)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 10000, 50000])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("results"))
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--engine", choices=["pcaplens", "dpkt"], default="pcaplens")
    parser.add_argument("--settings", default="{}")
    args = parser.parse_args()
    if args.worker:
        print(json.dumps(worker(args.worker, args.engine, json.loads(args.settings))))
        return
    if args.repeats < 1 or any(not 0 < size <= 1000000 for size in args.sizes):
        parser.error("Positive repeats and sizes <= 1,000,000 required")
    args.output.mkdir(parents=True, exist_ok=True)
    rows = []
    ablations = (
        [{"flow_timeout": value} for value in (1, 60, 10000)]
        + [{"overlap": value, "flow_timeout": 10000} for value in ("first", "last", "reject")]
        + [{"max_flows": value} for value in (32, 4096)]
        + [{"checksum": value} for value in (False, True)]
    )
    with tempfile.TemporaryDirectory(prefix="pcaplens-bench-") as directory:
        for size in args.sizes:
            path = Path(directory) / "synthetic.pcap"
            generate(path, size)
            for engine in ("pcaplens", "dpkt"):
                for repeat in range(args.repeats):
                    command = [sys.executable, __file__, "--worker", str(path), "--engine", engine]
                    result = subprocess.run(
                        command, check=True, capture_output=True, text=True, timeout=300
                    )
                    rows.append(
                        {**json.loads(result.stdout), "experiment": "throughput", "repeat": repeat}
                    )
        for settings in ablations:
            result = subprocess.run(
                [
                    sys.executable,
                    __file__,
                    "--worker",
                    str(path),
                    "--settings",
                    json.dumps(settings),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=300,
            )
            rows.append({**json.loads(result.stdout), "experiment": "ablation", "repeat": 0})
        profiler = cProfile.Profile()
        profiler.runcall(analyze, path)
        stats = pstats.Stats(profiler)
        hot = sorted(stats.stats.items(), key=lambda pair: -pair[1][3])[:25]
        profile = [
            {
                "function": Path(key[0]).name + ":" + str(key[1]) + ":" + key[2],
                "primitive_calls": value[0],
                "total_calls": value[1],
                "self_seconds": value[2],
                "cumulative_seconds": value[3],
            }
            for key, value in hot
        ]
    document = {
        "tool_version": __version__,
        "python": platform.python_version(),
        "machine": platform.machine(),
        "logical_cpus": psutil.cpu_count(),
        "physical_memory_bytes": psutil.virtual_memory().total,
        "hardware_scope": "execution machine, not necessarily the user's laptop",
        "seed": 0,
        "rss_sample_interval_seconds": 0.002,
        "baseline_scope": "dpkt parse-only L2-L4 versus pcaplens full analysis; workloads differ",
        "rows": rows,
        "profile": profile,
    }
    (args.output / "performance.json").write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n"
    )
    with (args.output / "performance.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(
            {**row, "settings": json.dumps(row["settings"], sort_keys=True)} for row in rows
        )
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    figure, axes = plt.subplots(1, 2, figsize=(10, 4))
    for engine in ("pcaplens", "dpkt"):
        selected = [
            row for row in rows if row["engine"] == engine and row["experiment"] == "throughput"
        ]
        axes[0].scatter(
            [row["file_bytes"] / 1e6 for row in selected],
            [row["packets_per_second"] for row in selected],
            label=engine,
        )
        axes[1].scatter(
            [row["file_bytes"] / 1e6 for row in selected],
            [row["sampled_peak_rss_bytes"] / 1e6 for row in selected],
            label=engine,
        )
    for axes_item in axes:
        axes_item.set_xlabel("Input size (decimal MB)")
        axes_item.legend()
    axes[0].set_ylabel("Packets / second")
    axes[1].set_ylabel("Sampled peak RSS (decimal MB)")
    figure.tight_layout()
    figure.savefig(args.output / "performance.png")
    plt.close(figure)
    selected = [row for row in rows if row["experiment"] == "ablation"]
    labels = [json.dumps(row["settings"], sort_keys=True) for row in selected]
    figure, axes = plt.subplots(2, 2, figsize=(12, 9))
    for axes_item, field, label in zip(
        axes.flat,
        ("packets_per_second", "sampled_peak_rss_bytes", "flows", "warnings"),
        ("Packets / second", "Sampled peak RSS (bytes)", "Flow instances", "Recorded warnings"),
    ):
        axes_item.barh(labels, [row[field] for row in selected])
        axes_item.set_xlabel(label)
        axes_item.tick_params(axis="y", labelsize=7)
    figure.suptitle("Synthetic parameter ablations; one measurement per setting")
    figure.tight_layout()
    figure.savefig(args.output / "ablations.png")
    plt.close(figure)
    print(f"Saved performance, ablations, and profile to {args.output}")


if __name__ == "__main__":
    main()

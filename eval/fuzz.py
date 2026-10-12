"""Fixed-seed capture mutations, per-case deadline, and sampled RSS measurement."""

import argparse
import json
import random
import signal
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

import psutil

from pcaplens.analysis.summary import analyze
from pcaplens.limits import Limits


class Deadline(Exception):
    pass


def expired(signum, frame):
    raise Deadline("Per-case timeout")


def mutate(source: bytes, rng: random.Random, index: int) -> tuple[str, bytes]:
    data = bytearray(source)
    kind = index % 4
    if kind == 0:
        for _ in range(rng.randint(1, 4)):
            position = rng.randrange(len(data))
            data[position] ^= 1 << rng.randrange(8)
        return "bit_flip", bytes(data)
    if kind == 1:
        return "truncation", bytes(data[: rng.randrange(len(data) + 1)])
    if kind == 2:
        positions = [16, 32, 36] if source[:4] != b"\x0a\x0d\x0d\x0a" else [4, 24, 32, 48]
        position = rng.choice(positions)
        if position + 4 <= len(data):
            data[position : position + 4] = rng.choice([b"\xff" * 4, b"\0" * 4, b"\x04\0\0\0"])
        return "length_tamper", bytes(data)
    left, right = rng.sample(range(max(1, len(data) - 4)), 2)
    a, b = bytes(data[left : left + 4]), bytes(data[right : right + 4])
    data[left : left + 4], data[right : right + 4] = b, a
    return "field_swap", bytes(data)


def campaign(captures: list[Path], cases: int, seed: int, timeout: float) -> dict:
    if not hasattr(signal, "setitimer"):
        raise RuntimeError("Per-case deadlines require POSIX; run this campaign in WSL2/Linux")
    sources = [path.read_bytes() for path in captures]
    if not sources or any(not source or len(source) > 1_000_000 for source in sources):
        raise ValueError("Use nonempty synthetic seeds smaller than 1 MB")
    rng = random.Random(seed)
    failures = []
    hangs = []
    warning_codes = Counter()
    mutations = Counter()
    process = psutil.Process()
    rss = [process.memory_info().rss]
    stopped = threading.Event()

    def sample():
        while not stopped.wait(0.002):
            rss[0] = max(rss[0], process.memory_info().rss)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    prior = signal.signal(signal.SIGALRM, expired)
    started = time.perf_counter()
    # Lower counts bound work even if a mutation turns bytes into many plausible records.
    limits = Limits(
        max_packets=1000,
        max_flows=64,
        max_metadata=128,
        max_stream_bytes=65536,
        max_reassembly_total=1048576,
        max_metadata_bytes=1048576,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="pcaplens-fuzz-") as directory:
            path = Path(directory) / "mutant.pcap"
            for index in range(cases):
                kind, content = mutate(sources[index % len(sources)], rng, index)
                mutations[kind] += 1
                path.write_bytes(content)
                try:
                    signal.setitimer(signal.ITIMER_REAL, timeout)
                    result = analyze(path, limits)
                    warning_codes.update(item["code"] for item in result["warnings"]["items"])
                except Deadline:
                    hangs.append({"case": index, "mutation": kind})
                except Exception as error:
                    failures.append(
                        {"case": index, "mutation": kind, "exception": type(error).__name__}
                    )
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
    finally:
        signal.signal(signal.SIGALRM, prior)
        stopped.set()
        sampler.join()
    return {
        "cases": cases,
        "seed": seed,
        "timeout_seconds": timeout,
        "uncaught_exceptions": failures,
        "timeouts": hangs,
        "mutations": dict(mutations),
        "warning_codes": dict(warning_codes),
        "elapsed_seconds": time.perf_counter() - started,
        "sampled_peak_rss_bytes": rss[0],
        "rss_sample_interval_seconds": 0.002,
        "limits": limits.model_dump(),
        "seeds": [path.name for path in captures],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=20250317)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--output", type=Path, default=Path("results/robustness.json"))
    args = parser.parse_args()
    if args.cases < 1 or args.timeout <= 0:
        parser.error("cases and timeout must be positive")
    root = Path(__file__).resolve().parents[1]
    result = campaign(
        [
            root / "fixtures" / name
            for name in (
                "protocols-le-us.pcap",
                "interfaces-le.pcapng",
                "tls.pcap",
                "reassembly.pcap",
            )
        ],
        args.cases,
        args.seed,
        args.timeout,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                key: result[key]
                for key in (
                    "cases",
                    "elapsed_seconds",
                    "sampled_peak_rss_bytes",
                    "uncaught_exceptions",
                    "timeouts",
                )
            }
        )
    )
    raise SystemExit(1 if result["uncaught_exceptions"] or result["timeouts"] else 0)


if __name__ == "__main__":
    main()

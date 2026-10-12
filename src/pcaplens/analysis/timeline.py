"""Static scientific I/O plot from bounded one-second bins."""

from pathlib import Path
from typing import Any


def series(rows: list[dict[str, Any]]) -> tuple[list[int], list[int]]:
    """Insert at most two zero points per gap; never allocate a dense time span."""
    points: list[tuple[int, int]] = []
    for row in rows:
        stamp, value = int(row["second"]), int(row["captured_bytes"])
        if points and stamp > points[-1][0] + 1:
            previous = points[-1][0]
            points.append((previous + 1, 0))
            if stamp > previous + 2:
                points.append((stamp - 1, 0))
        points.append((stamp, value))
    return [point[0] for point in points], [point[1] for point in points]


def plot(rows: list[dict[str, Any]], path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    figure, axes = plt.subplots(figsize=(8, 3))
    stamps, values = series(rows)
    origin = stamps[0] if stamps else 0
    axes.step([stamp - origin for stamp in stamps], values, where="post")
    axes.set(
        xlabel="Seconds from first retained bin",
        ylabel="Captured bytes / second",
        title="pcaplens I/O timeline",
    )
    figure.tight_layout()
    figure.savefig(path)
    plt.close(figure)

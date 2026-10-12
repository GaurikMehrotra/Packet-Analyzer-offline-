"""Self-contained, script-free HTML with an inline SVG I/O timeline."""

import html
from typing import Any

from pcaplens.analysis.timeline import series
from pcaplens.output.json_out import render as json_render


def timeline(rows: list[dict[str, Any]]) -> str:
    stamps, values = series(rows)
    if not stamps:
        return "<p>No retained timeline bins.</p>"
    duration = max(1, stamps[-1] - stamps[0] + 1)
    peak = max(values)
    maximum = max(1, peak)
    points = []
    for stamp, value in zip(stamps, values):
        x = 40 + 700 * (stamp - stamps[0]) / duration
        next_x = 40 + 700 * (stamp - stamps[0] + 1) / duration
        y = 220 - 180 * value / maximum
        points.extend([f"{x:.2f},{y:.2f}", f"{next_x:.2f},{y:.2f}"])
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 280" role="img" '
        'aria-label="Captured bytes per second in retained timeline bins">'
        '<path d="M40 40V220H740" fill="none" stroke="#444"/>'
        '<polyline fill="none" stroke="#006b8f" stroke-width="2" points="'
        + " ".join(points)
        + '"/>'
        + f'<text x="40" y="250">0</text><text x="700" y="250">{duration} s</text>'
        + f'<text x="50" y="30">Peak bin: {peak} captured bytes/s</text></svg>'
    )


def render(value: Any) -> str:
    sections = value if isinstance(value, dict) else {"metadata": value}
    content = []
    if isinstance(sections.get("timeline"), list):
        content.append("<h2>I/O timeline</h2>" + timeline(sections["timeline"]))
    for label, section in sorted(sections.items()):
        content.append(
            "<details open><summary>"
            + html.escape(str(label), quote=True)
            + "</summary><pre>"
            + html.escape(json_render(section), quote=True)
            + "</pre></details>"
        )
    return (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &apos;none&apos;; '
        'style-src &apos;unsafe-inline&apos;">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>pcaplens offline report</title><style>body{font-family:system-ui;"
        "max-width:1100px;margin:2em auto;padding:0 1em;color:#17252a;background:#fafafa}"
        "pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:.85em}"
        "details{padding:1em;border:1px solid #ccd;margin:1em 0;border-radius:8px}"
        "summary{font-weight:bold}svg{width:100%;height:auto}</style>"
        "<body><h1>pcaplens offline metadata report</h1>"
        "<p>Authorized offline input only. Findings are evidence with uncertainty. "
        "Check warnings and suppressed counters before drawing conclusions.</p>"
        + "".join(content)
        + "</body></html>\n"
    )

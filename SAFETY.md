# Safety and privacy contract

## Authorized offline inputs

Use only synthetic captures, public samples after checking and recording their
terms, or captures from your own authorized isolated lab. Capturing traffic on
networks you do not own or have permission to monitor can violate interception
and privacy laws. This is general information, not legal advice.

The project must never provide live capture, interception, TLS decryption,
payload execution, extracted-file export, or offensive automation. Never open
or execute captured payloads. Outputs are metadata and hashes, not payloads.
Heuristic findings must include evidence and uncertainty, never verdicts.

## Untrusted input and resource limits

Every capture is untrusted, including synthetic files. All parsing will use a
bounds-checked reader. Lengths and offsets must be checked against available
bytes before reads or allocation. No eval, exec, pickle, or dynamic code
generation may process capture content.

configs/limits.yaml and the validated Limits model define the resource defaults. Required
limits cover packet length and count, flow count, per-stream and total
reassembly bytes, header and option counts, IPv6 extension depth, fragment
buffers and bytes, DNS pointer hops and visited offsets, HTTP header bytes,
and decompressed size and ratio. Counts bound work; byte caps bound retained
memory; depth and hop caps prevent cycles and excessive traversal. Each limit
needs a dedicated test. The implementation and dedicated test index are documented in docs/limits.md.
Finite tests and mutation campaigns are empirical evidence, not a proof of total safety.

Malformed input must produce recorded bounded warnings and controlled stops,
not uncaught parser exceptions, hangs, or unlimited allocation. Checksum
mismatches will be warnings because capture offload can affect checksums.
Stream captures rather than loading entire files. Measure memory and speed;
do not infer them from input size or hardware specifications.

## Output privacy and safety

Redact credentials and sensitive values by default, including Authorization,
Cookie, password-like form fields, and query tokens. Do not retain bodies.
Provide consistent optional IP and MAC anonymization within a run.
Strip terminal controls, escape all dynamic HTML, use no external report
resources, and neutralize CSV formula prefixes (=, +, -, @).
These controls must apply to warnings, logs, filenames, and every export.

## Repository hygiene

Never commit real captures, real hostnames or addresses from traffic,
credentials, or reports derived from real traffic. Synthetic fixtures use
documentation IP ranges or private ranges and explicitly synthetic names and
MAC addresses. A sample's public availability does not grant redistribution
permission. Keep local samples and derived results ignored.

Before staging, inspect git status, git diff --cached, and the actual contents
of every new file. Never use git add -f to bypass capture rules. Renamed capture
files can evade extension-based ignores; review contents as well as names.
Publishing requires a separate review of the full Git history.

# Nineteen phases: study, reproduce, review

The complete code is already present in this checkout; no missing code blocks or
placeholder implementations are required. Work through this guide to understand
and reproduce it. Commands assume the repository root and an activated `.venv`.
Use the existing checkout; do not create a Git worktree unless explicitly wanted.
Commit commands are for you to run after reviewing staged contents. You can also
make one reviewed final commit instead of a phase-by-phase history.

Before each dissector phase, open the named synthetic file in Wireshark via
File > Open, select its packet, expand the protocol, and map highlighted hex bytes
to fields in your notebook. Follow [the byte-layout guide](how_packets_work.md).
A port number alone does not prove which application protocol is present.

## 1. Local environment and safety

Files: README.md, SAFETY.md, .gitignore, scripts/bootstrap.sh, docs/phase1.md.
Read the safety rules first; they define the authorized workflow and privacy limits.

```bash
bash scripts/bootstrap.sh
source .venv/bin/activate
python --version
python -m pip check
code .
git check-ignore samples/example.pcap other/example.PCAPNG
```

Expected: Python >=3.10, no broken requirements, both sample paths ignored. Select
`.venv/bin/python` in VS Code. Generate and inspect the one-SYN primer using the
full command in phase1.md; manually verify 54 captured bytes and raw sequence 1000.

```bash
git add .gitignore .gitattributes README.md SAFETY.md scripts/bootstrap.sh docs/phase1.md requirements.lock pyproject.toml src/pcaplens/__init__.py
git diff --cached --check
git commit -m "chore: establish pcaplens environment and safety contract"
```

## 2. Defensive foundations

Files: formats/reader_base.py, limits.py, models.py, dissect/errors.py,
configs/limits.yaml, tests/test_foundations.py. Read bounds and budgets before any
dissector. A capture's declared length is never trusted as an available length.

```bash
pytest -q tests/test_foundations.py
```

Expected: reader properties, failed-read cursor preservation, warning suppression
and configuration rejection pass. No dissector is needed for these checks.

```bash
git add src/pcaplens/formats/reader_base.py src/pcaplens/limits.py src/pcaplens/models.py src/pcaplens/dissect/errors.py configs/limits.yaml tests/test_foundations.py
git commit -m "feat: add bounded reading budgets and typed diagnostics"
```

## 3. Capture containers

Files: formats/pcap.py, pcapng.py, open.py, tests/test_formats.py,
docs/file_formats.md. Compare the first four bytes of both endian PCAPs and the
PCAPNG section/interface blocks before inspecting Ethernet bytes.

```bash
pytest -q tests/test_formats.py
```

Expected: four classic variants, mixed-resolution interfaces, multiple sections,
PB/SPB, truncated/wrong-endian files, options, and decompression caps pass.

```bash
git add src/pcaplens/formats tests/test_formats.py docs/file_formats.md
git commit -m "feat: stream checked PCAP PCAPNG and bounded gzip inputs"
```

## 4. Reproducible synthetic fixtures

Files: fixtures/generate_fixtures.py, fixtures/ground_truth/expected.json and its
named captures, tests/conftest.py. Scapy builds synthetic packets only; the parser
never delegates to it. Ground truth records generator intent rather than analyzer
output. Regeneration after a commit must produce no fixture diff.

```bash
python fixtures/generate_fixtures.py
python scripts/audit_repository.py
git diff -- fixtures/
```

Expected: stable hashes, 14 packets in the protocol fixture, only documentation
IPs, synthetic MACs/names and intentionally fake test values. Review the generator
and binary provenance before admitting captures to Git.

```bash
git add fixtures tests/conftest.py
git commit -m "test: add deterministic synthetic and malformed capture fixtures"
```

## 5. Link/network layers

Open protocols-le-us.pcap: VLAN packet 9, ARP packet 10, IPv6 packet 11, fragments
12–14. Map Ethernet types, IPv4 IHL/length/fragment offsets, IPv6 next headers and
ICMP fields before reading dissect/ethernet.py, vlan.py, arp.py, ipv4.py, ipv6.py,
icmp.py and registry.py.

```bash
pytest -q tests/test_protocols.py tests/test_adversarial.py
pcaplens hierarchy fixtures/protocols-le-us.pcap
```

Expected: three fragments produce one UDP/DNS datagram; malformed overlaps and
non-atomic IPv6 fragments remain warnings/unsupported behavior. No missing bytes
are invented. Checksums are optional and capture offload can create mismatches.

```bash
git add src/pcaplens/dissect/ethernet.py src/pcaplens/dissect/vlan.py src/pcaplens/dissect/arp.py src/pcaplens/dissect/ipv4.py src/pcaplens/dissect/ipv6.py src/pcaplens/dissect/icmp.py src/pcaplens/dissect/registry.py tests/test_protocols.py docs/how_packets_work.md
git commit -m "feat: dissect bounded link and network headers with IPv4 fragments"
```

## 6. TCP/UDP headers and checksums

Open protocol packets 1–8; map ports, TCP data offset/flags/sequence, and UDP length.
Files: dissect/tcp.py, udp.py; the regression test builds known TCP options.

```bash
pytest -q tests/test_protocols.py tests/test_regressions.py
pcaplens summary fixtures/protocols-le-us.pcap --checksum
```

Expected: six TCP packets, three decoded UDP packets, no synthetic checksum
warnings. IPv4/TCP/UDP use distinct checksum coverage; UDP IPv4 zero is permitted,
while missing IPv6 UDP checksum is warned.

```bash
git add src/pcaplens/dissect/tcp.py src/pcaplens/dissect/udp.py tests/test_regressions.py
git commit -m "feat: parse TCP UDP options and optional checksums"
```

## 7. Flow table

Files: flows/table.py, stats.py, tests/test_flows.py. Canonical endpoints make the
five-tuple bidirectional; timeouts and LRU eviction may split a conversation.

```bash
pytest -q tests/test_flows.py
pcaplens flows fixtures/reassembly.pcap
```

Expected: one eight-packet flow, observed handshake state, direction-specific
frame bytes, and a retransmission estimate of one. Timeout/eviction tests show
bounded tables and released buffers.

```bash
git add src/pcaplens/flows/table.py src/pcaplens/flows/stats.py tests/test_flows.py
git commit -m "feat: track bounded bidirectional conversations and observed TCP state"
```

## 8. TCP reassembly

Open reassembly.pcap and wraparound.pcap. Map raw sequence positions and identify
out-of-order and duplicate bytes before reading flows/reassembly.py. Compare
Wireshark's Follow TCP Stream display with the synthetic known bytes.

```bash
pytest -q tests/test_flows.py
pcaplens follow fixtures/reassembly.pcap
pcaplens follow fixtures/wraparound.pcap
make oracle
```

Expected: hashes match ABCDEFGHIJKLMNO / XYZ and wrapped ABCD internally; no stream
bytes are exported. Tests cover gaps, prepending, caps and first/last/reject policy.
Oracle commands require installed tshark; their full harness lives in eval/.

```bash
git add src/pcaplens/flows/reassembly.py
git commit -m "feat: reconstruct observed TCP runs with explicit overlap policy"
```

## 9. DNS/HTTP/TLS metadata

Open DNS packets 1–2 and 14, HTTP packets 6–7, and tls.pcap. Map DNS pointers,
HTTP CRLF/framing, TLS record/message/vector lengths and extensions. Files:
dissect/dns.py, http.py, tls.py; tests/test_protocols.py and regression tests.

```bash
pytest -q tests/test_protocols.py tests/test_regressions.py
pcaplens dns fixtures/protocols-le-us.pcap
pcaplens http fixtures/protocols-le-us.pcap
pcaplens tls fixtures/tls.pcap
```

Expected: three DNS questions, one documentation A answer, redacted request query,
Authorization and Cookie values, body hashes only, synthetic.test SNI, http/1.1
ALPN and version/cipher metadata. DNS loops and malformed framing are warnings.

```bash
git add src/pcaplens/dissect/dns.py src/pcaplens/dissect/http.py src/pcaplens/dissect/tls.py
git commit -m "feat: extract bounded DNS HTTP and TLS handshake metadata"
```

## 10. Filter language

Files: filter/lexer.py, parser.py, evaluator.py; tests/test_filters_outputs.py.
Recursive descent controls precedence and depth; no eval or generated code exists.

```bash
pytest -q tests/test_filters_outputs.py tests/test_adversarial.py
pcaplens filter fixtures/protocols-le-us.pcap --expression 'tcp and port 80'
pcaplens filter fixtures/protocols-le-us.pcap --expression 'ip.src in 192.0.2.0/24 and not arp'
```

Expected: TCP filter selects six packets. Hostile expressions have clear controlled
errors. Application predicates are packet-signature tests; they can drop TCP
continuations, so use transport/IP filters when stream completeness matters.

```bash
git add src/pcaplens/filter tests/test_filters_outputs.py
git commit -m "feat: add bounded hand-written packet filter language"
```

## 11. Safe analyses and reports

Files: analysis/, output/. Stored counts distinguish captured and original bytes;
privacy protection happens before rendering. Metadata retention is bounded too.

```bash
mkdir -p reports
pcaplens export fixtures/protocols-le-us.pcap --output reports/phase11.json --anonymize
pcaplens export fixtures/protocols-le-us.pcap --format csv --output reports/phase11.csv
pcaplens report fixtures/protocols-le-us.pcap --output reports/phase11.html
pcaplens summary fixtures/protocols-le-us.pcap --timeline-plot reports/phase11.png
pytest -q tests/test_filters_outputs.py tests/test_regressions.py
```

Expected: no credential values/bodies, consistent address pseudonyms, escaped HTML
with no external resources, neutralized CSV prefixes, and a local timeline plot.
Opening the generated report is safe output viewing; do not open captured payloads.

```bash
git add src/pcaplens/analysis src/pcaplens/output
git commit -m "feat: produce bounded privacy-conscious metadata and self-contained reports"
```

## 12. CLI and configuration

Files: cli.py, settings.py, configs/default.yaml. Every subcommand is offline; hashes
and settings explain what was analyzed. Progress is on stderr to preserve JSON.

```bash
pcaplens --help
pcaplens summary fixtures/protocols-le-us.pcap --settings configs/default.yaml --limits configs/limits.yaml --progress
pytest -q tests/test_filters_outputs.py tests/test_regressions.py
```

Expected: documented subcommands and sensible exit status; metadata JSON on stdout,
diagnostics on stderr. Existing output files are not overwritten by analysis CLI.

```bash
git add src/pcaplens/cli.py src/pcaplens/settings.py configs/default.yaml
git commit -m "feat: expose offline pcaplens CLI and validated analysis settings"
```

## 13. tshark oracle agreement

Files: eval/oracle_tshark.py, compare.py, tests/test_oracle.py. Use the installed
tool's help and registry rather than assuming field names or a percentage means
truth. Debian/Ubuntu offline-only reference installation:

```bash
sudo apt-get update
sudo apt-get install -y tshark
tshark --version
tshark -h
tshark -G fields > /tmp/tshark-fields.tsv
make oracle
python eval/oracle_tshark.py fixtures/protocols-le-us.pcap fixtures/reassembly.pcap fixtures/tls.pcap --output results/oracle.json
```

If installation asks about allowing non-root live capture, choose No: it is not
needed for offline analysis. Empty reference fields are unmeasured, not 100%.
Inspect every differences entry and its diagnosed/unexplained status. Public
samples require your own terms check and local download; see evaluation.md.

```bash
git add eval/oracle_tshark.py eval/compare.py tests/test_oracle.py
git commit -m "test: compare offline fields conversations and stream bytes with tshark"
```

## 14. Robustness campaign and resource tests

Files: eval/fuzz.py, tests/test_adversarial.py, docs/limits.md. Mutation testing is
finite empirical evidence, not a proof that all possible inputs are safe.

```bash
pytest -q tests/test_adversarial.py tests/test_formats.py tests/test_flows.py
make fuzz
```

Expected: exactly 10,000 fixed-seed cases with all four mutation families, zero
uncaught exceptions/timeouts, and measured sampled RSS. A nonzero runner exit
means failure; do not read an old results file as evidence for that failed run.

```bash
git add eval/fuzz.py tests/test_adversarial.py docs/limits.md
git commit -m "test: exercise resource limits and seeded hostile capture mutations"
```

## 15. Laptop performance and ablations

File: eval/bench.py. Run this yourself on the i3/8 GB machine; cloud results cannot
substitute for laptop measurements. No GPU or external compute service is needed.

```bash
make bench
```

Expected: performance.csv/json/png, ablations.png, measured sampled RSS and a
function-level cumulative/self-time profile. The dpkt baseline parses fewer layers
and does less work; it is not an equivalent full-analysis speed comparison. Each
setting ablation is labeled with its exact settings; their single measurement is
not a significance test. Preserve local results, never captures, for review.

```bash
git add eval/bench.py
git commit -m "perf: measure throughput RSS profiles and parameter sensitivity"
```

## 16. Optional defensive hypotheses

Files: detect/, eval/detect_eval.py, tests/test_detection.py. Alerts always contain
evidence and uncertainty. Synthetic benign lookalikes expose false positives.

```bash
pytest -q tests/test_detection.py
make detect-eval
pcaplens detect fixtures/protocols-le-us.pcap
```

Expected: case-level synthetic precision/recall/FPR, confusion counts and timing
jitter plots. See evaluation.md for a user-authored lab-label manifest; no lab data
has been supplied here and no real-world detection accuracy is claimed.

```bash
git add src/pcaplens/detect eval/detect_eval.py tests/test_detection.py
git commit -m "feat: evaluate defensive heuristics with evidence and uncertainty"
```

## 17. Packaging and synthetic-only CI

Files: pyproject.toml, requirements.lock, Makefile, .github/workflows/ci.yml.

```bash
make check test wheel
python -m pip check
```

Expected: Ruff formatted/clean, strict mypy on src, passing synthetic tests and a
built wheel. Oracle tests are separately marked. CI runs on Python 3.10/3.12 using
synthetic fixtures only; GitHub must actually run it before claiming CI passed.

```bash
git add pyproject.toml requirements.lock Makefile .github src/pcaplens
# Review before completing the package commit:
git diff --cached --check
git commit -m "build: package pcaplens and validate synthetic inputs in CI"
```

## 18. Documentation and honest evidence

Files: README.md, SAFETY.md, LICENSE, docs/ including synthetic/cloud evidence.

```bash
python scripts/audit_repository.py
```

Expected: no flagged credentials/captures/literals in the admitted working files.
Check reported measurements, scope, all protocol limitations, and the difference
between implementation, empirical validation and unavailable external evidence.

```bash
git add README.md SAFETY.md LICENSE docs scripts/audit_repository.py
git commit -m "docs: document packet layouts reproduction safety and measured limits"
```

## 19. Publication review

Follow [checklist.md](checklist.md). It includes both the existing repository push
and a separate new-repository gh command. No capture analysis proves ownership or
legal permission, and no automated audit proves the absence of all PII.

```bash
make check test
python scripts/audit_repository.py
git status --short --untracked-files=all
git diff --cached --check
git diff --cached
```

Expected: only intended source, docs and reviewed synthetic fixtures admitted to
Git; full history reviewed; every limit indexed to a passing test; known hierarchy
disagreements explained; pending public/lab/laptop evidence identified. Publish
only after that review and then inspect the actual GitHub CI run.

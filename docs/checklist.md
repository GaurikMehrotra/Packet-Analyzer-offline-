# Final review and GitHub publication

Review source and evidence, then run from the checkout:

```bash
source .venv/bin/activate
make check test
make oracle
make fuzz
make wheel
python scripts/audit_repository.py
git status --short --untracked-files=all
git check-ignore samples/local.pcap reports/local.html elsewhere/local.PCAPNG
```

Check that every resource budget in limits.md has a passing test. Confirm the
source import guard excludes Scapy/dpkt, HTML dynamic values are escaped, report
resources are local, terminal controls are removed, CSV prefixes are neutralized,
credentials are redacted, bodies are never exported, and no live/decryption API
exists. Warnings/gaps/limits and heuristic uncertainty must remain visible.

Audit limitations: the script checks known fixture hashes, forbidden runtime
oracle imports, common secret patterns and non-documentation/private IPv4 text
literals. It visits every Git commit and each reachable blob once. This is not a
complete credential/PII scanner: it cannot recognize arbitrary credentials,
hostnames, encoded data, renamed real captures, or every IPv6 literal. Manually
review all admitted files, the generator's provenance, and the complete history.
Dependency/documentation URLs are public references, not captured host identities.

During cloud construction the repository was unborn (zero historical commits).
The working files passed the conservative audit; rerun it after your own commits.
Downloaded samples, local captures and reports stay ignored. Never force-add them.
The MIT license covers this project's source; it does not grant rights to sample
captures or third-party tools.

All evaluation commands must complete successfully. Read their current output,
not an old result from a failed run. Verify fixture-only cloud evidence separately
from these required local checks:

- Your own terms-reviewed public captures: offline reference fields/streams and
  a written diagnosis for every disagreement marked unexplained.
- Your i3/8 GB laptop: measured performance/RSS and parameter ablations.
- If claiming detector quality: authorized lab captures with declared ground truth,
  false positives, threshold sensitivity and timing-jitter results.
- Manual Wireshark byte mapping, and the actual GitHub Actions run after a push.

## One final reviewed commit

If you did not use the phase commits:

```bash
git add .gitignore .gitattributes README.md SAFETY.md LICENSE Makefile pyproject.toml requirements.lock configs src tests fixtures eval docs scripts .github
git diff --cached --check
git diff --cached --stat
git diff --cached
git commit -m "feat: build bounded offline pcaplens analyzer and reproducible evaluation"
python scripts/audit_repository.py
```

Use the existing configured repository (do not create it again):

```bash
git branch -M main
git push -u origin main
```

That command publishes your reviewed commits to the existing origin. Nothing has
been pushed automatically by this project setup. Inspect CI results on GitHub,
and investigate any failure rather than editing tests just to obtain a green run.

If you intentionally want a separate portfolio repository and have GitHub CLI
installed/authenticated, check `gh repo create --help` for your installed version,
then after the reviewed commit:

```bash
gh repo create pcaplens --private --source=. --remote=portfolio --push
```

A distinct remote preserves the existing origin. Start private, review the full
history/evidence, then choose repository visibility yourself. The environment's
Git HTTPS proxy can supply authentication without GH_TOKEN/GITHUB_TOKEN; a CLI
login prompt alone does not prove native Git access is missing. Do not copy
credentials into scripts, chat, or this repository.

"""Conservative publication guard: fixture provenance, source imports, secrets and IPv4 literals."""

import ast
import hashlib
import ipaddress
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPTURES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz", ".cap.gz")
SECRET = re.compile(
    rb"AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
)
IPV4 = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
ALLOWED = [
    ipaddress.ip_network(value)
    for value in (
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    )
]


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *arguments])


def inspect(path: str, data: bytes, hashes: dict[str, str]) -> list[str]:
    issues = []
    if path.lower().endswith(CAPTURES):
        name = path.removeprefix("fixtures/")
        if not path.startswith("fixtures/") or hashes.get(name) != hashlib.sha256(data).hexdigest():
            issues.append(f"Unreviewed capture provenance: {path}")
        return issues
    if SECRET.search(data):
        issues.append(f"Possible credential material: {path}")
    for match in IPV4.finditer(data):
        try:
            address = ipaddress.ip_address(match.group().decode())
        except ValueError:
            continue
        if not any(address in network for network in ALLOWED):
            issues.append(
                f"Non-documentation/private IPv4 literal: {path}; review without publishing values"
            )
            break
    if path.startswith("src/pcaplens/") and path.endswith(".py"):
        for node in ast.walk(ast.parse(data)):
            imports = (
                [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else []
            )
            if any(module.split(".")[0] in {"scapy", "dpkt"} for module in imports):
                issues.append(f"Forbidden runtime oracle import: {path}")
    return issues


def main() -> None:
    hashes = json.loads((ROOT / "fixtures/ground_truth/expected.json").read_text())["hashes"]
    paths = git("ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0")
    issues = []
    for name in filter(None, paths):
        path = ROOT / name
        if path.is_file():
            issues.extend(inspect(name, path.read_bytes(), hashes))
    commits = git("rev-list", "--all").decode().splitlines()
    seen = set()
    for commit in commits:
        for entry in git("ls-tree", "-rz", commit).split(b"\0"):
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            if kind != b"blob" or oid in seen:
                continue
            seen.add(oid)
            issues.extend(inspect(name.decode(), git("cat-file", "blob", oid.decode()), hashes))
    print(
        json.dumps(
            {
                "working_files": len([p for p in paths if p]),
                "history_commits": len(commits),
                "issues": sorted(set(issues)),
                "scope": "Conservative checks, not a complete PII/credential scanner; manual review remains required.",
            },
            indent=2,
        )
    )
    raise SystemExit(1 if issues else 0)


if __name__ == "__main__":
    main()

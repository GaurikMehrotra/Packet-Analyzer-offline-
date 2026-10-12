# Phase 1: local setup and a byte-mapping exercise

Use the existing checkout; each cloud task already has an isolated environment.
Do not create a Git worktree unless explicitly requested. Empty directories
created by bootstrap are local scaffolding; Git stores files, not directories.

## Terminal setup

On Windows, use WSL2 with Ubuntu for the Python terminal workflow. Install
Wireshark on Windows and open the exercise file through the WSL filesystem.
No capture driver or live capture permissions are needed for this project.
Run `wsl --install -d Ubuntu` in an Administrator PowerShell if WSL is absent,
then restart when Windows requests it. Follow Microsoft's current WSL docs
if the command fails. On Ubuntu/WSL:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv git
```

Use your actual checkout location, then run:

```bash
cd /path/to/Packet-Analyzer-offline-
bash scripts/bootstrap.sh
source .venv/bin/activate
python --version
python -m pip --version
code .
```

In VS Code choose Python: Select Interpreter, then .venv/bin/python.
Python must be 3.10 or later. In the completed checkout, bootstrap also installs the tested dependency lock and editable package.

## Create one synthetic SYN for inspection

This command writes a 94-byte classic PCAP to ignored samples/. It does not
capture traffic. The packet has no application payload. Its 54-byte Ethernet
frame omits physical-link padding and FCS, as capture files often do. Run from
the checkout with the virtual environment active:

```bash
python - <<'PY'
from pathlib import Path
import struct

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff

source = bytes([192, 0, 2, 10])
destination = bytes([198, 51, 100, 20])
tcp = struct.pack('!HHIIBBHHH', 12345, 443, 1000, 0, 0x50, 0x02, 64240, 0, 0)
pseudo = source + destination + struct.pack('!BBH', 0, 6, len(tcp))
tcp = tcp[:16] + struct.pack('!H', checksum(pseudo + tcp)) + tcp[18:]
ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 1, 0x4000, 64, 6, 0, source, destination)
ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
ethernet = bytes.fromhex('0200000000020200000000010800')
frame = ethernet + ip + tcp
header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
record = struct.pack('<IIII', 1700000000, 0, len(frame), len(frame))
path = Path('samples/primer.pcap')
path.parent.mkdir(exist_ok=True)
with path.open('xb') as output:
    output.write(header + record + frame)
assert path.stat().st_size == 94
print(path, 'synthetic, one TCP SYN, no payload')
print('Frame hex:', frame.hex(' '))
PY
git check-ignore samples/primer.pcap
```

Exclusive creation prevents overwriting an existing file. To repeat, remove
only this generated file with `rm samples/primer.pcap`, then rerun the command.

## Wireshark: map the bytes by hand

Open samples/primer.pcap with File > Open in Wireshark. Do not start capture.
Select its only packet, expand Ethernet II, IPv4, and TCP, and click each field
to highlight its bytes in the Packet Bytes pane. Display labels may vary with
Wireshark version. Record offsets, raw hex, and decoded values yourself.
Offsets below are relative to the Ethernet frame, not the capture-file start.

| Offset | Bytes | Field and expected value |
| --- | --- | --- |
| 0–5 | 02 00 00 00 00 02 | Destination synthetic MAC |
| 6–11 | 02 00 00 00 00 01 | Source synthetic MAC |
| 12–13 | 08 00 | EtherType: IPv4 |
| 14 | 45 | IPv4 version 4, IHL 5 × 4 = 20 bytes |
| 15 | 00 | DSCP/ECN |
| 16–17 | 00 28 | IPv4 total length 40, excluding Ethernet |
| 18–19 | 00 01 | IPv4 identification |
| 20–21 | 40 00 | Don't Fragment set, offset zero |
| 22 | 40 | TTL 64 |
| 23 | 06 | Protocol TCP |
| 24–25 | 4e 7d | IPv4 header checksum |
| 26–29 | c0 00 02 0a | Source 192.0.2.10 |
| 30–33 | c6 33 64 14 | Destination 198.51.100.20 |
| 34–35 | 30 39 | Source port 12345 |
| 36–37 | 01 bb | Destination port 443 |
| 38–41 | 00 00 03 e8 | Raw TCP sequence number 1000 |
| 42–45 | 00 00 00 00 | Acknowledgment number, ACK flag unset |
| 46 | 50 | TCP data offset 5 × 4 = 20 bytes; reserved bits zero |
| 47 | 02 | SYN flag only |
| 48–49 | fa f0 | Window 64240 |
| 50–51 | 92 c3 | TCP checksum including IP pseudo-header |
| 52–53 | 00 00 | Urgent pointer |

Network headers use big-endian integer encoding: 00 28 is hexadecimal 0x28,
or 40. The PCAP container above uses little-endian fields: the initial magic
bytes are d4 c3 b2 a1. Its global header is 24 bytes; a 16-byte packet record
header follows; the Ethernet frame starts at file offset 40. Recorded and
original frame lengths are both 54. The timestamp uses microseconds.

Classic PCAP has one global link type and repeated packet records. PCAPNG
instead uses typed blocks, sections, interface descriptions, and packet blocks;
interfaces may have different link types and timestamp resolutions. We will
implement both containers in Phase 3, after bounded reading in Phase 2.

Wireshark often displays relative TCP sequence zero for this SYN. Expand the
raw sequence field to verify 1000 rather than mistaking display normalization
for a disagreement. SYN consumes one sequence number, so subsequent data would
start at 1001. Sequence numbers count bytes modulo 2^32. Reassembly later will
place bytes by sequence position, track gaps, and apply an explicit overlap
policy. This single SYN establishes no connection and implies no TLS handshake
or application protocol merely because its destination port is 443.

Expected: one Ethernet/IPv4/TCP packet, SYN set, no TCP payload, 54 captured
bytes. Checksum checking may be disabled by default in Wireshark; disabled is
not a successful validation. Consult the installed version's protocol
preferences before enabling checks.

## Review and commit

```bash
git status --short --untracked-files=all
git add .gitignore README.md SAFETY.md scripts/bootstrap.sh docs/phase1.md
git diff --cached --check
git diff --cached
git commit -m "chore: scaffold pcaplens environment and safety contract"
```

Expected: only the five named text files are staged. Neither .venv/ nor the
synthetic local primer is staged. Do not push until you have reviewed contents.
Stop here and complete the manual byte mapping before Phase 2.

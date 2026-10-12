# Streaming PCAP and PCAPNG

A capture file is a container; Ethernet/IP/TCP are the bytes inside its packet
records. Container endianness and timestamp precision do not change network
header byte order. Never allocate based only on a capture's declared size.

## Classic PCAP

```
24-byte global header:
0  magic 4
4  major 2 | minor 2
8  reserved/timezone 4 | reserved/significant figures 4
16 snaplen 4 | link type / additional flags 4

Repeated 16-byte record header:
0 timestamp seconds 4 | fraction 4
8 captured length 4 | original frame length 4
16 captured frame bytes (no per-record padding)
```

| First four bytes | Container order | Timestamp fraction |
| --- | --- | --- |
| d4 c3 b2 a1 | little | microseconds |
| a1 b2 c3 d4 | big | microseconds |
| 4d 3c b2 a1 | little | nanoseconds |
| a1 b2 3c 4d | big | nanoseconds |

Version 2.4 is supported. The global link type applies to every record; additional
flags are separated from the lower link-type bits. Captured length must fit
snaplen and the configured packet cap; original length must not be smaller.
Fractions must be in range. Original length can exceed captured length when a
snaplen truncates a packet; dissection still bounds every read against captured
bytes. A truncated final record stops with a warning after retaining earlier
complete packets. Bad headers or declared lengths stop safely, not by seeking to
an attacker-controlled offset and guessing the next record.

The one-SYN exercise has 24 + 16 + 54 = 94 bytes. Its Ethernet bytes start at file
offset 40. This convenient offset does not apply to PCAPNG.

## PCAPNG

```
Every block:
block type 4 | total length 4 | body (padded to 4-byte alignment)
                              | duplicate total length 4

Section Header Block body:
byte-order magic 4 | major 2 | minor 2 | section length 8 | options

Interface Description Block body:
link type 2 | reserved 2 | snaplen 4 | options

Enhanced Packet Block body:
interface ID 4 | timestamp high 4 | timestamp low 4
captured length 4 | original length 4 | data | padding | options
```

The invariant Section Header Block type is 0x0a0d0d0a. Its byte-order magic is
0x1a2b3c4d; decode it before the section's length/version fields. Sections may
change byte order. Each new section resets interface numbering. An EPB refers to
an IDB in that section, and each interface can have a different link type,
snaplen, timestamp resolution, and time offset.

Block lengths must be aligned, at least the block's mandatory size, within the
block budget, and match the trailing duplicate. Options use code(2), length(2),
value, and padding; option zero/length zero terminates them. Counts and all reads
are bounded. Unknown block types are skipped within the block-size/count budgets.
Repeated empty sections cannot bypass the overall block-count limit.

`if_tsresol` (option 9) defaults to 10^-6 seconds. With the high bit clear, its
remaining bits give a decimal exponent; with it set, a binary exponent. For
example 0x8a means 2^-10 seconds. Option 14 is a signed seconds offset. Combine the
high/low timestamp words into a 64-bit counter, then convert using integer
arithmetic to nanoseconds. Sub-nanosecond fractions round down, not to spurious
floating precision.

Obsolete Packet Blocks and Simple Packet Blocks are also supported. SPB uses
interface zero and has no timestamp; zero is a sentinel with an explicit warning,
so its time is not presented as trustworthy duration evidence. Unsupported
versions, interface references or malformed options produce controlled warnings.

## Gzip and input identity

Only regular offline files are accepted. File-size, packet-count, block-count,
individual-record and decompressed-size budgets apply. `.gz` inputs use a streaming
gzip reader. The expansion ratio is measured against the whole compressed file's
size, not an instantaneous per-member ratio; concatenated padding cannot evade the
absolute decompressed-size cap. HTTP gzip hashing has its own output/ratio bounds
and rejects incomplete/concatenated encoded bodies.

File SHA-256 is read in bounded chunks without loading the file. An inode/size/
mtime change during analysis invalidates the reported hash and generates a
warning. Analyze stable files; these checks are not a lock against an adversary
modifying a file while restoring its metadata. The hash identifies the entire
input file; limits/filters may make analyzed results a prefix or subset.

Run `pytest tests/test_formats.py tests/test_adversarial.py` to exercise byte
orders, timestamp resolutions, sections, block trailers, missing data, gzip bombs
and section floods. Synthetic PCAPNG fixtures alternate microsecond/nanosecond
interfaces; their timestamp gap must be exactly 100,000,000 ns.

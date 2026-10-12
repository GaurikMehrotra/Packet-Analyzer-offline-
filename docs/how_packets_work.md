# Packet bytes, fields, and sequence space

Start with the one-SYN [manual exercise](phase1.md). Open only an authorized capture
with File > Open in Wireshark. Never start live capture for this project, and never
open extracted objects or execute payloads. Select each field and match its
highlighted bytes with your notebook before studying the corresponding parser.

Network-header integers are big-endian: bytes `01 bb` are hexadecimal 0x01bb = 443.
A bounds check must precede every read. A declared length is a claim, not permission
to allocate or read bytes beyond the capture. `ByteReader.at()` validates negative
lengths/offsets and available bytes; failed reads do not advance its cursor.

## Ethernet and VLAN

```
Ethernet II, 14 bytes before optional tags:
+----------------+----------------+------------+------------------+
| destination 6  | source MAC 6   | type 2     | network payload  |
+----------------+----------------+------------+------------------+
byte 0                            byte 12      byte 14

Each 802.1Q tag adds four bytes:
| TCI 2 (PCP 3 bits, DEI 1, VLAN ID 12) | next EtherType 2 |
```

IPv4 EtherType is 0x0800, IPv6 0x86dd, ARP 0x0806, VLAN 0x8100/0x88a8.
A frame can have multiple VLAN tags, so the stack needs a count cap. Captures
usually omit FCS and may omit physical padding. The analyzer uses network-layer
lengths rather than treating padding/FCS as application bytes. Ethernet 802.3
length/LLC framing is not Ethernet II and is not guessed into an IP packet.

Linux SLL v1 has a 16-byte header ending in a two-byte protocol field. Raw IP has
no link header; its first nibble determines IPv4 or IPv6. Unknown link types must
remain unsupported, not be interpreted as Ethernet by assumption.

## ARP

```
hardware type 2 | protocol type 2 | hardware length 1 | protocol length 1
operation 2 | sender hardware hlen | sender protocol plen
            | target hardware hlen | target protocol plen
```

For Ethernet/IPv4, hlen=6 and plen=4. Requests commonly have operation 1 and replies
2. Check variable address lengths before reading. An IP changing its reported MAC
can reflect legitimate failover or mobility; that evidence alone is not spoofing.

## IPv4, fragments and ICMP

```
offset 0: version/IHL 1 | DSCP/ECN 1 | total length 2
       4: identification 2 | flags/fragment offset 2
       8: TTL 1 | next protocol 1 | header checksum 2
      12: source address 4 | destination address 4
      20: options (if IHL > 5) | payload
```

IHL counts 32-bit words; minimum 5 means 20 bytes. Total length includes the IP
header, not Ethernet. Fragment offsets count units of eight bytes; MF means more
fragments follow. A fragmented datagram is keyed by source, destination, protocol
and identification. Reassembly is allowed only when every range from zero through
the final end is observed. This implementation rejects overlapping fragment
ranges, bounds bytes/sets/pieces, and times out incomplete sets. Capture truncation
is not filled with zero bytes or treated as valid transport data.

ICMP/ICMPv6 begin with type(1), code(1), checksum(2), then type-specific fields.
Echo messages add identifier(2) and sequence(2). Quoted packets/error bodies stay
uninterpreted. IPv4's checksum covers only its header. ICMPv6 and transport
checksums include an IP pseudo-header; optional mismatch checks are warnings.

## IPv6 and extension chains

```
first word 4: version 4 bits | traffic class 8 | flow label 20
payload length 2 | next header 1 | hop limit 1
source address 16 | destination address 16 | extensions / upper-layer bytes
```

The base header is 40 bytes. Payload length excludes it. Hop-by-hop, destination,
routing, fragment and authentication headers can chain via their next-header
fields. Hop/routing/destination lengths count eight-byte units minus one;
authentication length uses four-byte units minus two. Pad1 options consume one
byte; other option TLVs carry a checked length. Bound both chain depth and option
counts. Atomic fragment headers can be skipped; non-atomic IPv6 fragments and
jumbograms are explicitly unsupported in this version.

## TCP and UDP

```
TCP offsets:
0 source port 2 | destination port 2
4 sequence 4 | acknowledgment 4
12 data offset/reserved 1 | flags 1 | window 2
16 checksum 2 | urgent pointer 2 | options | data

UDP:
source port 2 | destination port 2 | datagram length 2 | checksum 2 | data
```

TCP's data offset counts four-byte words and must be at least 5. Options use
kind/length/value TLVs except End and NOP; the count and each length are checked.
The parser extracts MSS, window scale, timestamp and SACK-block metadata.
Flags: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20,
ECE=0x40, CWR=0x80. UDP length includes its eight-byte header.

TCP sequence numbers count bytes modulo 2^32. SYN consumes one sequence number;
FIN also consumes one, but neither is application data. If SYN sequence is 1000,
the first data byte is 1001. An ACK number refers to the next expected sequence
position, not a count of application messages.

`distance(sequence, origin)` takes a signed modular distance in [-2^31, 2^31).
Ordering outside that half-space is ambiguous, so the small stream budget rejects
far offsets. After sequence 0xffffffff comes zero. Segments may arrive out of
order or repeat; the presence map distinguishes unobserved gaps from actual zero
bytes. Only contiguous observed runs are passed to application parsers. A gap is
never joined silently. For overlapping bytes, first/last/reject is configurable;
first is the default. Retransmission counts are overlap estimates, not proof of
network loss. Starting midstream leaves the origin uncertain.

In Wireshark, expand the raw sequence field: relative display zero may represent
raw 1000. For synthetic reassembly, compare Follow TCP Stream in raw mode with the
known fixture bytes; the oracle harness compares these bytes in memory, not by
writing extracted streams to disk.

## DNS, HTTP and TLS

DNS starts with a 12-byte header: ID, flags, and four 16-bit counts (questions,
answers, authority, additional). Names contain length-prefixed labels and a zero
terminator; a two-byte compression pointer has its top bits 11. Following a pointer
changes the name-reading location, not the enclosing record's next field. Track
visited offsets, bound pointer hops, and enforce the 255-byte wire-name limit.
Resource records have name, type(2), class(2), TTL(4), RDATA length(2), RDATA.
TCP DNS additionally prefixes each message with a two-byte message length.

HTTP/1.x starts with an ASCII request or status line, CRLF-delimited headers and
an empty line. Body framing depends on method/status, Content-Length or chunking.
Conflicting framing is rejected rather than guessed. Chunk sizes are hexadecimal;
chunks and trailers have their own caps. Bodies are transient and hashed only;
form fields never enter output. Known HEAD context prevents a response's declared
Content-Length from being mistaken for bytes that HEAD does not carry. Upgrades
end HTTP interpretation. Responses without requests retain context uncertainty.

TLS records have content type(1), legacy version(2), record length(2). A handshake
has message type(1), length(3), and body, possibly split over records/segments.
ClientHello/ServerHello include a legacy version, random, variable session ID,
cipher selection/list and extensions. SNI, ALPN and supported_versions use nested
checked length vectors. Do not infer encryption versions solely from the legacy
record version, and do not imply that metadata parsing decrypts TLS.

Before studying each module, use its synthetic fixture in Wireshark to map the
header bytes. The [phase guide](phases.md) lists exactly which file to open. Parser
results are typed Packet objects with sampled ParseWarning lists; internal helpers
populate the packet and the bounded run-wide diagnostic sink.

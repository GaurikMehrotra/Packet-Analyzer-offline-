"""Deterministic synthetic-only fixtures. Scapy is an oracle/generator, not a parser dependency."""

import hashlib
import json
import struct
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP, Dot1Q, Ether, Raw, fragment
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6ExtHdrHopByHop

ROOT = Path(__file__).resolve().parent
A, B = "192.0.2.10", "198.51.100.20"
MAC_A, MAC_B = "02:00:00:00:00:01", "02:00:00:00:00:02"
EPOCH = 1700000000


def ethernet(packet):
    return Ether(src=MAC_A, dst=MAC_B) / packet


def pcap(frames: list[bytes], *, endian: str = "<", nano: bool = False, link: int = 1) -> bytes:
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    output = bytearray(struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 262144, link))
    for index, frame in enumerate(frames):
        seconds, remainder = divmod(index * 100_000_000, 1_000_000_000)
        output.extend(
            struct.pack(
                endian + "IIII",
                EPOCH + seconds,
                remainder if nano else remainder // 1000,
                len(frame),
                len(frame),
            )
        )
        output.extend(frame)
    return bytes(output)


def block(kind: int, body: bytes, endian: str) -> bytes:
    body += b"\0" * ((-len(body)) % 4)
    size = 12 + len(body)
    return struct.pack(endian + "II", kind, size) + body + struct.pack(endian + "I", size)


def pcapng(frames: list[bytes], endian: str = "<") -> bytes:
    output = bytearray(
        block(0x0A0D0D0A, struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1), endian)
    )
    for exponent in (6, 9):
        option = struct.pack(endian + "HH", 9, 1) + bytes([exponent]) + b"\0" * 3 + b"\0" * 4
        output.extend(block(1, struct.pack(endian + "HHI", 1, 0, 262144) + option, endian))
    for index, frame in enumerate(frames):
        interface = index % 2
        timestamp = EPOCH * (10 ** (6 if interface == 0 else 9)) + index * (
            100000 if interface == 0 else 100000000
        )
        body = struct.pack(
            endian + "IIIII",
            interface,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(frame),
            len(frame),
        )
        output.extend(block(6, body + frame + b"\0" * ((-len(frame)) % 4), endian))
    return bytes(output)


def tcp(
    sequence: int,
    payload: bytes = b"",
    *,
    reverse: bool = False,
    flags: str = "PA",
    ack: int = 501,
    port: int = 80,
) -> bytes:
    src, dst, sport, dport = (B, A, port, 12345) if reverse else (A, B, 12345, port)
    return bytes(
        ethernet(
            IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, seq=sequence, ack=ack, flags=flags)
            / Raw(payload)
        )
    )


def client_hello() -> bytes:
    name = b"synthetic.test"
    server_name = struct.pack("!H", len(name) + 3) + b"\0" + struct.pack("!H", len(name)) + name
    alpn = b"\0\x09\x08http/1.1"
    versions = b"\x04\x03\x04\x03\x03"
    extensions = b"".join(
        struct.pack("!HH", kind, len(value)) + value
        for kind, value in ((0, server_name), (16, alpn), (43, versions))
    )
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\0\0\x04\x13\x01\xc0\x2f\x01\0"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    message = b"\x01" + len(body).to_bytes(3, "big") + body
    # A handshake fragmented across two TLS records, then TCP segments.
    return b"".join(
        b"\x16\x03\x03" + struct.pack("!H", len(part)) + part
        for part in (message[:23], message[23:])
    )


def generate() -> dict[str, object]:
    ROOT.mkdir(exist_ok=True)
    (ROOT / "ground_truth").mkdir(exist_ok=True)
    query = bytes(
        ethernet(
            IP(src=A, dst=B)
            / UDP(sport=53000, dport=53)
            / DNS(id=123, qd=DNSQR(qname="synthetic.test"))
        )
    )
    answer = bytes(
        ethernet(
            IP(src=B, dst=A)
            / UDP(sport=53, dport=53000)
            / DNS(
                id=123,
                qr=1,
                qd=DNSQR(qname="synthetic.test"),
                an=DNSRR(rrname="synthetic.test", type="A", rdata="203.0.113.7", ttl=60),
            )
        )
    )
    request = b"GET /demo?token=synthetic-only HTTP/1.1\r\nHost: synthetic.test\r\nAuthorization: Bearer synthetic-only\r\nCookie: synthetic=only\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    http = [
        tcp(100, flags="S", ack=0),
        tcp(500, reverse=True, flags="SA", ack=101),
        tcp(101, flags="A"),
        tcp(101, request),
        tcp(501, response, reverse=True, ack=101 + len(request)),
        tcp(101 + len(request), flags="FA", ack=501 + len(response)),
    ]
    layer = [
        bytes(Ether(src=MAC_A, dst=MAC_B) / Dot1Q(vlan=7) / IP(src=A, dst=B) / ICMP()),
        bytes(ethernet(ARP(hwsrc=MAC_A, hwdst=MAC_B, psrc=A, pdst=B))),
        bytes(
            ethernet(
                IPv6(src="2001:db8::10", dst="2001:db8::20")
                / IPv6ExtHdrHopByHop()
                / ICMPv6EchoRequest()
            )
        ),
    ]
    fragmented = [
        bytes(ethernet(p))
        for p in fragment(
            IP(src=A, dst=B, id=23)
            / UDP(sport=53001, dport=53)
            / DNS(id=124, qd=DNSQR(qname="fragment.test")),
            fragsize=16,
        )
    ]
    protocols = [query, answer, *http, *layer, *fragmented]
    fixtures: dict[str, bytes] = {}
    for endian, label in (("<", "le"), (">", "be")):
        for nano in (False, True):
            fixtures[f"protocols-{label}-{'ns' if nano else 'us'}.pcap"] = pcap(
                protocols, endian=endian, nano=nano
            )
        fixtures[f"interfaces-{label}.pcapng"] = pcapng([query, answer], endian)
    stream = [
        tcp(100, flags="S", ack=0),
        tcp(500, reverse=True, flags="SA", ack=101),
        tcp(101, flags="A"),
        tcp(101, b"ABCDE"),
        tcp(111, b"KLMNO"),
        tcp(106, b"FGHIJ"),
        tcp(106, b"FGHIJ"),
        tcp(501, b"XYZ", reverse=True, ack=116),
    ]
    fixtures["reassembly.pcap"] = pcap(stream)
    fixtures["wraparound.pcap"] = pcap(
        [tcp(0xFFFFFFFD, flags="S", ack=0), tcp(0xFFFFFFFE, b"AB"), tcp(0, b"CD")]
    )
    hello = client_hello()
    server_body = b"\x03\x03" + b"\x22" * 32 + b"\0\x13\x01\0\0\x06\0\x2b\0\x02\x03\x04"
    server = b"\x02" + len(server_body).to_bytes(3, "big") + server_body
    server = b"\x16\x03\x03" + struct.pack("!H", len(server)) + server
    fixtures["tls.pcap"] = pcap(
        [
            tcp(100, flags="S", ack=0, port=443),
            tcp(101, hello[:17], port=443),
            tcp(118, hello[17:], port=443),
            tcp(501, server, reverse=True, port=443),
        ]
    )
    fixtures["raw-ip.pcap"] = pcap([bytes(IP(src=A, dst=B) / ICMP())], link=101)
    sll = struct.pack("!HHH8sH", 0, 1, 6, bytes.fromhex("0200000000010000"), 0x800)
    fixtures["sll.pcap"] = pcap([sll + bytes(IP(src=A, dst=B) / ICMP())], link=113)
    fixtures["unsupported.pcap"] = pcap([b"synthetic"], link=999)
    fixtures["truncated.pcap"] = pcap([query])[:-7]
    fixtures["huge-length.pcap"] = pcap([]) + struct.pack("<IIII", EPOCH, 0, 0xFFFFFFFF, 0xFFFFFFFF)
    loop = struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c\0\x01\0\x01"
    fixtures["dns-loop.pcap"] = pcap(
        [bytes(ethernet(IP(src=A, dst=B) / UDP(sport=53000, dport=53) / Raw(loop)))]
    )
    fixtures["wrong-endian.pcap"] = bytes.fromhex("a1b2c3d4") + pcap([query])[4:]
    fixtures["block-mismatch.pcapng"] = pcapng([query])[:-4] + b"\0" * 4
    for name, content in fixtures.items():
        (ROOT / name).write_bytes(content)
    truth = {
        "synthetic": True,
        "seed": 0,
        "protocols_packets": len(protocols),
        "dns_questions": ["synthetic.test", "synthetic.test", "fragment.test"],
        "http_requests": [{"method": "GET", "url": "/demo?token=synthetic-only"}],
        "reassembly": {"a_to_b_hex": b"ABCDEFGHIJKLMNO".hex(), "b_to_a_hex": b"XYZ".hex()},
        "wraparound_hex": b"ABCD".hex(),
        "tls_sni": "synthetic.test",
        "hashes": {
            name: hashlib.sha256(data).hexdigest() for name, data in sorted(fixtures.items())
        },
    }
    (ROOT / "ground_truth" / "expected.json").write_text(
        json.dumps(truth, indent=2, sort_keys=True) + "\n"
    )
    return truth


if __name__ == "__main__":
    print(json.dumps(generate(), indent=2, sort_keys=True))

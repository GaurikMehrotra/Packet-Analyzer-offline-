"""TLS records and fragmented ClientHello/ServerHello metadata; no decryption."""

from typing import Any

from pcaplens.dissect.errors import ParseError
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits


def vector(reader: ByteReader, width: int) -> ByteReader:
    return ByteReader(reader.take(int.from_bytes(reader.take(width), "big")))


def hello(data: bytes, kind: int, limits: Limits) -> dict[str, Any]:
    reader = ByteReader(data)
    version = reader.u16()
    reader.take(32)
    session = vector(reader, 1)
    if session.remaining > 32:
        raise ParseError("tls_session", "TLS session ID exceeds protocol maximum")
    result: dict[str, Any] = {
        "hello": "client" if kind == 1 else "server",
        "legacy_version": version,
    }
    if kind == 1:
        ciphers = vector(reader, 2)
        if (
            not ciphers.remaining
            or ciphers.remaining % 2
            or ciphers.remaining // 2 > limits.max_options
        ):
            raise ParseError("option_limit", "Invalid or excessive TLS cipher list")
        result["cipher_suites"] = [ciphers.u16() for _ in range(ciphers.remaining // 2)]
        compression = vector(reader, 1)
        if not compression.remaining:
            raise ParseError("tls_compression", "Empty TLS compression list")
    else:
        result["cipher_suites"] = [reader.u16()]
        reader.u8()
    if not reader.remaining:
        return result
    extensions = vector(reader, 2)
    if reader.remaining:
        raise ParseError("tls_length", "Trailing bytes outside TLS extensions")
    count = 0
    seen: set[int] = set()
    while extensions.remaining:
        count += 1
        if count > limits.max_options:
            raise ParseError("option_limit", "TLS extension count exceeds cap")
        code = extensions.u16()
        if code in seen:
            raise ParseError("tls_extension", "Duplicate TLS extension")
        seen.add(code)
        value = vector(extensions, 2)
        if code == 0 and kind == 1:
            names = vector(value, 2)
            entries: list[str] = []
            while names.remaining:
                if len(entries) >= limits.max_options:
                    raise ParseError("option_limit", "Too many TLS SNI entries")
                name_type = names.u8()
                label = vector(names, 2)
                if name_type == 0:
                    entries.append(label.take(label.remaining).decode("ascii", errors="replace"))
            result["sni"] = entries
        elif code == 16:
            protocols = vector(value, 2)
            entries = []
            while protocols.remaining:
                if len(entries) >= limits.max_options:
                    raise ParseError("option_limit", "Too many ALPN entries")
                label = vector(protocols, 1)
                entries.append(label.take(label.remaining).decode("ascii", errors="replace"))
            result["alpn"] = entries
        elif code == 43:
            versions = vector(value, 1) if kind == 1 else value
            if versions.remaining % 2 or versions.remaining // 2 > limits.max_options:
                raise ParseError("tls_version", "Invalid supported versions list")
            result["versions"] = [versions.u16() for _ in range(versions.remaining // 2)]
        if code in (0, 16, 43) and (code != 0 or kind == 1) and value.remaining:
            raise ParseError("tls_extension", "Trailing bytes in parsed TLS extension")
    return result


def parse(data: bytes, limits: Limits) -> list[dict[str, Any]]:
    reader = ByteReader(data)
    handshakes = bytearray()
    result: list[dict[str, Any]] = []
    count = 0
    while reader.remaining:
        count += 1
        if count > limits.max_headers:
            raise ParseError("header_limit", "Too many TLS records")
        kind, version, length = reader.unpack("!BHH")
        if version >> 8 != 3 or length > 18432:
            raise ParseError("tls_record", "Invalid TLS record header")
        body = reader.take(length)
        if kind != 22:
            continue
        if len(handshakes) + len(body) > limits.max_tls_handshake:
            raise ParseError("tls_handshake_limit", "TLS handshake buffer exceeds cap")
        handshakes.extend(body)
        while len(handshakes) >= 4:
            message = ByteReader(bytes(handshakes))
            hello_kind, size = message.u8(), int.from_bytes(message.take(3), "big")
            if size > limits.max_tls_handshake:
                raise ParseError("tls_handshake_limit", "Declared TLS handshake exceeds cap")
            if message.remaining < size:
                break
            value = message.take(size)
            del handshakes[: size + 4]
            if hello_kind in (1, 2):
                result.append(hello(value, hello_kind, limits))
                if len(result) >= limits.max_metadata:
                    raise ParseError("metadata_limit", "TLS metadata cap reached")
    if handshakes:
        raise ParseError("tls_incomplete", "Incomplete fragmented TLS handshake")
    return result

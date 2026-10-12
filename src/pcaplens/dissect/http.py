"""HTTP/1.x framing and hashes only. Bodies never enter result objects."""

import hashlib
import zlib
from typing import Any

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.reader_base import ByteReader
from pcaplens.limits import Limits

METHODS = (
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)


def body_hash(body: bytes, encoding: str, limits: Limits) -> dict[str, Any]:
    result: dict[str, Any] = {
        "encoded_length": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }
    if encoding not in ("gzip", "deflate"):
        return result
    cap = min(limits.max_decompressed_bytes, max(1, len(body)) * limits.max_decompression_ratio)
    decoder = zlib.decompressobj(31 if encoding == "gzip" else 15)
    try:
        expanded = decoder.decompress(body, cap + 1)
        if len(expanded) > cap or decoder.unconsumed_tail:
            raise ParseError("decompression_limit", "HTTP body expansion cap exceeded")
        if not decoder.eof or decoder.unused_data:
            raise ParseError("http_encoding", "Incomplete or concatenated encoded HTTP body")
    except zlib.error as error:
        raise ParseError("http_encoding", "Invalid compressed HTTP body") from error
    result.update(
        {"decoded_length": len(expanded), "decoded_sha256": hashlib.sha256(expanded).hexdigest()}
    )
    return result


def parse(
    data: bytes, limits: Limits, warnings: WarningLog, response_methods: list[str] | None = None
) -> list[dict[str, Any]]:
    reader = ByteReader(data)
    result: list[dict[str, Any]] = []
    response_index = 0
    while reader.remaining and len(result) < limits.max_metadata:
        tail = reader.at(reader.position, reader.remaining)
        if not tail.startswith(METHODS + (b"HTTP/1.",)):
            break
        boundary = tail.find(b"\r\n\r\n", 0, limits.max_http_header + 1)
        if boundary < 0 or boundary + 4 > limits.max_http_header:
            warnings.record("http_header_limit", "HTTP headers incomplete or exceed cap")
            break
        lines = reader.take(boundary + 4)[:-4].split(b"\r\n")
        if len(lines) - 1 > limits.max_headers:
            raise ParseError("header_limit", "HTTP header count exceeds budget")
        start = ByteReader(lines[0]).take(len(lines[0])).decode("latin1")
        tokens = start.split(" ", 2)
        response = start.startswith("HTTP/")
        if (
            len(tokens) != 3
            or (response and tokens[0] not in ("HTTP/1.0", "HTTP/1.1"))
            or (not response and tokens[2] not in ("HTTP/1.0", "HTTP/1.1"))
        ):
            raise ParseError("http_line", "Invalid HTTP start line")
        headers: dict[str, str] = {}
        lengths: list[int] = []
        for line in lines[1:]:
            if b":" not in line or line[:1] in (b" ", b"\t"):
                raise ParseError("http_header", "Malformed or folded HTTP header")
            key, value = line.split(b":", 1)
            label = key.decode("ascii", errors="replace").lower()
            if not label or any(
                not (c.isascii() and (c.isalnum() or c in "!#$%&'*+-.^_`|~")) for c in label
            ):
                raise ParseError("http_header", "Invalid header name")
            text = value.strip().decode("latin1")
            if label == "content-length":
                if not text.isascii() or not text.isdecimal() or len(text) > 12:
                    raise ParseError("http_length", "Invalid HTTP Content-Length")
                lengths.append(int(text))
            headers[label] = headers[label] + ", " + text if label in headers else text
        if lengths and len(set(lengths)) != 1:
            raise ParseError("http_ambiguity", "Conflicting HTTP Content-Length values")
        status = 0
        if response:
            if not tokens[1].isascii() or not tokens[1].isdecimal() or len(tokens[1]) != 3:
                raise ParseError("http_status", "Invalid HTTP response status")
            status = int(tokens[1])
        metadata: dict[str, Any] = {"response": response, "headers": headers}
        metadata.update(
            {"status": status, "version": tokens[0]}
            if response
            else {"method": tokens[0], "url": tokens[1], "version": tokens[2]}
        )
        body = b""
        transfer = headers.get("transfer-encoding", "").lower()
        request_method = (
            response_methods[response_index]
            if response_methods is not None and response_index < len(response_methods)
            else None
        )
        no_body = response and (
            100 <= status < 200 or status in (204, 304) or request_method == "HEAD"
        )
        upgraded = response and (
            status == 101 or request_method == "CONNECT" and 200 <= status < 300
        )
        no_body |= upgraded
        if response:
            if status >= 200 or status == 101:
                response_index += 1
            metadata["request_method_context"] = request_method or "unknown"
        if transfer and lengths:
            raise ParseError("http_ambiguity", "Transfer-Encoding and Content-Length coexist")
        if no_body:
            pass
        elif transfer:
            if transfer != "chunked":
                raise ParseError("http_transfer", "Unsupported transfer encoding")
            pieces: list[bytes] = []
            total = 0
            for _ in range(limits.max_options):
                tail = reader.at(reader.position, reader.remaining)
                end = tail.find(b"\r\n", 0, limits.max_http_header)
                if end < 0:
                    raise ParseError("http_chunk", "Incomplete chunk size")
                raw_size = reader.take(end).split(b";", 1)[0]
                reader.take(2)
                if (
                    not raw_size
                    or len(raw_size) > 8
                    or any(c not in b"0123456789abcdefABCDEF" for c in raw_size)
                ):
                    raise ParseError("http_chunk", "Invalid chunk size")
                size = int(raw_size, 16)
                if size == 0:
                    # Trailers are bounded and deliberately not retained.
                    trailer_size = 0
                    for _ in range(limits.max_headers):
                        tail = reader.at(reader.position, reader.remaining)
                        end = tail.find(b"\r\n", 0, limits.max_http_header)
                        if end < 0:
                            raise ParseError("http_trailer", "Incomplete chunk trailer")
                        trailer_size += end + 2
                        if trailer_size > limits.max_http_header:
                            raise ParseError("http_header_limit", "HTTP trailers exceed cap")
                        reader.take(end + 2)
                        if end == 0:
                            break
                    else:
                        raise ParseError("header_limit", "HTTP trailer count exceeds cap")
                    body = b"".join(pieces)
                    break
                total += size
                if total > limits.max_stream_bytes:
                    raise ParseError("http_body_limit", "Chunked body exceeds stream budget")
                pieces.append(reader.take(size))
                if reader.take(2) != b"\r\n":
                    raise ParseError("http_chunk", "Missing chunk delimiter")
            else:
                raise ParseError("option_limit", "HTTP chunk count exceeds budget")
        elif lengths:
            body = reader.take(lengths[0])
        elif response:
            body = reader.take(reader.remaining)
            metadata["body_framing"] = "close-delimited; capture closure not proven"
        metadata["body"] = body_hash(body, headers.get("content-encoding", "").lower(), limits)
        result.append(metadata)
        if upgraded:
            metadata["upgraded_protocol_not_parsed"] = True
            break
    return result

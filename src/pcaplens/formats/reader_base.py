"""The only byte-access abstraction used by capture and protocol parsers."""

import struct
from typing import BinaryIO, Any

from pcaplens.dissect.errors import ParseError


class ByteReader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.position

    def at(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset > len(self.data) - size:
            raise ParseError("truncated", "Read outside available bytes", offset)
        return self.data[offset : offset + size]

    def take(self, size: int) -> bytes:
        value = self.at(self.position, size)
        self.position += size
        return value

    def unpack(self, layout: str) -> tuple[Any, ...]:
        return struct.unpack(layout, self.take(struct.calcsize(layout)))

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")


class StreamReader:
    def __init__(self, source: BinaryIO, maximum: int) -> None:
        self.source = source
        self.maximum = maximum
        self.position = 0

    def take(self, size: int, eof: bool = False) -> bytes:
        if size < 0 or size > self.maximum:
            raise ParseError("read_limit", "Capture read budget exceeded", self.position)
        chunks = bytearray()
        while len(chunks) < size:
            piece = self.source.read(size - len(chunks))
            if not piece:
                break
            chunks.extend(piece)
        self.position += len(chunks)
        if not chunks and eof:
            return b""
        if len(chunks) != size:
            raise ParseError("truncated", "Truncated capture record", self.position)
        return bytes(chunks)

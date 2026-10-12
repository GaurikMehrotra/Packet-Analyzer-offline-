"""Offline opening, content hashing, and bounded gzip decompression."""

import gzip
import hashlib
import zlib
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats import pcap, pcapng
from pcaplens.formats.reader_base import StreamReader
from pcaplens.limits import Limits
from pcaplens.models import CapturePacket


class LimitedGzip:
    def __init__(self, source: BinaryIO, limits: Limits, compressed_size: int) -> None:
        self.source = gzip.GzipFile(fileobj=source)
        self.cap = min(
            limits.max_decompressed_bytes, max(1, compressed_size) * limits.max_decompression_ratio
        )
        self.used = 0

    def read(self, size: int) -> bytes:
        # Read one sentinel byte over the cap, never allocate the declared bomb size.
        data = self.source.read(min(size, max(0, self.cap - self.used) + 1))
        self.used += len(data)
        if self.used > self.cap:
            raise ParseError("decompression_limit", "Gzip size or whole-file ratio cap exceeded")
        return data

    def close(self) -> None:
        self.source.close()


def file_hash(path: Path, maximum: int = 134217728) -> str:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
        raise ParseError(
            "capture_size_limit", "Hashing requires a regular file within input budget"
        )
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(65536):
            total += len(chunk)
            if total > maximum:
                raise ParseError("capture_size_limit", "File grew beyond hashing budget")
            digest.update(chunk)
    return digest.hexdigest()


def packets(path: Path, limits: Limits, warnings: WarningLog) -> Iterator[CapturePacket]:
    try:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limits.max_capture_bytes:
            raise ParseError(
                "capture_size_limit", "Input must be a regular file within capture size cap"
            )
        with path.open("rb") as raw:
            compressed = path.suffix.lower() == ".gz"
            source = LimitedGzip(raw, limits, path.stat().st_size) if compressed else raw
            try:
                reader = StreamReader(source, limits.max_block_length)  # type: ignore[arg-type]
                magic = reader.take(4)
                if magic in pcap.MAGIC:
                    yield from pcap.read(reader, magic, limits, warnings)
                elif magic == pcapng.SHB:
                    yield from pcapng.read(reader, magic, limits, warnings)
                else:
                    raise ParseError("format", "Unknown capture format")
            finally:
                if compressed:
                    source.close()
    except ParseError as error:
        warnings.add(error.warning)
    except (OSError, EOFError, zlib.error) as error:
        warnings.record("capture_io", f"Capture read failed: {type(error).__name__}")

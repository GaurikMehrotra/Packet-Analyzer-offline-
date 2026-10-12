import io
import struct

import pytest
from hypothesis import given, settings, strategies as st
from pydantic import ValidationError

from pcaplens.dissect.errors import ParseError, WarningLog
from pcaplens.formats.reader_base import ByteReader, StreamReader
from pcaplens.limits import Limits


@given(st.binary(max_size=1024), st.integers(-10, 1100), st.integers(-10, 1100))
@settings(max_examples=300, derandomize=True)
def test_bounds(data, offset, size):
    reader = ByteReader(data)
    if offset >= 0 and size >= 0 and offset <= len(data) - size:
        assert reader.at(offset, size) == data[offset : offset + size]
    else:
        with pytest.raises(ParseError):
            reader.at(offset, size)
    assert reader.position == 0


def test_cursor_transaction():
    reader = ByteReader(b"\0\x02")
    with pytest.raises(ParseError):
        reader.take(3)
    assert reader.position == 0
    assert reader.u16() == 2
    assert reader.remaining == 0


def test_stream_limits_and_truncation():
    stream = StreamReader(io.BytesIO(b"ab"), 2)
    with pytest.raises(ParseError, match="budget"):
        stream.take(3)
    with pytest.raises(ParseError, match="Truncated"):
        StreamReader(io.BytesIO(b"a"), 2).take(2)
    assert StreamReader(io.BytesIO(b""), 2).take(1, eof=True) == b""


def test_unpack_and_warning_budget():
    assert ByteReader(struct.pack("!HI", 5, 1000)).unpack("!HI") == (5, 1000)
    warnings = WarningLog(1)
    for _ in range(10):
        warnings.record("test", "bounded")
    assert len(warnings.items) == 1
    assert warnings.export()["suppressed"] == 9


@pytest.mark.parametrize(
    "values",
    [
        {"max_packets": 0},
        {"max_packets": -1},
        {"max_packets": True},
        {"max_packets": "5"},
        {"unknown": 5},
    ],
)
def test_config_rejects_invalid(values):
    with pytest.raises(ValidationError):
        Limits(**values)


def test_config_defaults_match_file(fixtures):
    assert Limits.load(fixtures.parent / "configs/limits.yaml") == Limits()

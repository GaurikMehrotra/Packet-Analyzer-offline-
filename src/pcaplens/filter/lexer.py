"""Linear hand-written tokenization, without eval or generated code."""

from dataclasses import dataclass

from pcaplens.limits import Limits


class FilterError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    value: str
    position: int


def lex(text: str, limits: Limits) -> list[Token]:
    if len(text) > limits.max_filter_tokens * 128:
        raise FilterError("Filter exceeds character budget")
    tokens: list[Token] = []
    position = 0
    while position < len(text):
        start = position
        char = text[position]
        if char.isspace():
            position += 1
            continue
        if char in "()":
            position += 1
        elif char in "=!<>":
            position += 1
            if position < len(text) and text[position] == "=":
                position += 1
            if text[start:position] in ("=", "!"):
                raise FilterError(f"Invalid operator at character {start}")
        elif char.isascii() and (char.isalnum() or char in "_.:/-"):
            while (
                position < len(text)
                and text[position].isascii()
                and (text[position].isalnum() or text[position] in "_.:/-")
            ):
                position += 1
        else:
            raise FilterError(f"Unexpected character at {start}")
        if position - start > 128:
            raise FilterError(f"Token too long at character {start}")
        tokens.append(Token(text[start:position], start))
        if len(tokens) > limits.max_filter_tokens:
            raise FilterError("Filter token budget exceeded")
    return tokens

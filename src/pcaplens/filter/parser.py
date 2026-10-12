"""Recursive descent: or < and < not < comparison/parentheses."""

import ipaddress
from dataclasses import dataclass
from typing import Any

from pcaplens.filter.lexer import FilterError, Token, lex
from pcaplens.limits import Limits

PROTOCOLS = {
    "ip",
    "ipv4",
    "ipv6",
    "tcp",
    "udp",
    "dns",
    "http",
    "tls",
    "arp",
    "icmp",
    "icmpv6",
    "ethernet",
    "vlan",
}
FIELDS = {"ip.src", "ip.dst", "port", "tcp.port", "udp.port", "tcp.flags", "length"}
OPERATORS = {"==", "!=", "<", "<=", ">", ">=", "in"}


@dataclass(frozen=True)
class Node:
    kind: str
    value: Any = None
    children: tuple["Node", ...] = ()


class Parser:
    def __init__(self, tokens: list[Token], limits: Limits) -> None:
        self.tokens, self.limits, self.position = tokens, limits, 0

    def peek(self) -> str:
        return self.tokens[self.position].value if self.position < len(self.tokens) else ""

    def take(self) -> str:
        value = self.peek()
        if not value:
            raise FilterError("Unexpected end of filter")
        self.position += 1
        return value

    def expression(self, level: int = 0, depth: int = 0) -> Node:
        if depth >= min(self.limits.max_filter_depth, 64):
            raise FilterError("Filter nesting budget exceeded")
        if level < 2:
            operator = ("or", "and")[level]
            values = [self.expression(level + 1, depth)]
            while self.peek() == operator:
                self.take()
                values.append(self.expression(level + 1, depth))
            return values[0] if len(values) == 1 else Node(operator, children=tuple(values))
        if self.peek() == "not":
            self.take()
            return Node("not", children=(self.expression(2, depth + 1),))
        if self.peek() == "(":
            self.take()
            node = self.expression(0, depth + 1)
            if self.take() != ")":
                raise FilterError("Expected closing parenthesis")
            return node
        field = self.take()
        if field in PROTOCOLS:
            return Node("protocol", field)
        if field not in FIELDS:
            raise FilterError(f"Unknown field: {field}")
        operator = "==" if field == "port" and self.peek() not in OPERATORS else self.take()
        if operator not in OPERATORS:
            raise FilterError("Expected comparison operator")
        literal = self.take()
        try:
            if field in ("ip.src", "ip.dst"):
                value: Any = (
                    ipaddress.ip_network(literal, strict=False)
                    if operator == "in"
                    else ipaddress.ip_address(literal)
                )
                if operator not in ("==", "!=", "in"):
                    raise FilterError("IP addresses support ==, !=, and in")
            else:
                if operator == "in" or not literal.isascii() or not literal.isdecimal():
                    raise FilterError("Numeric fields require a nonnegative integer")
                value = int(literal)
        except ValueError as error:
            raise FilterError("Invalid comparison literal") from error
        return Node("compare", (field, operator, value))


def parse(text: str, limits: Limits | None = None) -> Node:
    limits = limits or Limits()
    parser = Parser(lex(text, limits), limits)
    node = parser.expression()
    if parser.peek():
        raise FilterError(
            f"Unexpected token at character {parser.tokens[parser.position].position}"
        )
    return node

"""Evaluate typed filter nodes against packet metadata."""

import ipaddress
from typing import Any

from pcaplens.filter.parser import Node
from pcaplens.models import Packet


def compare(left: Any, operator: str, right: Any) -> bool:
    if operator == "==":
        return bool(left == right)
    if operator == "!=":
        return bool(left != right)
    if operator == "in":
        return bool(left in right)
    if operator == "<":
        return bool(left < right)
    if operator == "<=":
        return bool(left <= right)
    if operator == ">":
        return bool(left > right)
    return bool(left >= right)


def evaluate(node: Node, packet: Packet) -> bool:
    if node.kind == "or":
        return any(evaluate(child, packet) for child in node.children)
    if node.kind == "and":
        return all(evaluate(child, packet) for child in node.children)
    if node.kind == "not":
        return not evaluate(node.children[0], packet)
    if node.kind == "protocol":
        return (
            bool({"ipv4", "ipv6"} & set(packet.protocols))
            if node.value == "ip"
            else node.value in packet.protocols
        )
    field, operator, expected = node.value
    if field in ("tcp.port", "udp.port", "tcp.flags") and field.split(".")[0] != packet.transport:
        return False
    if field == "port" and not packet.transport:
        return False
    value = packet.fields().get(field)
    if field in ("ip.src", "ip.dst"):
        if not value:
            return False
        value = ipaddress.ip_address(value)
        if operator == "in" and value.version != expected.version:
            return False
    if isinstance(value, tuple):
        # != means neither endpoint equals the port.
        return (
            all(compare(item, operator, expected) for item in value)
            if operator == "!="
            else any(compare(item, operator, expected) for item in value)
        )
    return compare(value, operator, expected)

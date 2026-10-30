# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Access list entries: reading the Cisco-style token form, and the pieces every writer needs.

IOS, EOS, AOS-S and AOS-CX all write an entry as
``[seq] permit|deny PROTOCOL SOURCE [PORTS] DESTINATION [PORTS] [flags]``; they differ
in how an address looks (``any``, ``host A``, ``A WILDCARD``, ``A/len``, ``A/MASK``)
and in the names of ports and ICMP types. Comware has its own form and its own
reader, but shares the port and address helpers.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from .confparse import Node
from .model import Acl, AclAction, AclEntry

if TYPE_CHECKING:
    from .report import Report

PORT_NAMES: Dict[str, int] = {
    "ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "dns": 53, "bootps": 67,
    "bootpc": 68, "tftp": 69, "www": 80, "http": 80, "pop3": 110, "sunrpc": 111, "ntp": 123, "netbios-ns": 137,
    "netbios-dgm": 138, "netbios-ss": 139, "imap": 143, "imap4": 143, "snmp": 161, "snmptrap": 162,
    "snmp-trap": 162, "bgp": 179, "ldap": 389, "https": 443, "isakmp": 500, "syslog": 514, "rip": 520,
    "non500-isakmp": 4500, "tacacs": 49, "radius": 1812, "radius-acct": 1813,
}
ICMP_TYPES: Dict[str, int] = {
    "echo-reply": 0, "unreachable": 3, "destination-unreachable": 3, "source-quench": 4, "redirect": 5, "echo": 8,
    "echo-request": 8, "router-advertisement": 9, "router-solicitation": 10, "time-exceeded": 11,
    "ttl-exceeded": 11, "parameter-problem": 12, "timestamp-request": 13, "timestamp-reply": 14,
}
ICMP_NAMES = {0: "echo-reply", 3: "unreachable", 4: "source-quench", 5: "redirect", 8: "echo",
              11: "time-exceeded", 12: "parameter-problem", 13: "timestamp-request", 14: "timestamp-reply"}
PROTOCOLS = {"ip", "ipv6", "any", "tcp", "udp", "icmp", "icmpv6", "ipv6-icmp", "gre", "esp", "ahp", "ah", "ospf",
             "pim", "igmp", "sctp", "vrrp"}
_PROTOCOL_NAMES = {"ipv6": "ip", "any": "ip", "ipv6-icmp": "icmpv6", "ahp": "ah"}
_L4 = ("tcp", "udp", "sctp")


class Unsupported(ValueError):
    """An entry the model cannot hold."""


def port_number(word: str) -> int:
    if word.isdigit():
        return int(word)
    if word.lower() in PORT_NAMES:
        return PORT_NAMES[word.lower()]
    raise Unsupported(f"port {word}")


def wildcard_prefix(address: str, wildcard: str) -> str:
    """``10.0.0.0 0.0.0.255`` as ``10.0.0.0/24``; raises Unsupported for a non-contiguous wildcard."""
    inverted = int(ipaddress.IPv4Address(wildcard)) ^ 0xFFFFFFFF
    try:
        return str(ipaddress.ip_network(f"{address}/{ipaddress.IPv4Address(inverted)}", strict=False))
    except ValueError:
        raise Unsupported(f"non-contiguous wildcard {wildcard}") from None


def prefix_wildcard(prefix: str) -> Tuple[str, str]:
    net = ipaddress.ip_network(prefix)
    return str(net.network_address), str(net.hostmask)


def _is_address(word: str) -> bool:
    try:
        ipaddress.ip_address(word)
        return True
    except ValueError:
        return False


def _host(address: str) -> str:
    return str(ipaddress.ip_network(address))


class Tokens:
    def __init__(self, words: List[str]) -> None:
        self.words = list(words)

    def peek(self) -> str:
        return self.words[0] if self.words else ""

    def take(self) -> str:
        if not self.words:
            raise Unsupported("entry ends too early")
        return self.words.pop(0)


def read_address(tokens: Tokens, wildcards: bool) -> str:
    """One address of an entry: ``any``, ``host A``, ``A WILDCARD`` (when ``wildcards``), ``A/len``, ``A/MASK``
    or a bare ``A`` (a host, on AOS-CX)."""
    word = tokens.take()
    if word in ("any", "any4", "any6"):
        return "any"
    if word == "host":
        return _host(tokens.take())
    if "/" in word:
        address, _, length = word.partition("/")
        if "." in length and ":" not in address:
            return str(ipaddress.ip_network(f"{address}/{length}", strict=False))
        return str(ipaddress.ip_network(word, strict=False))
    if not _is_address(word):
        raise Unsupported(f"address {word}")
    if wildcards and _is_address(tokens.peek()) and ":" not in word:
        prefix = wildcard_prefix(word, tokens.take())
        return "any" if prefix == "0.0.0.0/0" else prefix
    return _host(word)


def read_ports(tokens: Tokens) -> str:
    """A port match after an address, as the model's ``80,443,1000-2000``; "" when there is none."""
    op = tokens.peek()
    if op == "eq":
        tokens.take()
        values = []
        while tokens.peek() and (tokens.peek().isdigit() or tokens.peek().lower() in PORT_NAMES):
            values.append(str(port_number(tokens.take())))
        if not values:
            raise Unsupported("eq without a port")
        return ",".join(values)
    if op == "range":
        tokens.take()
        return f"{port_number(tokens.take())}-{port_number(tokens.take())}"
    if op == "gt":
        tokens.take()
        return f"{port_number(tokens.take()) + 1}-65535"
    if op == "lt":
        tokens.take()
        return f"0-{port_number(tokens.take()) - 1}"
    if op == "neq":
        raise Unsupported("neq")
    return ""


def read_entry(words: List[str], family: int, wildcards: bool, standard: bool = False) -> AclEntry:
    """An entry in the Cisco-style token form, without its sequence number. ``remark`` / ``comment`` entries too.
    A standard list's entries match a source address only.

    Raises Unsupported for what the model cannot hold."""
    tokens = Tokens(words)
    action = tokens.take()
    if action in ("remark", "comment"):
        return AclEntry(AclAction.REMARK, remark=" ".join(tokens.words).strip('"'))
    if action not in ("permit", "deny"):
        raise Unsupported(f"action {action}")
    entry = AclEntry(AclAction(action))
    if standard:
        entry.source = read_address(tokens, wildcards)
        _flags(entry, tokens)
        return entry
    proto = tokens.take().lower()
    if proto in ("object-group", "addrgroup", "portgroup"):
        raise Unsupported("object groups")
    if not (proto in PROTOCOLS or proto.isdigit()):
        raise Unsupported(f"protocol {proto}")
    entry.protocol = _PROTOCOL_NAMES.get(proto, proto)
    if entry.protocol == "icmp" and family == 6:
        entry.protocol = "icmpv6"
    entry.source = read_address(tokens, wildcards)
    if entry.protocol in _L4:
        entry.src_ports = read_ports(tokens)
    entry.destination = read_address(tokens, wildcards)
    if entry.protocol in _L4:
        entry.dst_ports = read_ports(tokens)
    if entry.protocol in ("icmp", "icmpv6"):
        word = tokens.peek()
        if word == "icmp-type":
            tokens.take()
            word = tokens.peek()
        if word.isdigit():
            entry.icmp_type = int(tokens.take())
            if tokens.peek().isdigit():
                raise Unsupported("ICMP code")
        elif word in ICMP_TYPES:
            entry.icmp_type = ICMP_TYPES[tokens.take()]
    _flags(entry, tokens)
    return entry


def _flags(entry: AclEntry, tokens: Tokens) -> None:
    while tokens.words:
        word = tokens.take()
        if word == "established" and entry.protocol == "tcp":
            entry.established = True
        elif word in ("log", "log-input", "logging"):
            entry.log = True
        elif word == "count":
            pass  # a counter, not a match
        else:
            raise Unsupported(f"'{word}'")


def unsupported_entry(text: str, sequence: Optional[int] = None) -> AclEntry:
    return AclEntry(AclAction.DENY, sequence=sequence, unsupported=text)


# writing ---------------------------------------------------------------------------------------------------------

def port_items(ports: str) -> List[Tuple[str, List[int]]]:
    """The model's ports as operator items: ``eq [80]``, ``range [1000, 2000]``; one ``""`` item for any port."""
    if not ports:
        return [("", [])]
    items: List[Tuple[str, List[int]]] = []
    for part in ports.split(","):
        if "-" in part:
            first, last = (int(p) for p in part.split("-", 1))
            if first == 0:
                items.append(("lt", [last + 1]))
            elif last == 65535:
                items.append(("gt", [first - 1]))
            else:
                items.append(("range", [first, last]))
        else:
            items.append(("eq", [int(part)]))
    return items


def expand(entry: AclEntry) -> List[Tuple[Tuple[str, List[int]], Tuple[str, List[int]]]]:
    """One (source ports, destination ports) item pair per entry a platform with one port match per side needs."""
    return [(s, d) for s in port_items(entry.src_ports) for d in port_items(entry.dst_ports)]


def numbered(acl: Acl, step: int = 10) -> List[Tuple[int, AclEntry, Tuple[str, List[int]], Tuple[str, List[int]]]]:
    """The entries of an ACL, expanded to one port match per side, with the sequence numbers to write: the source's
    numbers when nothing had to be expanded, else step, 2 * step, ... in order."""
    rows = [(entry, pair) for entry in acl.entries for pair in (expand(entry) if not entry.unsupported and
                                                                  entry.action != AclAction.REMARK else
                                                                  [(("", []), ("", []))])]
    keep = len(rows) == len(acl.entries) and all(e.sequence for e in acl.entries) and len(
        {e.sequence for e in acl.entries}) == len(acl.entries)
    result = []
    for n, (entry, (src, dst)) in enumerate(rows, 1):
        seq = entry.sequence if keep and entry.sequence is not None else n * step
        result.append((seq, entry, src, dst))
    return result


def cisco_ports(item: Tuple[str, List[int]]) -> List[str]:
    op, values = item
    return [op] + [str(v) for v in values] if op else []


def safe_name(name: str) -> str:
    """An ACL name every platform takes: numbered lists (IOS 101, Comware 3000) get a prefix."""
    return f"ACL-{name}" if name[:1].isdigit() else name.replace(" ", "_")


def cisco_address(prefix: str, style: str) -> List[str]:
    """An address in the token form of a platform. ``style``: "wildcard" (IOS IPv4, AOS-S: ``A W``), "prefix"
    (EOS, IPv6 everywhere: ``A/len``), "mask" (AOS-CX: ``A/MASK``, a host bare)."""
    if prefix == "any":
        return ["any"]
    net = ipaddress.ip_network(prefix)
    host = net.prefixlen == net.max_prefixlen
    if style == "mask":
        if host:
            return [str(net.network_address)]
        return [f"{net.network_address}/{net.netmask}" if net.version == 4 else str(net)]
    if host:
        return ["host", str(net.network_address)]
    if style == "wildcard" and net.version == 4:
        return list(prefix_wildcard(prefix))
    return [str(net)]


def cisco_entry(entry: AclEntry, family: int, src: Tuple[str, List[int]], dst: Tuple[str, List[int]], style: str,
                any_protocol: str, icmp6: str, icmp_names: bool, icmp_keyword: str = "") -> List[str]:
    """The words of one entry after its sequence number, in the Cisco-style token form."""
    if entry.action == AclAction.REMARK:
        return ["remark", entry.remark]
    words = [entry.action.value]
    proto = entry.protocol
    if proto == "ip":
        proto = any_protocol
    elif proto == "icmpv6":
        proto = icmp6
    words.append(proto)
    words += cisco_address(entry.source, style) + cisco_ports(src)
    words += cisco_address(entry.destination, style) + cisco_ports(dst)
    if entry.icmp_type is not None:
        if icmp_keyword:
            words.append(icmp_keyword)
        name = ICMP_NAMES.get(entry.icmp_type) if icmp_names and family == 4 else None
        words.append(name or str(entry.icmp_type))
    if entry.established:
        words.append("established")
    if entry.log:
        words.append("log")
    return words


def read_block(acl: Acl, children: List[Node], wildcards: bool, standard: bool = False) -> None:
    """The entries of an ACL block in the Cisco-style token form (``10 permit ...``), appended to ``acl``."""
    from .model import Origin
    for child in children:
        words = child.words
        if words in (["exit"],) or words[:1] in (["statistics"], ["counters"]):
            continue
        sequence: Optional[int] = None
        if words[0] == "sequence" and len(words) > 1:
            words = words[1:]
        if words[0].isdigit():
            sequence, words = int(words[0]), words[1:]
        try:
            entry = read_entry(words, acl.family, wildcards, standard)
        except (Unsupported, ValueError, IndexError):
            entry = unsupported_entry(child.text)
        entry.sequence, entry.origin = sequence, Origin(child.line, child.text)
        acl.entries.append(entry)


def cisco_lines(acl: Acl, report: "Report", label: str, style: str, any_protocol: str, icmp6: str,
                icmp_names: bool, icmp_keyword: str = "", remark: str = "remark", quote_remark: bool = False,
                established: bool = True) -> List[str]:
    """The entry lines of an ACL in the Cisco-style token form, each with its sequence number."""
    from .report import Severity
    lines = []
    for seq, entry, src, dst in numbered(acl):
        if entry.unsupported:
            lines.append(f"{seq} {remark} {_quoted('RouterShift could not convert: ' + entry.unsupported, quote_remark)}")
            report.add("acl", label, Severity.REVIEW, "acl-entry",
                       f"entry '{entry.unsupported}' not converted; its place is marked by a {remark}")
            continue
        if entry.action == AclAction.REMARK:
            lines.append(f"{seq} {remark} {_quoted(entry.remark, quote_remark)}")
            continue
        if entry.established and not established:
            report.add("acl", label, Severity.REVIEW, "established",
                       "'established' is not taken by every release of the platform; check the entry")
        words = cisco_entry(entry, acl.family, src, dst, style, any_protocol, icmp6, icmp_names, icmp_keyword)
        lines.append(f"{seq} {' '.join(words)}")
    return lines


def _quoted(text: str, quote: bool) -> str:
    return '"' + text.replace('"', "'") + '"' if quote else text

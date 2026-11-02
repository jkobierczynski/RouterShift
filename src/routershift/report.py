# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fidelity report: what was converted exactly, approximately, or not at all."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Tuple

from . import known
from .model import Unparsed


# Words after which a configuration line carries a secret; the report shows "<removed>" instead.
_SECRET_WORDS = {"community", "password", "secret", "key", "key-string", "md5", "sha", "auth", "priv", "pre-shared-key",
                 "shared-key", "authentication-key", "encrypted-password", "simple-password", "value", "authentication-mode", "privacy-mode", "set-key"}
# Words between a secret word and the secret: its form, or (SNMP) its access
_SECRET_TYPES = {"ciphertext", "plaintext", "encrypted", "cipher", "hash", "simple", "read", "write", "text",
                 "local", "remote", "ascii", "hex", "ascii-text", "hexadecimal"}
# Algorithms and key sizes that stand between a secret word and the secret ("priv aes 128 <key>")
_ALGORITHMS = {"des", "3des", "aes", "aes128", "aes192", "aes256", "128", "192", "256", "sha1", "sha256", "sha384",
               "sha512", "hmac-sha-1", "hmac-sha-256"}
# Forms that are always followed by the secret itself, wherever they stand ("super password role R simple X",
# 'password manager user-name "U" plaintext "X"')
_SECRET_FORMS = {"simple", "plaintext", "ciphertext", "cipher", "hash", "sha1"}
# Commands where "authentication" itself is followed by a secret (HSRP: "standby 1 authentication cisco")
_AUTH_COMMANDS = {"standby", "vrrp"}


def redact(text: str) -> str:
    words = text.split()
    result = list(words)
    secret_words = _SECRET_WORDS | ({"authentication"} if words and words[0] in _AUTH_COMMANDS else set())
    if words and words[0] in ("match", "set"):  # route maps: "match community LIST" names a list, not a secret
        secret_words = secret_words - {"community"}
    n = 0
    while n < len(words) - 1:
        if words[n].lower() in secret_words:
            n += 1
            # "password 7 <hash>", "secret 0 <text>", "password ciphertext <hash>", "md5 key-string <key>": the type
            # stays, the secret goes
            while n < len(words) - 1 and (words[n].isdigit() and len(words[n]) == 1 or words[n] in _SECRET_TYPES
                                           or words[n].lower() in secret_words | _ALGORITHMS):
                n += 1
            result[n] = "<removed>"
        elif words[n].lower() in _SECRET_FORMS:
            n += 1 if words[n + 1].isdigit() and len(words[n + 1]) == 1 and n + 2 < len(words) else 0
            result[n + 1] = "<removed>"
        n += 1
    return " ".join(result)


def _ranges(lines: List[int]) -> str:
    """'9-18, 23, 71-77' for a list of line numbers."""
    parts: List[str] = []
    numbers = sorted(set(lines))
    start = prev = numbers[0]
    for n in numbers[1:] + [0]:
        if n == prev + 1:
            prev = n
            continue
        parts.append(f"{start}-{prev}" if prev > start else str(start))
        start = prev = n
    return ", ".join(parts)


class Severity(IntEnum):
    INFO = 0  # exact, worth knowing
    APPROX = 1  # converted, but not with identical semantics
    REVIEW = 2  # a person has to look at this before it goes live


_LABEL = {Severity.INFO: "info", Severity.APPROX: "approximated", Severity.REVIEW: "needs-review"}

_KIND_TITLES = [
    ("system", "System"),
    ("vlan", "VLANs"),
    ("interface", "Interfaces"),
    ("fhrp", "Gateway redundancy (HSRP, VRRP)"),
    ("route", "Static routes"),
    ("track", "IP SLA and object tracking"),
    ("ospf", "OSPF"),
    ("rip", "RIP"),
    ("isis", "IS-IS"),
    ("mpls", "MPLS"),
    ("bgp", "BGP"),
    ("acl", "Access lists"),
    ("policy", "Prefix lists and route maps"),
    ("dhcp", "DHCP server"),
    ("nat", "NAT"),
    ("vpn", "Site-to-site VPN (IPsec)"),
    ("qos", "QoS"),
    ("monitor", "Port mirroring, sFlow and NetFlow"),
    ("wlan", "Wireless (WLAN)"),
    ("management", "Management"),
    ("known", "Recognised, not converted"),
    ("unparsed", "Not understood"),
]


@dataclass
class Finding:
    severity: Severity
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"severity": _LABEL[self.severity], "code": self.code, "message": self.message}


@dataclass
class Item:
    kind: str
    name: str
    findings: List[Finding] = field(default_factory=list)
    skipped: bool = False  # not emitted at all

    @property
    def status(self) -> str:
        if self.skipped:
            return "skipped"
        worst = max((f.severity for f in self.findings), default=Severity.INFO)
        return "exact" if worst == Severity.INFO else _LABEL[worst]


class Report:
    def __init__(self, source: str = "", target: str = "") -> None:
        self.source = source
        self.target = target
        self.items: Dict[Tuple[str, str], Item] = {}

    def item(self, kind: str, name: str) -> Item:
        key = (kind, name)
        if key not in self.items:
            self.items[key] = Item(kind, name)
        return self.items[key]

    def add(self, kind: str, name: str, severity: Severity, code: str, message: str) -> None:
        self.item(kind, name).findings.append(Finding(severity, code, message))

    def skip(self, kind: str, name: str, code: str, message: str) -> None:
        item = self.item(kind, name)
        item.skipped = True
        item.findings.append(Finding(Severity.REVIEW, code, message))

    def unparsed(self, entries: List[Unparsed]) -> None:
        """Lines no writer could use. Those RouterShift recognises are grouped by feature, with the reason, once per
        feature; the others are grouped by the block they are in, with every line listed."""
        recognised: Dict[str, Tuple[str, List[int]]] = {}
        for entry in entries:
            group = (entry.group, entry.reason) if entry.group else known.classify(entry.text, entry.section)
            if group is not None:
                recognised.setdefault(group[0], (group[1], []))[1].append(entry.line)
                continue
            if not entry.section:
                self.skip("unparsed", f"line {entry.line}: {redact(entry.text)}", "not-converted",
                          "not converted; translate it by hand if the new device needs it")
                continue
            head = entry.section.split(" / ")[0]
            block = next((k for k in self.items if k[0] == "unparsed" and k[1].endswith(f": {redact(head)}")), None)
            name = block[1] if block else f"in '{redact(head)}'"
            self.skip("unparsed", name, "not-converted", f"line {entry.line}: {redact(entry.text)} not converted")
        for label, (reason, lines) in sorted(recognised.items()):
            count = f"{len(set(lines))} line" + ("s" if len(set(lines)) > 1 else "")
            self.skip("known", label, "not-converted", f"{reason} ({count}: {_ranges(lines)})")

    def counts(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for item in self.items.values():
            result[item.status] = result.get(item.status, 0) + 1
        return result

    def to_text(self) -> str:
        lines = [f"RouterShift report: {self.source} -> {self.target}", ""]
        counts = self.counts()
        lines.append(", ".join(f"{counts[s]} {s}" for s in ("exact", "approximated", "needs-review", "skipped")
                               if s in counts) or "nothing converted")
        for kind, title in _KIND_TITLES:
            items = [i for i in self.items.values() if i.kind == kind]
            if not items:
                continue
            lines += ["", title]
            for i in items:
                lines.append(f"  {i.name}: {i.status}")
                lines += [f"    - [{_LABEL[f.severity]}] {f.message}" for f in i.findings
                          if f.severity > Severity.INFO or i.skipped]
        return "\n".join(lines) + "\n"

    def to_json(self) -> str:
        data = {
            "source": self.source,
            "target": self.target,
            "counts": self.counts(),
            "items": [{"kind": i.kind, "name": i.name, "status": i.status,
                       "findings": [f.to_dict() for f in i.findings]} for i in self.items.values()],
        }
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

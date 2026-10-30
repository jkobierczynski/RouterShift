# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fidelity report: what was converted exactly, approximately, or not at all."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Tuple


class Severity(IntEnum):
    INFO = 0  # exact, worth knowing
    APPROX = 1  # converted, but not with identical semantics
    REVIEW = 2  # a person has to look at this before it goes live


_LABEL = {Severity.INFO: "info", Severity.APPROX: "approximated", Severity.REVIEW: "needs-review"}

_KIND_TITLES = [
    ("system", "System"),
    ("vlan", "VLANs"),
    ("interface", "Interfaces"),
    ("route", "Static routes"),
    ("ospf", "OSPF"),
    ("bgp", "BGP"),
    ("acl", "Access lists"),
    ("management", "Management"),
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

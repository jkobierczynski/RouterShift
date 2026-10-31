# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""QoS helpers that every reader and writer shares: DSCP names and the policies a target can take."""

from __future__ import annotations

from typing import Any, List, Tuple

from . import acl as acl_text
from .confparse import Node
from .model import Acl, AclAction, Device, QosAction, QosClass, QosPolicy
from .report import Report

DEFAULT_CLASS = "class-default"

# DSCP names every platform reads; writers use the number or the name as the platform prefers
DSCP_NAMES = {"default": 0, "ef": 46, "va": 44,
              **{f"cs{n}": n * 8 for n in range(8)},
              **{f"af{c}{d}": c * 8 + d * 2 for c in range(1, 5) for d in range(1, 4)}}
_NAME_OF = {value: name for name, value in DSCP_NAMES.items() if name != "cs0"}


def dscp(word: str) -> int:
    """A DSCP value from its name (ef, af41, cs3) or number; ValueError when neither, so the line is reported."""
    word = word.lower()
    if word in DSCP_NAMES:
        return DSCP_NAMES[word]
    value = int(word)
    if not 0 <= value <= 63:
        raise ValueError(word)
    return value


def dscp_name(value: int) -> str:
    """ef, af41, cs3, or the number when the value has no name."""
    return _NAME_OF.get(value, str(value))


def action_label(policy: QosPolicy, action: QosAction) -> str:
    return f"policy {policy.name} class {action.qos_class}"


def policies_used(device: Device) -> List[str]:
    return sorted({n for i in device.interfaces.values() for n in (i.qos_policy_in, i.qos_policy_out) if n})


def has_qos(device: Device) -> bool:
    return bool(device.qos_policies or device.qos_classes
                or any(i.qos_trust or i.qos_policy_in or i.qos_policy_out for i in device.interfaces.values()))


# Switches whose classes hold their own entries (AOS-CX, AOS-S) ---------------------------------------------------------

def class_lines(acl: Acl, report: Report, label: str, **cisco: Any) -> List[str]:
    """The entries of an ACL as class entries: 'match' for permit, 'ignore' for deny (classes take no remarks)."""
    lines = []
    for line in acl_text.cisco_lines(acl, report, label, **cisco):
        seq, rest = line.split(" ", 1)
        verb, _, tail = rest.partition(" ")
        if verb not in _CLASS_VERB:
            continue
        if tail.endswith(" log"):  # a class does not log
            tail = tail[:-4]
        lines.append(f"{seq} {_CLASS_VERB.get(verb, verb)} {tail}")
    return lines


_CLASS_VERB = {"permit": "match", "deny": "ignore"}


def read_class(qos_class: QosClass, children: List[Node], dscp_word: str, wildcards: bool,
               pending: List[Tuple[QosClass, Acl]]) -> List[Node]:
    """Class entries: those that match one DSCP value on all traffic become the class's DSCP list, the rest an ACL
    (resolved by ``adopt`` once every ACL is read). Returns the children it could not read."""
    entries: List[Node] = []
    rest: List[Node] = []
    for child in children:
        w = _any([word.strip('"') for word in child.words])
        if len(w) >= 3 and w[0].isdigit() and w[1] in ("match", "ignore"):
            if w[1] == "match" and len(w) == 7 and w[2:5] in (["any", "any", "any"], ["ip", "any", "any"]) \
                    and w[5] == dscp_word:
                try:
                    qos_class.dscp.append(dscp(w[6]))
                    continue
                except ValueError:
                    pass
            entries.append(Node(child.line, " ".join([w[0], "permit" if w[1] == "match" else "deny"] + w[2:])))
        elif w != ["exit"]:
            rest.append(child)
    if entries:
        acl = Acl(qos_class.name)
        acl_text.read_block(acl, entries, wildcards)
        pending.append((qos_class, acl))
    return rest


def _any(words: List[str]) -> List[str]:
    """Words with each '0.0.0.0 255.255.255.255' (all addresses as a wildcard mask) written as 'any'."""
    out: List[str] = []
    for word in words:
        if word == "255.255.255.255" and out and out[-1] == "0.0.0.0":
            out[-1] = "any"
        else:
            out.append(word)
    return out


def _key(acl: Acl) -> List[Tuple[Any, ...]]:
    return [(e.action, e.protocol, e.source, e.destination, e.src_ports, e.dst_ports, e.icmp_type, e.established,
             e.unsupported) for e in acl.entries if e.action != AclAction.REMARK]


def adopt(device: Device, pending: List[Tuple[QosClass, Acl]]) -> None:
    """Point each class at the ACL with the same entries, or add its entries as an ACL of its own."""
    for qos_class, acl in pending:
        same = next((a.name for a in device.acls.values() if _key(a) == _key(acl)), None)
        if same is None:
            same = next(n for n in (qos_class.name, f"{qos_class.name}-CLASS", f"{qos_class.name}-CLASS2")
                        if n not in device.acls)
            acl.name = same
            device.acls[same] = acl
        qos_class.acl = same

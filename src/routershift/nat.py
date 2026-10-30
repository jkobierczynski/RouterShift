# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NAT helpers that every writer shares."""

from __future__ import annotations

from typing import List

from .model import Device, InterfaceKind, NatRule
from .report import Report

SUPPORTED = {"ios", "eos", "comware"}  # AOS-CX and AOS-S switches have no NAT


def label(rule: NatRule) -> str:
    if rule.kind == "static":
        port = f" {rule.protocol} {rule.local_port}->{rule.translated_port}" if rule.protocol else ""
        return f"static {rule.local} -> {rule.translated}{port}"
    target = f"pool {rule.pool}" if rule.pool else "interface"
    return f"dynamic {rule.acl or 'all sources'} -> {target}" + (" overload" if rule.overload else "")


def outside(device: Device, rule: NatRule) -> List[str]:
    """The outside interfaces a rule applies on: its own, or every interface marked outside."""
    if rule.interface:
        return [rule.interface]
    return [i.name for i in device.interfaces.values() if i.nat == "outside"]


def has_nat(device: Device) -> bool:
    return bool(device.nat_rules or device.nat_pools or any(i.nat for i in device.interfaces.values()))


def inside_unknown(device: Device) -> bool:
    """True when the source marks no inside interfaces (EOS, Comware), which IOS needs."""
    return bool(device.nat_rules) and not any(i.nat == "inside" for i in device.interfaces.values()
                                              if i.kind != InterfaceKind.MANAGEMENT)


def needs_acl(rule: NatRule) -> bool:
    """A dynamic rule with no ACL (Comware's plain 'nat outbound'), which IOS and EOS cannot express."""
    return rule.kind == "dynamic" and not rule.acl


def skip_all(device: Device, report: Report, platform: str) -> None:
    """For a target without NAT: every rule goes to the report, so it is moved to the edge router by hand."""
    for rule in device.nat_rules:
        report.skip("nat", label(rule), "nat-unsupported",
                    f"{platform} switches do not do NAT; move this rule to a router or firewall")

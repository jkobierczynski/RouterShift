# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""SNMP and NTP helpers that every writer shares. Communities and keys are secrets: no label shows them."""

from __future__ import annotations

from typing import List

from .model import Device, NtpKey, SnmpCommunity, SnmpHost, SnmpUser
from .report import Report, Severity

PLACEHOLDER = "CHANGE-ME"  # written where the source secret is encrypted

AUTH = ["md5", "sha", "sha256", "sha384", "sha512"]
PRIV = ["des", "3des", "aes128", "aes192", "aes256"]


def community_label(device: Device, c: SnmpCommunity) -> str:
    return f"community #{device.snmp.communities.index(c) + 1} ({c.access})"


def host_label(h: SnmpHost) -> str:
    kind = "inform" if h.informs else "trap"
    return f"{kind} host {h.address}" + (f" vrf {h.vrf}" if h.vrf else "") + f" (v{h.version})"


def user_label(u: SnmpUser) -> str:
    return f"SNMPv3 user {u.name}"


def level(u: SnmpUser) -> str:
    return "priv" if u.priv else "auth" if u.auth else "noauth"


def secret(value: str, report: Report, kind: str, label: str, what: str) -> str:
    """The secret to write, or the placeholder with a note when the source holds it encrypted."""
    if value:
        return value
    report.add(kind, label, Severity.REVIEW, "secret-encrypted",
               f"the {what} is stored encrypted in the source; replace {PLACEHOLDER} with it")
    return PLACEHOLDER


def user_keys(u: SnmpUser, report: Report) -> List[str]:
    """[auth key, priv key] to write for a user (placeholders where encrypted)."""
    label = user_label(u)
    keys = []
    if u.auth:
        keys.append(secret(u.auth_key, report, "management", label, "authentication key"))
    if u.priv:
        keys.append(secret(u.priv_key, report, "management", label, "privacy key"))
    return keys


def pick(value: str, offered: List[str], report: Report, label: str) -> str:
    """The algorithm, or the nearest stronger one the platform offers (reported)."""
    if value in offered:
        return value
    order = AUTH if value in AUTH else PRIV
    stronger = [v for v in order[order.index(value) + 1:] if v in offered] if value in order else []
    chosen = stronger[0] if stronger else offered[-1]
    report.add("management", label, Severity.REVIEW, "snmp-algorithm",
               f"{value} is not offered; {chosen} is written, so the managers must change to it as well")
    return chosen


def ntp_key(key: NtpKey, report: Report) -> str:
    return secret(key.key, report, "system", f"ntp key {key.number}", "NTP key")


def has_snmp(device: Device) -> bool:
    s = device.snmp
    return bool(s.communities or s.hosts or s.users or s.location or s.contact or s.groups)

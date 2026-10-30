# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Local users and AAA helpers that every writer shares. Passwords and keys are secrets: no label shows them."""

from __future__ import annotations

from typing import List, Optional, Tuple

from .model import AaaMethod, AaaServer, Device, LocalUser
from .report import Report, Severity

PLACEHOLDER = "CHANGE-ME"  # written where a server key is encrypted in the source

_TYPE7 = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def decode_type7(text: str) -> str:
    """Cisco type 7 is an obfuscation, not a hash: it reads back to the clear text ('' when malformed)."""
    try:
        seed = int(text[:2])
        pairs = bytes.fromhex(text[2:])
    except ValueError:
        return ""
    return "".join(chr(b ^ ord(_TYPE7[(seed + n) % len(_TYPE7)])) for n, b in enumerate(pairs))


def hash_type(value: str) -> str:
    """The family of a crypt(3)-style hash, which some platforms share."""
    return {"$1$": "md5-crypt", "$5$": "sha256-crypt", "$6$": "sha512-crypt"}.get(value[:3], "")


def server_label(s: AaaServer) -> str:
    return f"{'RADIUS' if s.protocol == 'radius' else 'TACACS+'} server {s.address}" + (f" vrf {s.vrf}" if s.vrf else "")


def method_label(m: AaaMethod) -> str:
    level = f" {m.level}" if m.level is not None else ""
    return f"{m.kind} {m.service}{level} {m.name}"


def user_label(u: LocalUser) -> str:
    return f"user {u.name}"


def key(s: AaaServer, report: Report) -> str:
    """The server key to write, or the placeholder with a note."""
    if s.key:
        return s.key
    report.add("management", server_label(s), Severity.REVIEW, "secret-encrypted",
               f"the server key is stored encrypted in the source; replace {PLACEHOLDER} with it")
    return PLACEHOLDER


def password(u: LocalUser, hashes: Tuple[str, ...], report: Report, kind: str = "user") -> Optional[Tuple[str, str]]:
    """("plain", text) or (hash type, hash) the target can take, or None with a note: the user is left out rather
    than given a password nobody chose."""
    if u.password:
        return "plain", u.password
    if u.password_hash and u.hash_type in hashes:
        return u.hash_type, u.password_hash
    label = user_label(u) if kind == "user" else "enable secret"
    if not u.password_hash:
        return "none", ""
    report.skip("management", label, "password-hash",
                f"the password hash ({u.hash_type or 'platform specific'}) cannot be used on the target; "
                f"{'create the user' if kind == 'user' else 'set it'} by hand")
    return None


# Privilege levels and the roles of the platforms that have roles instead
def role(privilege: Optional[int], roles: List[Tuple[int, str]]) -> str:
    """The role for a privilege level: the first role whose level is at or below it (roles from the top down)."""
    level = 1 if privilege is None else privilege
    return next((name for floor, name in roles if level >= floor), roles[-1][1])


def privilege(name: str, roles: List[Tuple[int, str]]) -> Optional[int]:
    return next((floor for floor, role_name in roles if role_name == name), None)


def has_aaa(device: Device) -> bool:
    a = device.aaa
    return bool(a.servers or a.methods or a.groups)


def group_servers(device: Device, method: str) -> List[AaaServer]:
    """The servers a method stands for."""
    if not method.startswith("group:"):
        return []
    name = method[len("group:"):]
    if name in ("radius", "tacacs"):
        return [s for s in device.aaa.servers if s.protocol == name]
    group = device.aaa.groups.get(name)
    if group is None:
        return []
    return [s for s in device.aaa.servers if s.address in group.servers and s.protocol == group.protocol]


def protocol_of(device: Device, method: str) -> str:
    """'radius' or 'tacacs' for a group method, '' otherwise."""
    name = method[len("group:"):] if method.startswith("group:") else ""
    if name in ("radius", "tacacs"):
        return name
    group = device.aaa.groups.get(name)
    return group.protocol if group else ""

# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""NX-OS device security: MACsec, MAC ACLs, NAT; IPsec is reported (a Nexus switch terminates no VPNs).

How the model maps to NX-OS:

* A MACsec profile is ``macsec policy NAME`` (cipher suite, key server priority, SAK expiry time) and a key chain
  ``KC-NAME macsec`` that holds the pre-shared key (``key CKN`` / ``key-octet-string CAK cryptographic-algorithm
  AES_128_CMAC|AES_256_CMAC``); a port takes both with ``macsec keychain KC-NAME policy NAME``. NX-OS has no setting
  for sending the SCI or for passing LLDP unencrypted.
* A MAC ACL is ``mac access-list NAME`` with ``[SEQ] permit|deny SRC DST [0xETHERTYPE] [vlan V]``, a MAC address
  written ``MAC WILDCARD`` in dotted form; a port takes it inbound with ``mac port access-group NAME``.
* NAT is ``feature nat`` with ``ip nat inside|outside`` on the interfaces and the IOS form of the rules: ``ip nat
  inside source static|list ...`` and ``ip nat pool``. A Nexus 9000 needs TCAM carved for NAT first.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Set

from . import acl as acl_text
from . import nat as nat_text
from . import security as security_text
from . import vpn as vpn_text
from .model import AclAction, Device, Interface, MacAcl, MacAclEntry, MacsecProfile, NatRule
from .report import Report, Severity

KIND = security_text.KIND
Add = Callable[[Severity, str, str], None]
Name = Callable[[str], str]
CIPHERS = {"aes128-gcm": "GCM-AES-128", "aes256-gcm": "GCM-AES-256", "aes128-gcm-xpn": "GCM-AES-XPN-128",
           "aes256-gcm-xpn": "GCM-AES-XPN-256"}
_FROM_CIPHER = {v: k for k, v in CIPHERS.items()}
HOST = "00:00:00:00:00:00"


def keychain(profile: str) -> str:
    return security_text.keychain_name(profile)


# MACsec -------------------------------------------------------------------------------------------------------------

def macsec_lines(device: Device, report: Report, ind: str, features: Set[str]) -> List[str]:
    lines: List[str] = []
    for p in device.macsec_profiles.values():
        features.add("macsec")
        label = f"MACsec profile {p.name}"
        report.item(KIND, label)
        if p.ckn:
            bits = "256" if "256" in p.cipher else "128"
            lines += [f"key chain {keychain(p.name)} macsec", f"{ind}key {p.ckn}",
                      f"{ind * 2}key-octet-string {p.cak or security_text.PLACEHOLDER} cryptographic-algorithm "
                      f"AES_{bits}_CMAC"]
            if not p.cak:
                report.add(KIND, label, Severity.REVIEW, "macsec-key",
                           f"the key is stored encrypted in the source; replace {security_text.PLACEHOLDER} in key "
                           f"chain {keychain(p.name)} with it")
        else:
            report.add(KIND, label, Severity.REVIEW, "macsec-key",
                       "the profile has no pre-shared key in the source; add one to the key chain by hand")
        lines.append(f"macsec policy {p.name}")
        if p.cipher:
            lines.append(f"{ind}cipher-suite {CIPHERS[p.cipher]}")
        if p.key_server_priority is not None:
            lines.append(f"{ind}key-server-priority {p.key_server_priority}")
        if p.rekey_period is not None:
            lines.append(f"{ind}sak-expiry-time {p.rekey_period}")
        left = [w for w, v in (("sending the SCI in every frame", p.sci),
                               ("LLDP passing unencrypted", p.lldp_bypass)) if v]
        if left:
            report.add(KIND, label, Severity.APPROX, "macsec-options",
                       "; ".join(left) + ": NX-OS has no such setting on the MACsec policy and decides itself")
        report.add(KIND, label, Severity.REVIEW, "macsec-platform",
                   "MACsec runs on some Nexus 9000 models and ports only (with a licence); check the target supports it")
    if device.macsec_fips:
        report.add(KIND, "MACsec", Severity.REVIEW, "macsec-fips",
                   "FIPS restrictions for MACsec are not written; NX-OS enables FIPS mode for the whole switch "
                   "(fips mode enable)")
    return lines + (["!"] if lines else [])


# MAC ACLs -----------------------------------------------------------------------------------------------------------

def _dotted(colon: str) -> str:
    d = colon.replace(":", "")
    return f"{d[0:4]}.{d[4:8]}.{d[8:12]}"


def _address(a: str) -> str:
    if a == "any":
        return "any"
    mac, wildcard = a.split()
    return f"{_dotted(mac)} {_dotted(wildcard)}"


def mac_acl_lines(acl: MacAcl, report: Report, ind: str) -> List[str]:
    label = f"mac access-list {acl.name}"
    report.item("acl", label)
    lines = [f"mac access-list {acl.name}"]
    logged = False
    for n, e in enumerate(acl.entries, 1):
        seq = e.sequence or n * 10
        if e.action == AclAction.REMARK:
            lines.append(f"{ind}{seq} remark {e.remark}")
            continue
        words = [str(seq), e.action.value, _address(e.source), _address(e.destination)]
        if e.ethertype is not None:
            words.append(f"0x{e.ethertype:04x}")
        if e.vlan is not None:
            words.append(f"vlan {e.vlan}")
        logged = logged or e.log
        lines.append(ind + " ".join(words))
    if logged:
        report.add("acl", label, Severity.APPROX, "mac-acl-log", "logging of matches is left out: an NX-OS MAC ACL "
                                                                 "entry does not log")
    return lines + ["!"]


def interface_lines(device: Device, iface: Interface, add: Add) -> List[str]:
    lines: List[str] = []
    if iface.mac_acl_in:
        if iface.mac_acl_in in device.mac_acls:
            lines.append(f"mac port access-group {iface.mac_acl_in}")
        else:
            add(Severity.REVIEW, "mac-acl", f"MAC ACL {iface.mac_acl_in} is applied but not defined; left out")
    if iface.mac_acl_out:
        add(Severity.REVIEW, "mac-acl", f"NX-OS filters MAC ACLs inbound only; output MAC ACL {iface.mac_acl_out} "
                                        "left out")
    if iface.macsec_profile:
        p = device.macsec_profiles.get(iface.macsec_profile)
        if p is None:
            add(Severity.REVIEW, "macsec", f"MACsec profile {iface.macsec_profile} is not defined; left out")
        else:
            lines.append(f"macsec keychain {keychain(p.name)} policy {p.name}")
        if p is not None and not p.ckn:
            add(Severity.REVIEW, "macsec", f"key chain {keychain(p.name)} is not written (the profile has no key); "
                                           "create it before applying")
    if iface.crypto_map:
        add(Severity.REVIEW, "vpn", f"crypto map {iface.crypto_map} is left out: a Nexus switch terminates no IPsec; "
                                    "move the VPN to a router or firewall")
    side = iface.nat or ("outside" if any(iface.name in nat_text.outside(device, r) for r in device.nat_rules
                                          if not nat_text.needs_acl(r)) else "")
    if side:
        lines.append(f"ip nat {side}")
    return lines


# NAT ----------------------------------------------------------------------------------------------------------------

def nat_lines(device: Device, report: Report, port: Name, vrf: Name, features: Set[str]) -> List[str]:
    d = device
    if not nat_text.has_nat(d):
        return []
    features.add("nat")
    lines: List[str] = []
    for pool in d.nat_pools.values():
        if not pool.prefix_len:
            report.add("nat", f"pool {pool.name}", Severity.REVIEW, "nat-mask",
                       "the source gives no mask for the pool; /24 is written, check it")
        lines.append(f"ip nat pool {pool.name} {pool.first} {pool.last} prefix-length {pool.prefix_len or 24}")
    for rule in d.nat_rules:
        label = nat_text.label(rule)
        if nat_text.needs_acl(rule):
            report.skip("nat", label, "nat-acl", "the rule translates every source; write an ACL for the inside "
                        "networks and add the rule by hand")
            continue
        report.item("nat", label)
        if rule.acl and rule.acl not in d.acls:
            report.add("nat", label, Severity.REVIEW, "acl-missing", f"ACL {rule.acl} is not defined")
        outside = nat_text.outside(d, rule)
        if not outside:
            report.add("nat", label, Severity.REVIEW, "nat-outside",
                       "no outside interface is marked; the rule has nowhere to apply")
        lines.append(_rule(rule, outside, report, port, vrf))
    if nat_text.inside_unknown(d):
        report.add("nat", "inside interfaces", Severity.REVIEW, "nat-inside",
                   "the source does not mark inside interfaces; add 'ip nat inside' to them")
    if d.nat_rules:
        report.add("nat", nat_text.label(d.nat_rules[0]), Severity.REVIEW, "nat-tcam",
                   "a Nexus 9000 translates in hardware only after TCAM is carved for it (hardware access-list tcam "
                   "region nat N, then a reload); check the model supports the rules")
    return lines + (["!"] if lines else [])


def _rule(rule: NatRule, outside: List[str], report: Report, port: Name, vrf: Name) -> str:
    tail = f" vrf {vrf(rule.vrf)}" if rule.vrf else ""
    if rule.kind == "static":
        if rule.protocol:
            return (f"ip nat inside source static {rule.protocol} {rule.local} {rule.local_port} {rule.translated} "
                    f"{rule.translated_port}{tail}")
        return f"ip nat inside source static {rule.local} {rule.translated}{tail}"
    acl = acl_text.safe_name(rule.acl)
    if rule.pool:
        return f"ip nat inside source list {acl} pool {rule.pool}" + (" overload" if rule.overload else "") + tail
    if len(outside) > 1:
        report.add("nat", nat_text.label(rule), Severity.REVIEW, "nat-outside",
                   f"NX-OS overloads onto one interface; {port(outside[0])} is used, not "
                   + ", ".join(port(n) for n in outside[1:]))
    where = port(outside[0]) if outside else "OUTSIDE-INTERFACE"
    return f"ip nat inside source list {acl} interface {where} overload{tail}"


def unwritable(device: Device, report: Report) -> None:
    vpn_text.skip_all(device, report, "NX-OS")


# reading ------------------------------------------------------------------------------------------------------------

def mac_acl_line(acl: MacAcl, w: List[str]) -> bool:
    """[SEQ] permit|deny SRC DST [0xETHERTYPE] [vlan V], or [SEQ] remark TEXT; an address is any or MAC WILDCARD."""
    seq: Optional[int] = None
    if w[0].isdigit():
        seq, w = int(w[0]), w[1:]
    if w[0] == "remark":
        acl.entries.append(MacAclEntry(AclAction.REMARK, seq, remark=" ".join(w[1:])))
        return True
    if w[0] not in ("permit", "deny"):
        return False
    e = MacAclEntry(AclAction(w[0]), seq)
    e.source, rest = security_text._address(w[1:])
    e.destination, rest = security_text._address(rest)
    while rest:
        if rest[0].startswith("0x"):
            e.ethertype, rest = int(rest[0], 16), rest[1:]
        elif rest[0] == "vlan" and len(rest) >= 2:
            e.vlan, rest = int(rest[1]), rest[2:]
        else:
            return False
    acl.entries.append(e)
    return True


def macsec_policy(device: Device, name: str, children: List[List[str]]) -> List[int]:
    p = device.macsec_profiles.setdefault(name, MacsecProfile(name))
    bad = []
    for n, w in enumerate(children):
        if w[0] == "cipher-suite" and len(w) == 2 and w[1] in _FROM_CIPHER:
            p.cipher = _FROM_CIPHER[w[1]]
        elif w[0] == "key-server-priority" and len(w) == 2:
            p.key_server_priority = int(w[1])
        elif w[0] == "sak-expiry-time" and len(w) == 2:
            p.rekey_period = int(w[1])
        elif w == ["include-icv-indicator"] or w[0] == "security-policy" or w[0] == "conf-offset" or \
                w[0] == "window-size":
            pass
        else:
            bad.append(n)
    return bad


def octet_string(w: List[str]) -> Optional[str]:
    """key-octet-string [0|7] CAK [cryptographic-algorithm X]: the clear-text key, "" if encrypted, None if not one."""
    if w[0] != "key-octet-string" or len(w) < 2:
        return None
    args = w[1:]
    if len(args) >= 2 and args[-2] == "cryptographic-algorithm":
        args = args[:-2]
    if len(args) == 1:
        return "" if args[0] == security_text.PLACEHOLDER else args[0]
    if len(args) == 2 and args[0] in ("0", "7"):
        return args[1] if args[0] == "0" else ""
    return None

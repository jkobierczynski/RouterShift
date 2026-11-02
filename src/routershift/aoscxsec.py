# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-CX device security: control-plane ACLs and policing, MACsec, MAC ACLs.

How the model maps to AOS-CX:

* An ACL on the control plane is ``apply access-list ip NAME control-plane vrf V``.
* The platform's CoPP classes (EOS ``copp-system-bgp`` ...) are the classes of the same protocol in the CoPP policy
  ``RS-COPP`` (``class bgp-ipv4 priority 6 rate N``), applied with ``apply copp-policy``. AOS-CX CoPP classes are the
  platform's own: a class that matches an ACL has no place in it.
* A MACsec profile is a MACsec policy (cipher, SCI) and an MKA policy of the same name (pre-shared key, key server
  priority), applied on the port with ``apply mka policy``.
* A MAC ACL is ``access-list mac NAME`` with ``SEQ permit|deny SRC DST ETHERTYPE [vlan V] [log]``; a MAC address with
  a mask is ``MAC/MASK`` (bits set are compared), applied with ``apply access-list mac NAME in|out``.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional, Tuple

from . import security as security_text
from .model import AclAction, CoppClass, Device, Interface, MacAcl, MacAclEntry, MacsecProfile
from .report import Report, Severity

KIND = security_text.KIND
COPP_POLICY = "RS-COPP"
# EOS CoPP class (after copp-system-) -> AOS-CX CoPP class, and the priority AOS-CX gives it
COPP_CLASSES: Dict[str, Tuple[str, int]] = {
    "bgp": ("bgp-ipv4", 6), "bfd": ("bfd", 6), "lacp": ("lacp", 6), "ospf": ("ospf-unicast-ipv4", 6),
    "arp": ("arp-broadcast", 4), "lldp": ("lldp", 5), "pim": ("pim", 5), "vrrp": ("vrrp", 6), "igmp": ("igmp", 5),
    "ipmcmiss": ("unknown-multicast", 1), "dhcp": ("dhcp", 3), "ptp": ("ptp", 6), "default": ("default", 1),
    "stp": ("stp", 6), "sflow": ("sflow", 2)}
_FROM_COPP = {v[0]: k for k, v in COPP_CLASSES.items()}
CIPHERS = {"aes128-gcm": "gcm-aes-128", "aes256-gcm": "gcm-aes-256", "aes128-gcm-xpn": "gcm-aes-xpn-128",
           "aes256-gcm-xpn": "gcm-aes-xpn-256"}
_FROM_CIPHER = {v: k for k, v in CIPHERS.items()}
ALL_ONES = "ff:ff:ff:ff:ff:ff"


# writing ------------------------------------------------------------------------------------------------------------

def control_plane(device: Device, report: Report, vrf: Callable[[str], str], ind: str) -> List[str]:
    cp = device.control_plane
    if cp is None:
        return []
    label = security_text.COPP
    report.item(KIND, label)
    lines: List[str] = []
    for name, acl in cp.acls.items():
        where = f" (VRF {name})" if name else ""
        if acl == security_text.EOS_DEFAULT_ACL:
            report.add(KIND, label, Severity.APPROX, "copp-default-acl",
                       f"the platform's default control-plane ACL{where} has no AOS-CX counterpart; AOS-CX guards "
                       "the CPU with its CoPP policy")
            continue
        if acl not in device.acls:
            report.add(KIND, label, Severity.REVIEW, "copp-acl", f"ACL {acl}{where} is not defined; not applied")
            continue
        lines.append(f"apply access-list ip {acl} control-plane vrf {vrf(name) if name else 'default'}")
    builtin = [c for c in cp.classes if not c.acl]
    own = [c for c in cp.classes if c.acl]
    body: List[str] = []
    left: List[str] = []
    for c in builtin:
        key = c.name[len("copp-system-"):] if c.name.startswith("copp-system-") else c.name
        cls = COPP_CLASSES.get(key)
        if cls is None or c.pps is None:
            left.append(f"{c.name} ({c.pps} pps)" if c.pps is not None else f"{c.name} ({c.kbps} kbit/s)")
            continue
        report.item(KIND, security_text.copp_label(c.name))
        body.append(f"{ind}class {cls[0]} priority {cls[1]} rate {c.pps}")
    if body:
        lines += [f"copp-policy {COPP_POLICY}"] + body + [f"apply copp-policy {COPP_POLICY}"]
        report.add(KIND, label, Severity.APPROX, "copp-classes",
                   f"the platform's CoPP classes are the classes of the same protocols in policy {COPP_POLICY}, with "
                   "the AOS-CX priorities and bursts; the classes not named keep the defaults of the default policy")
    if left:
        report.add(KIND, label, Severity.REVIEW, "copp-builtin",
                   "these CoPP classes have no AOS-CX class by name: " + ", ".join(left))
    if own:
        report.add(KIND, label, Severity.REVIEW, "copp-classes",
                   "CoPP classes that match an ACL (" + ", ".join(f"{c.name}: {c.acl}" for c in own) + ") are not "
                   "written: AOS-CX CoPP takes the platform's classes only; filter the traffic with a control-plane "
                   "ACL instead")
    return lines


def macsec(device: Device, report: Report, ind: str) -> List[str]:
    lines: List[str] = []
    for p in device.macsec_profiles.values():
        label = f"MACsec profile {p.name}"
        report.item(KIND, label)
        lines.append(f"macsec policy {p.name}")
        if p.cipher:
            lines.append(f"{ind}cipher-suite {CIPHERS[p.cipher]}")
        if p.sci:
            lines.append(f"{ind}include-sci-tag")
        lines.append(f"mka policy {p.name}")
        if p.ckn:
            lines.append(f"{ind}pre-shared-key ckn {p.ckn} cak plaintext {p.cak or security_text.PLACEHOLDER}")
            if not p.cak:
                report.add(KIND, label, Severity.REVIEW, "macsec-key",
                           f"the key is stored encrypted in the source; replace {security_text.PLACEHOLDER} with it")
        if p.key_server_priority is not None:
            lines.append(f"{ind}key-server-priority {p.key_server_priority}")
        lines.append(f"{ind}macsec-policy {p.name}")
        left = [w for w, v in ((f"the rekey period of {p.rekey_period} seconds", p.rekey_period is not None),
                               ("LLDP passing unencrypted", p.lldp_bypass)) if v]
        if left:
            report.add(KIND, label, Severity.APPROX, "macsec-options",
                       "; ".join(left) + ": left out, AOS-CX rekeys and treats LLDP itself")
        report.add(KIND, label, Severity.REVIEW, "macsec-platform",
                   "MACsec runs on some AOS-CX switches and ports only (with a licence on some); check the target "
                   "supports it")
    if device.macsec_fips:
        report.add(KIND, "MACsec", Severity.REVIEW, "macsec-fips",
                   "FIPS restrictions for MACsec are not written; AOS-CX enables FIPS mode for the whole switch")
    return lines


def _address(a: str) -> str:
    if a == "any":
        return "any"
    mac, wildcard = a.split()
    if wildcard == "00:00:00:00:00:00":
        return mac
    mask = ":".join(f"{0xFF ^ int(x, 16):02x}" for x in wildcard.split(":"))
    return f"{mac}/{mask}"


def mac_acl_lines(acl: MacAcl, report: Report, ind: str) -> List[str]:
    label = f"mac access-list {acl.name}"
    report.item("acl", label)
    lines = [f"access-list mac {acl.name}"]
    for n, e in enumerate(acl.entries, 1):
        seq = e.sequence or n * 10
        if e.action == AclAction.REMARK:
            lines.append(f"{ind}{seq} comment {e.remark}")
            continue
        words = [str(seq), e.action.value, _address(e.source), _address(e.destination),
                 "any" if e.ethertype is None else f"0x{e.ethertype:04x}"]
        if e.vlan is not None:
            words.append(f"vlan {e.vlan}")
        if e.log:
            words.append("log")
        lines.append(ind + " ".join(words))
    return lines


def mac_acl_interface(device: Device, iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
    lines = []
    for direction, name in (("in", iface.mac_acl_in), ("out", iface.mac_acl_out)):
        if name and name in device.mac_acls:
            lines.append(f"apply access-list mac {name} {direction}")
        elif name:
            add(Severity.REVIEW, "mac-acl", f"MAC ACL {name} is applied but not defined; left out")
    if iface.macsec_profile:
        if iface.macsec_profile in device.macsec_profiles:
            lines.append(f"apply mka policy {iface.macsec_profile}")
        else:
            add(Severity.REVIEW, "macsec", f"MACsec profile {iface.macsec_profile} is not defined; left out")
    return lines


# reading ------------------------------------------------------------------------------------------------------------

def _mac_word(word: str) -> str:
    """MAC, MAC/MASK or any -> the model's "MAC WILDCARD" form."""
    if word == "any":
        return "any"
    mac, _, mask = word.partition("/")
    mac = security_text._mac(mac)
    if not mask:
        return f"{mac} 00:00:00:00:00:00"
    wildcard = ":".join(f"{0xFF ^ int(x, 16):02x}" for x in security_text._mac(mask).split(":"))
    return f"{mac} {wildcard}"


def mac_acl_line(acl: MacAcl, w: List[str]) -> bool:
    """SEQ permit|deny SRC DST ETHERTYPE|any [vlan V] [log], or SEQ comment TEXT."""
    if not w[0].isdigit() or len(w) < 2:
        return False
    seq = int(w[0])
    if w[1] == "comment":
        acl.entries.append(MacAclEntry(AclAction.REMARK, seq, remark=" ".join(w[2:])))
        return True
    if w[1] not in ("permit", "deny") or len(w) < 5:
        return False
    e = MacAclEntry(AclAction(w[1]), seq, _mac_word(w[2]), _mac_word(w[3]))
    if w[4] != "any":
        e.ethertype = int(w[4], 16) if w[4].startswith("0x") else {"lldp": 0x88CC, "ipv4": 0x0800, "arp": 0x0806,
                                                                  "ipv6": 0x86DD}[w[4]]
    rest = w[5:]
    while rest:
        if rest[0] == "vlan" and len(rest) >= 2:
            e.vlan, rest = int(rest[1]), rest[2:]
        elif rest[0] == "log":
            e.log, rest = True, rest[1:]
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
        elif w == ["include-sci-tag"]:
            p.sci = True
        else:
            bad.append(n)
    return bad


def mka_policy(device: Device, name: str, children: List[List[str]]) -> List[int]:
    p = device.macsec_profiles.setdefault(name, MacsecProfile(name))
    bad = []
    for n, w in enumerate(children):
        if w[:2] == ["pre-shared-key", "ckn"] and len(w) == 6 and w[3] == "cak" and w[4] in ("plaintext",
                                                                                           "ciphertext"):
            p.ckn = w[2]
            p.cak = "" if w[4] == "ciphertext" or w[5] == security_text.PLACEHOLDER else w[5]
        elif w[0] == "key-server-priority" and len(w) == 2:
            p.key_server_priority = int(w[1])
        elif w[0] == "macsec-policy" and len(w) == 2:
            pass  # the MACsec policy of the same name
        else:
            bad.append(n)
    return bad


def copp_policy(device: Device, children: List[List[str]]) -> List[int]:
    cp = security_text.control_plane(device)
    bad = []
    for n, w in enumerate(children):
        if w[0] == "class" and len(w) == 6 and w[2] == "priority" and w[4] == "rate" and w[1] in _FROM_COPP:
            cp.classes.append(CoppClass(f"copp-system-{_FROM_COPP[w[1]]}", pps=int(w[5])))
        else:
            bad.append(n)
    return bad


def control_plane_acl(device: Device, w: List[str]) -> bool:
    """apply access-list ip NAME control-plane vrf V; apply copp-policy NAME."""
    if w[:3] == ["apply", "access-list", "ip"] and len(w) == 7 and w[4:6] == ["control-plane", "vrf"]:
        security_text.control_plane(device).acls["" if w[6] == "default" else w[6]] = w[3]
        return True
    return len(w) == 3 and w[:2] == ["apply", "copp-policy"]


def interface_line(device: Device, iface: Interface, w: List[str]) -> Optional[bool]:
    if w[:3] == ["apply", "access-list", "mac"] and len(w) == 5 and w[4] in ("in", "out"):
        setattr(iface, f"mac_acl_{w[4]}", w[3])
        return True
    if w[:3] == ["apply", "mka", "policy"] and len(w) == 4:
        iface.macsec_profile = w[3]
        return True
    return None

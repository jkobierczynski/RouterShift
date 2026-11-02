# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Device security beyond ACLs: control-plane policing, MACsec, MAC ACLs. The IOS and EOS reader and writer share
these helpers."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

from .model import AclAction, ControlPlane, CoppClass, Device, MacAcl, MacAclEntry, MacsecProfile
from .report import Report, Severity

KIND = "security"
COPP = "control-plane policing"
EOS_COPP_POLICY = "copp-system-policy"
EOS_DEFAULT_ACL = "default-control-plane-acl"
PLACEHOLDER = "CHANGE-ME"

_CIPHERS = {"aes128-gcm": "gcm-aes-128", "aes256-gcm": "gcm-aes-256", "aes128-gcm-xpn": "gcm-aes-xpn-128",
            "aes256-gcm-xpn": "gcm-aes-xpn-256"}
_IOS_CIPHERS = {v: k for k, v in _CIPHERS.items()}


def control_plane(device: Device) -> ControlPlane:
    if device.control_plane is None:
        device.control_plane = ControlPlane()
    return device.control_plane


def copp_label(name: str) -> str:
    return f"{COPP} class {name}"


# CoPP ----------------------------------------------------------------------------------------------------------------

def eos_copp_class_line(cls: CoppClass, w: List[str]) -> bool:
    """EOS policy-map type copp / class C: shape|bandwidth pps|kbps N."""
    if w[0] in ("shape", "bandwidth") and len(w) == 3 and w[1] in ("pps", "kbps"):
        setattr(cls, w[1], int(w[2]))
        return True
    return False


def ios_police(cls: CoppClass, w: List[str]) -> bool:
    """IOS: police [cir] BPS [bc N] [conform-action X] [exceed-action Y] [violate-action Z] | police rate N pps."""
    if w[:2] == ["police", "rate"] and len(w) == 4 and w[3] == "pps":
        cls.pps = int(w[2])
        return True
    args = w[1:]
    if args[:1] == ["cir"]:
        args = args[1:]
    if not args or not args[0].isdigit():
        return False
    cls.kbps = max(1, int(args[0]) // 1000)
    args = args[1:]
    while args:
        if args[0] in ("bc", "be") and len(args) >= 2 or \
                args[0] in ("conform-action", "exceed-action", "violate-action") and len(args) >= 2:
            args = args[2:]
        elif args[0].isdigit():
            args = args[1:]
        else:
            return False
    return True


def eos_lines(device: Device, report: Report, ind: str, vrf_name) -> List[str]:  # type: ignore[no-untyped-def]
    cp = device.control_plane
    if cp is None:
        return []
    lines: List[str] = []
    if cp.acls:
        report.item(KIND, COPP)
        lines.append("system control-plane")
        for vrf, acl in cp.acls.items():
            lines.append(f"{ind}ip access-group {acl}" + (f" vrf {vrf_name(vrf)}" if vrf else "") + " in")
        lines.append("!")
    if cp.classes:
        for c in cp.classes:
            report.item(KIND, copp_label(c.name))
            if c.acl:
                lines += [f"class-map type copp match-any {c.name}", f"{ind}match ip access-group {c.acl}", "!"]
        lines.append(f"policy-map type copp {EOS_COPP_POLICY}")
        for c in cp.classes:
            lines.append(f"{ind}class {c.name}")
            if c.pps is not None:
                lines.append(f"{ind * 2}shape pps {c.pps}")
            elif c.kbps is not None:
                lines.append(f"{ind * 2}shape kbps {c.kbps}")
                if device.platform != "eos":
                    report.add(KIND, copp_label(c.name), Severity.APPROX, "copp-rate",
                               f"the policer of {c.kbps} kbit/s is written as a shaper (EOS limits control-plane "
                               "classes by shaping); check the platform takes kbps, others count packets")
        lines.append("!")
        if device.platform != "eos" and cp.policy and cp.policy != EOS_COPP_POLICY:
            report.add(KIND, COPP, Severity.APPROX, "copp-policy",
                       f"policy {cp.policy} becomes classes of {EOS_COPP_POLICY}, the one policy EOS applies to the "
                       "control plane; the platform's own classes keep their defaults")
    return lines


def ios_lines(device: Device, report: Report, vrf_name) -> List[str]:  # type: ignore[no-untyped-def]
    cp = device.control_plane
    if cp is None:
        return []
    lines: List[str] = []
    report.item(KIND, COPP)
    for vrf, acl in cp.acls.items():
        where = f" (VRF {vrf_name(vrf)})" if vrf else ""
        if acl == EOS_DEFAULT_ACL:
            report.add(KIND, COPP, Severity.APPROX, "copp-default-acl",
                       f"the platform's default control-plane ACL{where} has no IOS equivalent; IOS XE protects the "
                       "CPU with its system CoPP policy")
        else:
            report.add(KIND, COPP, Severity.REVIEW, "copp-acl",
                       f"IOS takes no ACL on the control plane: ACL {acl}{where} is written but not applied; apply it "
                       "as 'access-class' on the vty lines for management logins, or match it in a CoPP class")
    own = [c for c in cp.classes if c.acl]
    builtin = [c for c in cp.classes if not c.acl]
    if builtin:
        report.add(KIND, COPP, Severity.REVIEW, "copp-builtin",
                   "the platform's own CoPP classes have no IOS counterpart by name: " + ", ".join(
                       f"{c.name} ({c.pps} pps)" if c.pps is not None else f"{c.name} ({c.kbps} kbit/s)"
                       for c in builtin) + "; set the rates in the matching classes of system-cpp-policy "
                   "(policy-map system-cpp-policy / class system-cpp-police-... / police rate N pps)")
    if own:
        name = cp.policy if cp.policy and cp.policy != EOS_COPP_POLICY else "RS-COPP"
        for c in own:
            report.item(KIND, copp_label(c.name))
            lines += [f"class-map match-any {c.name}", f" match access-group name {c.acl}", "!"]
        lines.append(f"policy-map {name}")
        for c in own:
            lines.append(f" class {c.name}")
            if c.pps is not None:
                lines.append(f"  police rate {c.pps} pps")
            elif c.kbps is not None:
                lines.append(f"  police cir {c.kbps * 1000} conform-action transmit exceed-action drop")
        lines += ["!", "control-plane", f" service-policy input {name}", "!"]
    return lines


# MACsec --------------------------------------------------------------------------------------------------------------

def eos_profile_line(p: MacsecProfile, w: List[str]) -> bool:
    n = len(w)
    if w[0] == "cipher" and n == 2 and w[1] in _CIPHERS:
        p.cipher = w[1]
    elif w[0] == "key" and n in (3, 4):
        p.ckn = w[1]
        if n == 3:
            p.cak = w[2]  # clear text
        else:
            p.cak = w[3] if w[2] == "0" else ""  # type 7: encrypted
    elif w[:3] == ["mka", "key-server", "priority"] and n == 4:
        p.key_server_priority = int(w[3])
    elif w[:3] == ["mka", "session", "rekey-period"] and n == 4:
        p.rekey_period = int(w[3])
    elif w == ["sci"]:
        p.sci = True
    elif w == ["l2-protocol", "lldp", "bypass"]:
        p.lldp_bypass = True
    else:
        return False
    return True


def ios_mka_line(p: MacsecProfile, w: List[str]) -> bool:
    n = len(w)
    if w[:2] == ["key-server", "priority"] and n == 3:
        p.key_server_priority = int(w[2])
    elif w[:2] == ["sak-rekey", "interval"] and n == 3:
        p.rekey_period = int(w[2])
    elif w[0] == "macsec-cipher-suite" and n >= 2 and w[1] in _IOS_CIPHERS:
        p.cipher = _IOS_CIPHERS[w[1]]
    elif w == ["include-icv-indicator"] or w == ["send-secure-announcements"]:
        pass
    else:
        return False
    return True


def keychain_name(profile: str) -> str:
    return f"KC-{profile}"


def eos_macsec_lines(device: Device, report: Report, ind: str) -> List[str]:
    if not device.macsec_profiles:
        return []
    lines = ["mac security"]
    if device.macsec_fips:
        lines.append(f"{ind}fips restrictions")
    for p in device.macsec_profiles.values():
        label = f"MACsec profile {p.name}"
        report.item(KIND, label)
        lines.append(f"{ind}profile {p.name}")
        if p.cipher:
            lines.append(f"{ind * 2}cipher {p.cipher}")
        if p.ckn:
            lines.append(f"{ind * 2}key {p.ckn} 0 {p.cak or PLACEHOLDER}")
            if not p.cak:
                report.add(KIND, label, Severity.REVIEW, "macsec-key",
                           f"the key is stored encrypted in the source; replace {PLACEHOLDER} with it")
        if p.key_server_priority is not None:
            lines.append(f"{ind * 2}mka key-server priority {p.key_server_priority}")
        if p.rekey_period is not None:
            lines.append(f"{ind * 2}mka session rekey-period {p.rekey_period}")
        if p.sci:
            lines.append(f"{ind * 2}sci")
        if p.lldp_bypass:
            lines.append(f"{ind * 2}l2-protocol lldp bypass")
    return lines + ["!"]


def ios_macsec_lines(device: Device, report: Report) -> List[str]:
    lines: List[str] = []
    for p in device.macsec_profiles.values():
        label = f"MACsec profile {p.name}"
        report.item(KIND, label)
        if p.ckn:
            bits = "256" if "256" in p.cipher else "128"
            lines += [f"key chain {keychain_name(p.name)} macsec", f" key {p.ckn}",
                      f"  cryptographic-algorithm aes-{bits}-cmac", f"  key-string {p.cak or PLACEHOLDER}", "!"]
            if not p.cak:
                report.add(KIND, label, Severity.REVIEW, "macsec-key",
                           f"the key is stored encrypted in the source; replace {PLACEHOLDER} in key chain "
                           f"{keychain_name(p.name)} with it")
        lines.append(f"mka policy {p.name}")
        if p.key_server_priority is not None:
            lines.append(f" key-server priority {p.key_server_priority}")
        if p.rekey_period is not None:
            lines.append(f" sak-rekey interval {p.rekey_period}")
        if p.cipher:
            lines.append(f" macsec-cipher-suite {_CIPHERS[p.cipher]}")
        lines.append("!")
        left = [w for w, v in (("sending the SCI in every frame (sci)", p.sci),
                               ("LLDP passing unencrypted (l2-protocol lldp bypass)", p.lldp_bypass)) if v]
        if left:
            report.add(KIND, label, Severity.APPROX, "macsec-options",
                       "; ".join(left) + ": IOS XE has no such setting on the MKA policy and decides itself")
    if device.macsec_fips:
        report.add(KIND, "MACsec", Severity.REVIEW, "macsec-fips",
                   "FIPS restrictions for MACsec are not written; IOS XE enables FIPS mode device-wide "
                   "(fips authorization-key)")
    return lines


# MAC ACLs ------------------------------------------------------------------------------------------------------------

def _mac(text: str) -> str:
    digits = re.sub(r"[.:-]", "", text).lower()
    if len(digits) != 12 or not re.match(r"^[0-9a-f]+$", digits):
        raise ValueError(text)
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _ios_mac(colon: str) -> str:
    d = colon.replace(":", "")
    return f"{d[0:4]}.{d[4:8]}.{d[8:12]}"


def _address(words: List[str]) -> Tuple[str, List[str]]:
    if words[0] == "any":
        return "any", words[1:]
    if words[0] == "host":
        return f"{_mac(words[1])} 00:00:00:00:00:00", words[2:]
    return f"{_mac(words[0])} {_mac(words[1])}", words[2:]


def mac_acl_line(acl: MacAcl, w: List[str], ios: bool) -> bool:
    """EOS: [seq] permit|deny SRC DST [vlan V MASK] [protocol 0xNNNN] [log];
    IOS: permit|deny SRC DST [0xNNNN MASK | etype-name] [vlan V] [log]."""
    seq: Optional[int] = None
    if w[0].isdigit():
        seq, w = int(w[0]), w[1:]
    if w[0] == "remark":
        acl.entries.append(MacAclEntry(AclAction.REMARK, seq, remark=" ".join(w[1:])))
        return True
    if w[0] not in ("permit", "deny"):
        return False
    entry = MacAclEntry(AclAction(w[0]), seq)
    entry.source, rest = _address(w[1:])
    entry.destination, rest = _address(rest)
    while rest:
        if rest[0] == "vlan" and len(rest) >= 2:
            entry.vlan = int(rest[1])
            rest = rest[3:] if not ios and len(rest) >= 3 and rest[2].startswith("0x") else rest[2:]
        elif rest[0] == "protocol" and len(rest) >= 2:
            entry.ethertype, rest = int(rest[1], 16), rest[2:]
        elif ios and rest[0].startswith("0x") and len(rest) >= 2:
            if int(rest[1], 16) != 0:
                return False
            entry.ethertype, rest = int(rest[0], 16), rest[2:]
        elif rest[0] == "lldp":
            entry.ethertype, rest = 0x88CC, rest[1:]
        elif rest[0] == "log":
            entry.log, rest = True, rest[1:]
        else:
            return False
    acl.entries.append(entry)
    return True


def mac_acl_lines(acl: MacAcl, ios: bool, report: Report) -> List[str]:
    label = f"mac access-list {acl.name}"
    report.item("acl", label)
    lines = [f"mac access-list extended {acl.name}" if ios else f"mac access-list {acl.name}"]
    for n, e in enumerate(acl.entries, 1):
        seq = e.sequence or n * 10
        if e.action == AclAction.REMARK:
            lines.append(f" remark {e.remark}" if ios else f"   {seq} remark {e.remark}")
            continue

        def addr(a: str) -> str:
            if a == "any":
                return "any"
            mac, mask = a.split()
            if ios:
                return f"host {_ios_mac(mac)}" if mask == "00:00:00:00:00:00" else f"{_ios_mac(mac)} {_ios_mac(mask)}"
            return f"{mac} {mask}"

        words = [e.action.value, addr(e.source), addr(e.destination)]
        if ios:
            if e.ethertype is not None:
                words.append(f"0x{e.ethertype:X} 0x0")
            if e.vlan is not None:
                words.append(f"vlan {e.vlan}")
                report.add("acl", label, Severity.APPROX, "mac-acl-vlan",
                           "the VLAN of an entry is written as 'vlan N'; check the Catalyst model takes it")
        else:
            if e.vlan is not None:
                words.append(f"vlan {e.vlan} 0xfff")
            if e.ethertype is not None:
                words.append(f"protocol 0x{e.ethertype:x}")
        if e.log:
            words.append("log")
        lines.append((" " if ios else f"   {seq} ") + " ".join(words))
    return lines + ["!"]

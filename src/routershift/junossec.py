# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos device security: control-plane protection, MACsec, MAC ACLs and RADIUS change of authorization.

How the model maps to Junos:

* A control-plane ACL is the input filter of the loopback (``lo0.0``), which guards everything sent to the routing
  engine; the management VRF's is the input filter of the management port ``me0``. EOS's built-in
  ``default-control-plane-acl`` has no Junos counterpart.
* The platform's own CoPP classes (EOS ``copp-system-bgp`` ...) are DDoS protection policers of the matching protocol
  group (``system ddos-protection protocols bgp aggregate bandwidth N``, in packets per second).
* A MACsec profile is a connectivity association with a static CAK (``security macsec connectivity-association``).
* A MAC ACL is an ``ethernet-switching`` filter that matches MAC addresses, the EtherType and the VLAN.
* Change of authorization is the RADIUS disconnect port (``access radius-disconnect-port 3799``).
"""

from __future__ import annotations

from typing import Callable, Dict, List, Optional

from . import security as security_text
from .junospolicy import MAC_MATCHES, Policy
from .model import AclAction, CoppClass, Device, MacAcl, MacAclEntry, MacsecProfile
from .report import Report, Severity

KIND = security_text.KIND
COA_PORT = 3799
# EOS CoPP class (after copp-system-) -> Junos DDoS protection protocol path
DDOS = {"bgp": ("bgp", "aggregate"), "bfd": ("bfd", "aggregate"), "lacp": ("lacp", "aggregate"),
        "ospf": ("ospf", "aggregate"), "arp": ("arp", "aggregate"), "lldp": ("lldp", "aggregate"),
        "pim": ("pim", "aggregate"), "vrrp": ("vrrp", "aggregate"), "igmp": ("igmp", "aggregate"),
        "ipmcmiss": ("resolve", "mcast-v4"), "dhcp": ("dhcpv4", "aggregate"), "ptp": ("ptp", "aggregate")}
_FROM_DDOS = {v: k for k, v in DDOS.items()}
CIPHERS = {"aes128-gcm": "gcm-aes-128", "aes256-gcm": "gcm-aes-256", "aes128-gcm-xpn": "gcm-aes-xpn-128",
           "aes256-gcm-xpn": "gcm-aes-xpn-256"}
_FROM_CIPHER = {v: k for k, v in CIPHERS.items()}

Add = Callable[..., None]


# writing ------------------------------------------------------------------------------------------------------------

def control_plane(device: Device, add: Add, apply: Callable[[str, str], None], report: Report, mgmt_vrfs: List[str],
                  loopback_unit: Callable[[str], Optional[str]], filter_name: Callable[[str], str]) -> None:
    """The control-plane ACLs (applied through ``apply(unit, filter)``) and the platform's CoPP classes."""
    cp = device.control_plane
    if cp is None:
        return
    label = security_text.COPP
    report.item(KIND, label)
    for vrf, acl in cp.acls.items():
        where = f" (VRF {vrf})" if vrf else ""
        if acl == security_text.EOS_DEFAULT_ACL:
            report.add(KIND, label, Severity.APPROX, "copp-default-acl",
                       f"the platform's default control-plane ACL{where} has no Junos counterpart; Junos guards the "
                       "routing engine with the loopback's input filter, which RouterShift writes only for ACLs of "
                       "the source")
            continue
        if not vrf:
            apply("lo0.0", filter_name(acl))
        elif vrf in mgmt_vrfs:
            apply("me0.0", filter_name(acl))
            report.add(KIND, label, Severity.APPROX, "copp-mgmt",
                       f"ACL {acl}{where} is the input filter of the management port me0, which takes the management "
                       "VRF's traffic to the switch")
        else:
            unit = loopback_unit(vrf)
            if unit is None:
                report.add(KIND, label, Severity.REVIEW, "copp-vrf",
                           f"ACL {acl}{where}: Junos guards a VRF with the input filter of a loopback unit in it, and "
                           "the VRF has none; not applied")
                continue
            apply(f"lo0.{unit}", filter_name(acl))
    builtin = [c for c in cp.classes if not c.acl]
    own = [c for c in cp.classes if c.acl]
    left = []
    for c in builtin:
        key = c.name[len("copp-system-"):] if c.name.startswith("copp-system-") else c.name
        path = DDOS.get(key)
        if path is None or c.pps is None:
            left.append(f"{c.name} ({c.pps} pps)" if c.pps is not None else f"{c.name} ({c.kbps} kbit/s)")
            continue
        report.item(KIND, security_text.copp_label(c.name))
        add("system", "ddos-protection", "protocols", path[0], path[1], f"bandwidth {c.pps}")
    if builtin and len(left) < len(builtin):
        report.add(KIND, label, Severity.APPROX, "copp-ddos",
                   "the platform's CoPP classes are DDoS protection policers of the matching protocol groups (packets "
                   "per second); their bursts keep the Junos defaults")
    if left:
        report.add(KIND, label, Severity.REVIEW, "copp-builtin",
                   "these CoPP classes have no Junos DDoS protection group by name: " + ", ".join(left))
    if own:
        report.add(KIND, label, Severity.REVIEW, "copp-classes",
                   "CoPP classes that match an ACL (" + ", ".join(f"{c.name}: {c.acl}" for c in own) + ") are not "
                   "written; police them with policer terms in the loopback's input filter")


def macsec(device: Device, add: Add, report: Report, port: Callable[[str], str]) -> None:
    for p in device.macsec_profiles.values():
        label = f"MACsec profile {p.name}"
        report.item(KIND, label)
        base = ("security", "macsec", f"connectivity-association {p.name}")
        if p.cipher:
            add(*base, f"cipher-suite {CIPHERS[p.cipher]}")
        add(*base, "security-mode static-cak")
        if p.ckn:
            add(*base, "pre-shared-key", f"ckn {p.ckn}")
            add(*base, "pre-shared-key", f"cak {p.cak or security_text.PLACEHOLDER}")
            if not p.cak:
                report.add(KIND, label, Severity.REVIEW, "macsec-key",
                           f"the key is stored encrypted in the source; replace {security_text.PLACEHOLDER} with it")
        if p.key_server_priority is not None:
            add(*base, "mka", f"key-server-priority {p.key_server_priority}")
        if p.rekey_period is not None:
            add(*base, f"sak-rekey-interval {p.rekey_period}")
        if p.sci:
            add(*base, "include-sci")
        if p.lldp_bypass:
            add(*base, "exclude-protocol lldp")
    for iface in device.interfaces.values():
        if iface.macsec_profile:
            add("security", "macsec", f"interfaces {port(iface.name)}",
                f"connectivity-association {iface.macsec_profile}")
    if device.macsec_fips:
        report.add(KIND, "MACsec", Severity.REVIEW, "macsec-fips",
                   "FIPS restrictions for MACsec are not written: FIPS is a mode of the whole Junos install (Junos "
                   "FIPS edition, 'request system fips')")


def _mac_word(address: str, label: str, report: Report) -> Optional[str]:
    """EOS 'MAC MASK' (wildcard bits set) as a Junos MAC prefix, or None when the mask is not a prefix."""
    mac, mask = address.split()
    wildcard = int(mask.replace(":", ""), 16)
    ones = bin(wildcard).count("1")
    if wildcard != (1 << ones) - 1:
        report.add("acl", label, Severity.REVIEW, "mac-mask",
                   f"the mask {mask} does not cover a run of trailing bits; Junos matches MAC prefixes only")
        return None
    return mac if ones == 0 else f"{mac}/{48 - ones}"


def mac_filters(device: Device, add: Add, report: Report) -> None:
    for acl in device.mac_acls.values():
        label = f"mac access-list {acl.name}"
        report.item("acl", label)
        base = ("firewall", "family ethernet-switching", f"filter {acl.name}")
        remarks = 0
        for n, e in enumerate(acl.entries, 1):
            if e.action == AclAction.REMARK:
                remarks += 1
                continue
            term = base + (f"term {e.sequence or n * 10}",)
            ok = True
            for key, address in (("source-mac-address", e.source), ("destination-mac-address", e.destination)):
                if address != "any":
                    word = _mac_word(address, label, report)
                    if word is None:
                        ok = False
                    else:
                        add(*term, "from", f"{key} {word}")
            if not ok:
                continue
            if e.ethertype is not None:
                add(*term, "from", f"ether-type 0x{e.ethertype:04x}")
            if e.vlan is not None:
                add(*term, "from", f"learn-vlan-id {e.vlan}")
            if e.log:
                add(*term, "then", "log")
            add(*term, "then", "accept" if e.action == AclAction.PERMIT else "discard")
        if remarks:
            report.add("acl", label, Severity.APPROX, "acl-remark",
                       "Junos filter terms have no remarks; the remarks are left out")


def coa(device: Device, add: Add, report: Report) -> None:
    if not device.aaa.coa:
        return
    label = "RADIUS change of authorization"
    report.item("management", label)
    add("access", f"radius-disconnect-port {COA_PORT}")
    report.add("management", label, Severity.REVIEW, "coa-clients",
               "add the RADIUS servers that may send changes as 'access radius-disconnect ADDRESS secret KEY'")


# reading ------------------------------------------------------------------------------------------------------------

def is_mac_filter(policy: Policy) -> bool:
    return any(f and f[0] in MAC_MATCHES for term in policy.terms.values() for f in term.froms)


def read_mac_filter(device: Device, policy: Policy, unread: Callable[[int, str, str], None]) -> None:
    acl = device.mac_acls.setdefault(policy.name, MacAcl(policy.name))
    acl.origin.line = policy.line
    for term in policy.terms.values():
        seq = int(term.name) if term.name.isdigit() else None
        entry = MacAclEntry(AclAction.PERMIT, seq)
        ok = True
        for t in term.thens:
            if t == ["accept"]:
                entry.action = AclAction.PERMIT
            elif t in (["discard"], ["reject"]):
                entry.action = AclAction.DENY
            elif t in (["log"], ["syslog"]):
                entry.log = True
            elif t[0] != "count":
                ok = False
        for f in term.froms:
            if f[0] in ("source-mac-address", "destination-mac-address") and len(f) == 2:
                mac, _, length = f[1].partition("/")
                bits = 48 - int(length) if length else 0
                mask = format((1 << bits) - 1, "012x")
                value = f"{security_text._mac(mac)} {':'.join(mask[i:i + 2] for i in range(0, 12, 2))}"
                if f[0] == "source-mac-address":
                    entry.source = value
                else:
                    entry.destination = value
            elif f[0] == "ether-type" and len(f) == 2:
                named = {"lldp": 0x88CC, "arp": 0x0806, "ipv4": 0x0800, "ipv6": 0x86DD}
                entry.ethertype = named.get(f[1]) or int(f[1], 16 if f[1].startswith("0x") else 10)
            elif f[0] in ("learn-vlan-id", "user-vlan-id") and len(f) == 2:
                entry.vlan = int(f[1])
            else:
                ok = False
        if not ok:
            unread(term.line, f"set firewall family ethernet-switching filter {policy.name} term {term.name}",
                   "a MAC filter term RouterShift cannot hold")
            continue
        acl.entries.append(entry)


def read_ddos(device: Device, w: List[str]) -> bool:
    """system ddos-protection protocols P SUB bandwidth N (w starts after 'protocols')."""
    if len(w) == 4 and w[2] == "bandwidth" and w[3].isdigit():
        key = _FROM_DDOS.get((w[0], w[1]))
        if key is None:
            return False
        cp = security_text.control_plane(device)
        cp.policy = cp.policy or security_text.EOS_COPP_POLICY
        cp.classes.append(CoppClass(f"copp-system-{key}", pps=int(w[3])))
        return True
    return False


def read_macsec(device: Device, w: List[str], profiles_of: Dict[str, str]) -> bool:
    """security macsec ... (w starts after 'macsec'). profiles_of collects port -> profile."""
    if w[0] == "connectivity-association" and len(w) >= 3:
        p = device.macsec_profiles.setdefault(w[1], MacsecProfile(w[1]))
        rest = w[2:]
        if rest[0] == "cipher-suite" and len(rest) == 2 and rest[1] in _FROM_CIPHER:
            p.cipher = _FROM_CIPHER[rest[1]]
        elif rest == ["security-mode", "static-cak"]:
            pass
        elif rest[:2] == ["pre-shared-key", "ckn"] and len(rest) == 3:
            p.ckn = rest[2]
        elif rest[:2] == ["pre-shared-key", "cak"] and len(rest) == 3:
            p.cak = "" if rest[2] in (security_text.PLACEHOLDER,) or rest[2].startswith("$9$") else rest[2]
        elif rest[:2] == ["mka", "key-server-priority"] and len(rest) == 3:
            p.key_server_priority = int(rest[2])
        elif rest[0] == "sak-rekey-interval" and len(rest) == 2:
            p.rekey_period = int(rest[1])
        elif rest == ["include-sci"]:
            p.sci = True
        elif rest == ["exclude-protocol", "lldp"]:
            p.lldp_bypass = True
        else:
            return False
        return True
    if w[0] == "interfaces" and len(w) == 4 and w[2] == "connectivity-association":
        profiles_of[w[1]] = w[3]
        return True
    return False

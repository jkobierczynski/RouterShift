# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Comware 7 security, queuing and multicast beyond the basics: MACsec (MKA policies and pre-shared keys), MAC ACLs,
interface hardening (uRPF, proxy ARP), unnumbered addresses, SVI MACs, the 802.1X fail VLAN, RADIUS dynamic
authorization; the DSCP to local-precedence map and queue scheduling profiles (qmprofile); PIM rendezvous points for
group ranges, anycast RP, MSDP, multicast in VPN instances and the IGMP snooping querier. Written and read; what Comware
has no form for is reported."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .aaa import PLACEHOLDER
from .model import (AclAction, Device, Interface, MacAcl, MacAclEntry, MacsecProfile, QosProfile, QosQueue,
                    VrfMulticast)
from .report import Report, Severity

IND = " "
Add = Callable[[Severity, str, str], None]
_CIPHERS = {"aes128-gcm": "gcm-aes-128", "aes256-gcm": "gcm-aes-256", "aes128-gcm-xpn": "gcm-aes-xpn-128",
            "aes256-gcm-xpn": "gcm-aes-xpn-256"}
RP_ACL_BASE = 2990  # basic ACLs that name the groups of the rendezvous points, numbered down from here


# MACsec ------------------------------------------------------------------------------------------------------------

def macsec_lines(device: Device, report: Report) -> List[str]:
    out: List[str] = []
    for p in device.macsec_profiles.values():
        label = f"MACsec profile {p.name}"
        report.item("security", label)
        body = []
        if p.cipher:
            body.append(f"macsec cipher-suite {_CIPHERS.get(p.cipher, 'gcm-aes-128')}")
            if p.cipher not in _CIPHERS:
                report.add("security", label, Severity.APPROX, "macsec-cipher",
                           f"cipher {p.cipher} is written as GCM-AES-128")
        if p.sci:
            body.append("send-sci")
        if p.rekey_period is not None:
            report.add("security", label, Severity.APPROX, "macsec-rekey",
                       f"Comware renews the SAK by packet number; the rekey period of {p.rekey_period} s is left out")
        if p.lldp_bypass:
            report.add("security", label, Severity.APPROX, "macsec-lldp",
                       "LLDP passing unencrypted has no Comware setting; left out")
        out += [f"mka policy {p.name}"] + [IND + b for b in body] + ["#"]
    if device.macsec_fips:
        report.add("security", "MACsec", Severity.APPROX, "macsec-fips", "the FIPS restrictions are left out")
    return out


def macsec_interface(device: Device, iface: Interface, add: Add) -> List[str]:
    if not iface.macsec_profile:
        return []
    p = device.macsec_profiles.get(iface.macsec_profile)
    if p is None:
        add(Severity.REVIEW, "macsec-missing", f"MACsec profile {iface.macsec_profile} is not defined; left out")
        return []
    lines = ["mka enable"]
    if p.ckn:
        if not p.cak:
            add(Severity.REVIEW, "secret-placeholder",
                f"the MACsec key is stored encrypted in the source; replace {PLACEHOLDER} with it")
        lines.append(f"mka psk ckn {p.ckn} cak simple {p.cak or PLACEHOLDER}")
    if p.key_server_priority is not None:
        lines.append(f"mka priority {p.key_server_priority}")
    lines += [f"mka apply policy {p.name}", "macsec desire"]
    return lines


def read_mka_policy(device: Device, name: str, children: List[List[str]]) -> List[int]:
    """mka policy NAME; the indexes of the lines not read."""
    p = device.macsec_profiles.setdefault(name, MacsecProfile(name))
    left = []
    ciphers = {v: k for k, v in _CIPHERS.items()}
    for n, w in enumerate(children):
        if w[:2] == ["macsec", "cipher-suite"] and len(w) == 3 and w[2] in ciphers:
            p.cipher = ciphers[w[2]]
        elif w == ["send-sci"]:
            p.sci = True
        else:
            left.append(n)
    return left


def read_mka_interface(device: Device, iface: Interface, w: List[str], psk: Dict[str, Tuple[str, str, int]]) -> bool:
    if w == ["mka", "enable"] or w == ["macsec", "desire"]:
        return True
    if w[:3] == ["mka", "psk", "ckn"] and len(w) == 7 and w[4] == "cak" and w[5] in ("simple", "cipher"):
        psk[iface.name] = (w[3], w[6] if w[5] == "simple" and w[6] != PLACEHOLDER else "", -1)
        return True
    if w[:2] == ["mka", "priority"] and len(w) == 3:
        ckn, cak, _ = psk.get(iface.name, ("", "", -1))
        psk[iface.name] = (ckn, cak, int(w[2]))
        return True
    if w[:3] == ["mka", "apply", "policy"] and len(w) == 4:
        iface.macsec_profile = w[3]
        return True
    return False


def finish_mka(device: Device, psk: Dict[str, Tuple[str, str, int]]) -> None:
    for name, (ckn, cak, priority) in psk.items():
        iface = device.interfaces.get(name)
        p = device.macsec_profiles.get(iface.macsec_profile) if iface is not None else None
        if p is None:
            continue
        p.ckn, p.cak = p.ckn or ckn, p.cak or cak
        if priority >= 0:
            p.key_server_priority = priority


# MAC ACLs ----------------------------------------------------------------------------------------------------------

def _mac(text: str) -> str:
    digits = text.replace(":", "").replace(".", "").replace("-", "").lower()
    return f"{digits[0:4]}-{digits[4:8]}-{digits[8:12]}"


def _colon(text: str) -> str:
    digits = text.replace("-", "").lower()
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _wildcard(mask: str) -> str:
    """The model's MAC mask (EOS: 1 bits ignore) as Comware's (1 bits match)."""
    digits = mask.replace(":", "")
    return _mac(f"{int(digits, 16) ^ 0xFFFFFFFFFFFF:012x}")


def mac_acl_lines(device: Device, report: Report) -> List[str]:
    out: List[str] = []
    for acl in device.mac_acls.values():
        label = f"mac access-list {acl.name}"
        report.item("acl", label)
        body = []
        seq = 0
        for e in acl.entries:
            if e.action == AclAction.REMARK or e.remark:
                continue
            seq = e.sequence if e.sequence is not None else seq + 5
            words = [f"rule {seq}", e.action.value]
            for side, value in (("source-mac", e.source), ("dest-mac", e.destination)):
                if value != "any":
                    address, mask = value.split()
                    words += [side, _mac(address), _wildcard(mask)]
            if e.ethertype is not None:
                words += ["type", f"{e.ethertype:04x}", "ffff"]
            if e.vlan is not None or e.log:
                report.add("acl", label, Severity.APPROX, "mac-acl",
                           f"rule {seq}: Comware's MAC ACLs match no VLAN and do not log; written without them")
            body.append(" ".join(words))
        out += [f"acl mac name {acl.name}"] + [IND + b for b in body] + ["#"]
    return out


def mac_acl_interface(device: Device, iface: Interface, add: Add) -> List[str]:
    lines = []
    for name, direction in ((iface.mac_acl_in, "inbound"), (iface.mac_acl_out, "outbound")):
        if name and name in device.mac_acls:
            lines.append(f"packet-filter mac name {name} {direction}")
        elif name:
            add(Severity.REVIEW, "acl-missing", f"MAC ACL {name} is applied but not defined; left out")
    return lines


def read_mac_acl(device: Device, name: str, children: List[List[str]]) -> List[int]:
    acl = device.mac_acls.setdefault(name, MacAcl(name))
    left = []
    for n, w in enumerate(children):
        if w[0] != "rule" or len(w) < 3 or not w[1].isdigit() or w[2] not in ("permit", "deny"):
            left.append(n)
            continue
        e = MacAclEntry(AclAction(w[2]), int(w[1]))
        args = w[3:]
        ok = True
        while args:
            if args[0] in ("source-mac", "dest-mac") and len(args) >= 3:
                mask = _colon(args[2])
                inverted = f"{int(mask.replace(':', ''), 16) ^ 0xFFFFFFFFFFFF:012x}"
                value = f"{_colon(args[1])} {':'.join(inverted[i:i + 2] for i in range(0, 12, 2))}"
                if args[0] == "source-mac":
                    e.source = value
                else:
                    e.destination = value
                args = args[3:]
            elif args[0] == "type" and len(args) >= 3 and args[2] == "ffff":
                e.ethertype = int(args[1], 16)
                args = args[3:]
            else:
                ok = False
                break
        if ok:
            acl.entries.append(e)
        else:
            left.append(n)
    return left


# interface settings ------------------------------------------------------------------------------------------------

def interface_lines(device: Device, iface: Interface, add: Add, port: Callable[[str], str],
                    gateway: bool) -> List[str]:
    lines: List[str] = []
    if iface.unnumbered:
        lines.append(f"ip address unnumbered interface {port(iface.unnumbered)}")
    if iface.mac_address and not gateway:
        digits = iface.mac_address.replace(":", "").replace(".", "").lower()
        lines.append(f"mac-address {digits[0:4]}-{digits[4:8]}-{digits[8:12]}")
    if iface.urpf:
        lines.append(f"ip urpf {iface.urpf}")
    if iface.proxy_arp:
        lines.append("proxy-arp enable")
    if iface.ip_redirects is not None or iface.ip_unreachables is not None:
        add(Severity.APPROX, "hardening", "Comware sends ICMP redirects and unreachables by a global setting "
                                          "('ip redirects enable', 'ip unreachables enable'); the port's own choice "
                                          "is not written")
    if iface.autostate is False:
        add(Severity.APPROX, "autostate", "Comware has no 'no autostate': a VLAN interface follows its VLAN's ports")
    if iface.dot1x_fail_vlan is not None:
        lines.append(f"dot1x auth-fail vlan {iface.dot1x_fail_vlan}")
    if iface.helper_addresses and (iface.helper_vrf or iface.helper_source):
        add(Severity.REVIEW, "relay-vrf",
            "the DHCP relay's server VRF and source interface are not written: Comware relays into another VPN "
            "instance with 'dhcp relay server-address A vpn-instance V' on the models that have it; set it by hand")
    lines += mac_acl_interface(device, iface, add)
    lines += macsec_interface(device, iface, add)
    return lines


def read_interface(iface: Interface, w: List[str], canonical: Callable[[str], str]) -> bool:
    n = len(w)
    if w[:4] == ["ip", "address", "unnumbered", "interface"] and n >= 5:
        iface.unnumbered = canonical(" ".join(w[4:]))
    elif w[:2] == ["ip", "urpf"] and n == 3 and w[2] in ("strict", "loose"):
        iface.urpf = w[2]
    elif w == ["proxy-arp", "enable"]:
        iface.proxy_arp = True
    elif w[:3] == ["dot1x", "auth-fail", "vlan"] and n == 4:
        iface.dot1x_fail_vlan = int(w[3])
    elif w[:3] == ["packet-filter", "mac", "name"] and n == 5 and w[4] in ("inbound", "outbound"):
        setattr(iface, "mac_acl_in" if w[4] == "inbound" else "mac_acl_out", w[3])
    else:
        return False
    return True


def device_lines(device: Device, report: Report) -> List[str]:
    """Global security lines: RADIUS dynamic authorization; reports for DHCP option 82 and the control plane."""
    out: List[str] = []
    if device.aaa.coa:
        report.item("system", "RADIUS CoA")
        out += ["radius dynamic-author server", "#"]
        report.add("system", "RADIUS CoA", Severity.REVIEW, "coa",
                   "add the RADIUS servers that may change sessions with 'client ip A key simple KEY' under "
                   "'radius dynamic-author server'")
    if device.dhcp_option82 is not None:
        report.add("system", "DHCP snooping", Severity.APPROX, "option82",
                   "Comware inserts option 82 per port ('dhcp snooping information enable' on the untrusted ports); "
                   "the device-wide setting is not written")
    cp = device.control_plane
    if cp is not None and (cp.acls or cp.classes or cp.policy):
        report.add("system", "control plane", Severity.REVIEW, "copp",
                   "the control-plane ACLs and policing are not written: Comware protects its CPU with built-in "
                   "limits; to add your own, apply a QoS policy under 'control-plane slot N' by hand")
    return out


# queuing -----------------------------------------------------------------------------------------------------------

def queuing_lines(device: Device, report: Report) -> List[str]:
    out: List[str] = []
    if device.qos_dscp_tc:
        report.item("qos", "DSCP to traffic-class map")
        out.append("qos map-table dscp-lp")
        by_tc: Dict[int, List[int]] = {}
        for dscp, tc in sorted(device.qos_dscp_tc.items()):
            by_tc.setdefault(tc, []).append(dscp)
        for tc, values in sorted(by_tc.items()):
            for n in range(0, len(values), 8):
                out.append(f"{IND}import {' '.join(str(v) for v in values[n:n + 8])} export {tc}")
        out.append("#")
    if device.qos_tc_dscp:
        report.add("qos", "DSCP to traffic-class map", Severity.APPROX, "tc-dscp",
                   "the rewrite of traffic classes to DSCP values is left out: Comware remarks by QoS policy")
    for p in device.qos_profiles.values():
        label = f"queuing profile {p.name}"
        report.item("qos", label)
        out += [f"qos qmprofile {p.name}"] + [IND + line for line in _queues(p, report, label)] + ["#"]
        if p.shape_kbps is not None:
            report.add("qos", label, Severity.APPROX, "qos-shape",
                       f"the port shaping of {p.shape_kbps} kbps is left out: set 'qos lr outbound cir' on the ports")
        if p.input_policy:
            report.add("qos", label, Severity.APPROX, "qos-input",
                       f"the profile's input policy {p.input_policy} is not applied by it: Comware applies a policy "
                       "on the port ('qos apply policy')")
    return out


def _queues(p: QosProfile, report: Report, label: str) -> List[str]:
    lines = []
    left = []
    for tc, q in sorted(p.queues.items()):
        if q.priority:
            lines.append(f"queue {tc} sp")
        elif q.bandwidth_percent is not None or q.bandwidth_remaining is not None:
            weight = q.bandwidth_percent if q.bandwidth_percent is not None else q.bandwidth_remaining
            lines.append(f"queue {tc} wrr group 1 weight {weight}")
        if q.shape_percent is not None or q.shape_kbps is not None or q.ecn or q.wred or q.queue_limit or \
                q.priority_percent is not None:
            left.append(str(tc))
    if left:
        report.add("qos", label, Severity.APPROX, "queue-options",
                   f"the shaping, WRED/ECN and limits of queues {', '.join(left)} are left out: Comware sets them "
                   "with 'qos gts queue' and WRED tables on the ports")
    return lines


def queuing_interface(device: Device, iface: Interface, add: Add) -> List[str]:
    lines = []
    if iface.qos_profile and iface.qos_profile in device.qos_profiles:
        profile = device.qos_profiles[iface.qos_profile]
        if profile.trust == "dscp" and not iface.qos_trust:
            lines.append("qos trust dscp")
        lines.append(f"qos apply qmprofile {iface.qos_profile}")
    elif iface.qos_profile:
        add(Severity.REVIEW, "qos-profile", f"queuing profile {iface.qos_profile} is not defined; left out")
    if iface.queues:
        add(Severity.REVIEW, "queuing", "the port's own queue settings are not written: give it a qmprofile of "
                                        "its own")
    return lines


@dataclass
class QueuingReader:
    device: Device

    def map_table(self, w: List[str], children: List[List[str]]) -> Optional[List[int]]:
        if w != ["qos", "map-table", "dscp-lp"]:
            return None
        left = []
        for n, c in enumerate(children):
            if c[0] == "import" and "export" in c and c[-2] == "export" and c[-1].isdigit():
                for v in c[1:-2]:
                    self.device.qos_dscp_tc[int(v)] = int(c[-1])
            else:
                left.append(n)
        return left

    def qmprofile(self, w: List[str], children: List[List[str]]) -> Optional[List[int]]:
        if w[:2] != ["qos", "qmprofile"] or len(w) != 3:
            return None
        p = self.device.qos_profiles.setdefault(w[2], QosProfile(w[2]))
        left = []
        for n, c in enumerate(children):
            if c[0] == "queue" and len(c) == 3 and c[1].isdigit() and c[2] == "sp":
                p.queues[int(c[1])] = QosQueue(int(c[1]), priority=True)
            elif c[0] == "queue" and len(c) == 6 and c[1].isdigit() and c[2:5] == ["wrr", "group", "1"] or \
                    c[0] == "queue" and len(c) == 7 and c[1].isdigit() and c[2:6] == ["wrr", "group", "1", "weight"]:
                p.queues[int(c[1])] = QosQueue(int(c[1]), bandwidth_percent=int(c[-1]))
            else:
                left.append(n)
        return left

    def interface(self, iface: Interface, w: List[str]) -> bool:
        if w[:3] == ["qos", "apply", "qmprofile"] and len(w) == 4:
            iface.qos_profile = w[3]
            return True
        return False

    def finish(self) -> None:
        """A profile's trust is that of the ports that use it."""
        for p in self.device.qos_profiles.values():
            users = [i for i in self.device.interfaces.values() if i.qos_profile == p.name]
            if users and all(i.qos_trust == "dscp" for i in users):
                p.trust = "dscp"
                for i in users:
                    i.qos_trust = ""


# multicast ---------------------------------------------------------------------------------------------------------

def rp_acls(device: Device) -> Dict[Tuple[str, str], int]:
    """(VRF, RP) -> the basic ACL that names its groups."""
    numbers: Dict[Tuple[str, str], int] = {}
    n = RP_ACL_BASE
    for vrf, groups in [("", device.pim_rp_groups)] + [(v, m.rp_groups) for v, m in device.multicast_vrfs.items()]:
        for rp in groups:
            numbers[(vrf, rp)] = n
            n -= 1
    return numbers


def multicast_lines(device: Device, report: Report, port: Callable[[str], str]) -> List[str]:
    """The ACLs of the RPs' groups, anycast RP, MSDP and multicast in VPN instances (the default PIM view's static
    RPs are written by the writer, with these ACLs)."""
    out: List[str] = []
    acls = rp_acls(device)
    for (vrf, rp), number in acls.items():
        groups = (device.pim_rp_groups if not vrf else device.multicast_vrfs[vrf].rp_groups)[rp]
        net = ipaddress.ip_network(groups)
        out += [f"acl number {number}", f"{IND}rule 0 permit source {net.network_address} {net.hostmask}", "#"]
    for vrf, m in device.multicast_vrfs.items():
        report.item("system", f"multicast vrf {vrf}")
        if m.routing:
            out += [f"multicast routing vpn-instance {vrf}", "#"]
        if m.rps:
            out += [f"pim vpn-instance {vrf}"] + [IND + static_rp(device, vrf, rp, acls) for rp in m.rps] + ["#"]
    if device.msdp_peers:
        report.item("system", "MSDP")
        out += ["msdp"] + [f"{IND}peer {peer} connect-interface {port(source)}" if source else f"{IND}peer {peer}"
                           for peer, source in device.msdp_peers.items()] + ["#"]
    return out


def static_rp(device: Device, vrf: str, rp: str, acls: Dict[Tuple[str, str], int]) -> str:
    number = acls.get((vrf, rp))
    return f"static-rp {rp}" + (f" {number}" if number is not None else "")


def anycast_lines(device: Device) -> List[str]:
    """anycast-rp lines of the pim view."""
    return [f"anycast-rp {anycast} {peer}" for anycast, peers in device.pim_anycast.items() for peer in peers]


def querier_lines(device: Device, vid: int) -> List[str]:
    lines = []
    vlan = device.vlans.get(vid)
    address = (vlan.igmp_querier_address if vlan is not None else "") or device.igmp_querier_address
    version = (vlan.igmp_querier_version if vlan is not None else None) or device.igmp_querier_version
    if address:
        lines.append(f"igmp-snooping general-query source-ip {address}")
    if version is not None:
        lines.append(f"igmp-snooping version {version}")
    return lines


@dataclass
class MulticastReader:
    device: Device
    rp_acl: Dict[Tuple[str, str], str] = field(default_factory=dict)  # (VRF, RP) -> ACL number

    def pim_line(self, vrf: str, w: List[str]) -> bool:
        d = self.device
        if w[0] == "static-rp" and len(w) in (2, 3):
            rp = str(ipaddress.IPv4Address(w[1]))
            if vrf:
                m = d.multicast_vrfs.setdefault(vrf, VrfMulticast())
                m.rps.append(rp)
            else:
                d.pim_rps.append(rp)
            if len(w) == 3:
                self.rp_acl[(vrf, rp)] = w[2]
            return True
        if w[0] == "anycast-rp" and len(w) == 3 and not vrf:
            d.pim_anycast.setdefault(w[1], []).append(w[2])
            return True
        return False

    def msdp_line(self, w: List[str], canonical: Callable[[str], str]) -> bool:
        if w[0] == "peer" and len(w) in (2, 4) and w[2:3] in ([], ["connect-interface"]):
            self.device.msdp_peers[w[1]] = canonical(w[3]) if len(w) == 4 else ""
            return True
        return False

    def querier_line(self, vid: int, w: List[str]) -> bool:
        vlan = self.device.vlans.get(vid)
        if vlan is None:
            return False
        if w[:3] == ["igmp-snooping", "general-query", "source-ip"] and len(w) == 4:
            vlan.igmp_querier_address = w[3]
            return True
        if w[:2] == ["igmp-snooping", "version"] and len(w) == 3:
            vlan.igmp_querier_version = int(w[2])
            return True
        return False

    def finish(self) -> None:
        d = self.device
        for (vrf, rp), number in self.rp_acl.items():
            acl = d.acls.get(number)
            if acl is None or len(acl.entries) != 1 or acl.entries[0].source == "any":
                continue
            groups = acl.entries[0].source
            if vrf:
                d.multicast_vrfs[vrf].rp_groups[rp] = groups
            else:
                d.pim_rp_groups[rp] = groups
            del d.acls[number]
        # the same querier address or version in every querier VLAN is the device's
        queriers = [v for v in d.vlans.values() if v.igmp_querier_address or v.igmp_querier_version]
        if queriers and len(queriers) == len([v for v in d.vlans.values() if v.igmp_querier or d.igmp_querier]):
            addresses = {v.igmp_querier_address for v in queriers}
            versions = {v.igmp_querier_version for v in queriers}
            if len(addresses) == 1 and len(versions) == 1:
                d.igmp_querier_address, d.igmp_querier_version = addresses.pop(), versions.pop()
                for v in queriers:
                    v.igmp_querier_address, v.igmp_querier_version = "", None

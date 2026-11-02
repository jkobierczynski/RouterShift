# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Junos RIP, IS-IS, MPLS with LDP, and tunnel interfaces; NAT and IPsec, which Junos switches do not do.

How the model maps to Junos:

* RIP is one group (``protocols rip group RS-RIP``) with a neighbor per interface in a RIP network; a passive one
  sends nothing (``send none``). Junos RIP announces no connected route by itself: the export policy ``RIP-EXPORT``
  announces the RIP networks (term ``rip-networks``) and what the source redistributes.
* IS-IS is ``protocols isis`` with its interfaces, the NET on the loopback unit (``family iso address``) and
  ``family iso`` on every IS-IS unit; one level is the other ``disable``d, wide metrics ``wide-metrics-only``.
* MPLS is ``family mpls`` on a unit and that unit under ``protocols mpls``, and under ``protocols ldp`` with LDP.
* A GRE tunnel is a unit of ``gr-0/0/0`` with its source and destination; an IPsec tunnel interface is a unit of
  ``st0`` (an SRX's secure tunnel) with its addresses.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import igp as igp_text
from . import junospolicy
from . import vpn as vpn_text
from .model import Device, Interface, InterfaceKind, Isis, Rip
from .report import Report, Severity

RIP_GROUP = "RS-RIP"
RIP_EXPORT = "RIP-EXPORT"
RIP_NETWORKS = "rip-networks"
ISIS_EXPORT = "ISIS-EXPORT"
GRE = "gr-0/0/0"
SECURE = "st0"
LEVELS = {"level-1": (1,), "level-2": (2,), "level-1-2": (1, 2), "": (1, 2)}

Add = Callable[..., None]


def rip_interfaces(device: Device, rip: Rip) -> List[Interface]:
    nets = [ipaddress.ip_network(n, strict=False) for n in rip.networks]
    out = []
    for iface in device.interfaces.values():
        if iface.vrf:
            continue
        for a in iface.ipv4:
            ip = ipaddress.ip_interface(a.split()[0]).ip
            if any(ip in n for n in nets):
                out.append(iface)
                break
    return out


def rip_passive(rip: Rip, name: str) -> bool:
    if rip.passive_default:
        return name not in rip.active_interfaces
    return name in rip.passive_interfaces


# writing ------------------------------------------------------------------------------------------------------------

class IgpWriter:
    def __init__(self, device: Device, add: Add, report: Report, unit: Callable[[str], str],
                 split: Callable[[Interface], Tuple[str, str]], address_of: Callable[[str], str]) -> None:
        self.device, self.add, self.report, self.unit, self.split, self.address_of = \
            device, add, report, unit, split, address_of

    def write(self) -> None:
        self.rip()
        self.isis()
        self.mpls()
        self.nat()
        self.ipsec()

    def unit_path(self, iface: Interface) -> Tuple[str, ...]:
        ifd, unit = self.split(iface)
        return ("interfaces", ifd, f"unit {unit}")

    # RIP

    def rip(self) -> None:
        rip = self.device.rip
        if rip is None:
            return
        label = igp_text.RIP_LABEL
        self.report.item("rip", label)
        group = ("protocols", "rip", f"group {RIP_GROUP}")
        members = rip_interfaces(self.device, rip)
        if not members:
            self.report.add("rip", label, Severity.REVIEW, "rip-interfaces",
                            "no interface of the switch is in a RIP network; the group has no neighbor")
        for iface in members:
            path = group + (f"neighbor {self.unit(iface.name)}",)
            self.add(*path)
            if rip_passive(rip, iface.name):
                self.add(*path, "send none")
        if rip.version == 1:
            self.add("protocols", "rip", "send version-1")
            self.add("protocols", "rip", "receive version-1")
        elif rip.version == 2:
            self.add("protocols", "rip", "send multicast")
            self.add("protocols", "rip", "receive version-2")
        if rip.default_metric is not None:
            self.add(*group, f"metric-out {rip.default_metric}")
        base = ("policy-options", f"policy-statement {RIP_EXPORT}", f"term {RIP_NETWORKS}")
        for prefix in rip.networks:
            self.add(*base, "from", f"route-filter {ipaddress.ip_network(prefix, strict=False)} orlonger")
        if rip.networks:
            self.add(*base, "from", "protocol direct")
            self.add(*base, "then accept")
        junospolicy.export_policy(self.add, RIP_EXPORT, rip.redistribute, rip.redistribute_maps,
                                  default="on" if rip.default_originate else "")
        self.add(*group, f"export {RIP_EXPORT}")
        self.report.add("rip", label, Severity.APPROX, "rip-export",
                        f"Junos RIP announces no connected route by itself: the export policy {RIP_EXPORT} announces "
                        "the connected routes in the RIP networks and what the source redistributes")
        if rip.default_originate:
            self.report.add("rip", label, Severity.APPROX, "rip-default",
                            "the default route is announced when the routing table has one; Junos does not make it up")
        if rip.auto_summary:
            self.report.add("rip", label, Severity.APPROX, "rip-summary",
                            "Junos never summarises RIP routes at classful boundaries; auto-summary is left out")

    # IS-IS

    def isis(self) -> None:
        isis = self.device.isis
        if isis is None:
            return
        label = igp_text.isis_label(isis)
        self.report.item("isis", label)
        base = ("protocols", "isis")
        levels = LEVELS.get(isis.level, (1, 2))
        if isis.level == "level-1":
            self.add(*base, "level 2", "disable")
        elif isis.level == "level-2":
            self.add(*base, "level 1", "disable")
        if isis.wide_metrics:
            for level in levels:
                self.add(*base, f"level {level}", "wide-metrics-only")
        loopback = next((i for i in self.device.interfaces.values()
                         if i.kind == InterfaceKind.LOOPBACK and not i.vrf), None)
        loop_path = self.unit_path(loopback) if loopback is not None else ("interfaces", "lo0", "unit 0")
        for net in isis.nets:
            self.add(*loop_path, "family iso", f"address {net}")
        if isis.nets and loopback is None:
            self.report.add("isis", label, Severity.APPROX, "isis-net",
                            "the switch has no loopback: the NET is written on lo0 unit 0")
        for iface in self.device.interfaces.values():
            if not iface.isis:
                continue
            path = base + (f"interface {self.unit(iface.name)}",)
            self.add(*path)
            self.add(*self.unit_path(iface), "family iso")
            if iface.isis_passive:
                self.add(*path, "passive")
            if iface.isis_network == "point-to-point":
                self.add(*path, "point-to-point")
            if iface.isis_metric is not None:
                for level in levels:
                    self.add(*path, f"level {level}", f"metric {iface.isis_metric}")
        if isis.redistribute:
            junospolicy.export_policy(self.add, ISIS_EXPORT, isis.redistribute, isis.redistribute_maps)
            self.add(*base, f"export {ISIS_EXPORT}")
        if isis.tag:
            self.report.add("isis", label, Severity.APPROX, "isis-tag",
                            f"Junos runs one IS-IS without a process tag; '{isis.tag}' is left out")
        if not isis.wide_metrics:
            self.report.add("isis", label, Severity.APPROX, "isis-metric-style",
                            "Junos sends both metric styles by default; narrow-only is not written")

    # MPLS and LDP

    def mpls(self) -> None:
        dev = self.device
        ports = [i for i in dev.interfaces.values() if i.mpls]
        if not ports and not dev.mpls.ldp:
            return
        label = "MPLS and LDP"
        self.report.item("mpls", label)
        for iface in ports:
            self.add(*self.unit_path(iface), "family mpls")
            self.add("protocols", "mpls", f"interface {self.unit(iface.name)}")
            if dev.mpls.ldp:
                self.add("protocols", "ldp", f"interface {self.unit(iface.name)}")
        if dev.mpls.ldp and not ports:
            self.report.add("mpls", label, Severity.REVIEW, "ldp-interfaces",
                            "LDP is on but no interface runs MPLS; nothing to write")
        rid = dev.mpls.router_id or (self.address_of(dev.mpls.router_id_interface)
                                     if dev.mpls.router_id_interface else "")
        if rid:
            self.report.add("mpls", label, Severity.APPROX, "ldp-router-id",
                            f"Junos LDP takes the router ID of the routing options; {rid} is not written on its own")

    # tunnels

    def tunnel(self, iface: Interface, path: Tuple[str, ...], label: str) -> None:
        """The tunnel settings of a gr-0/0/0 or st0 unit (its addresses are written as for any unit)."""
        if path[1] == SECURE:
            self.report.add("interface", label, Severity.REVIEW, "ipsec-tunnel",
                            "an IPsec tunnel interface is an SRX's st0 unit: the unit and its addresses are written, "
                            "the IKE gateway, IPsec VPN and the binding (bind-interface) are not; Junos switches do "
                            "not terminate IPsec")
            return
        source = iface.tunnel_source
        if source and not vpn_text.is_address(source):
            source = self.address_of(source)
        if source:
            self.add(*path, "tunnel", f"source {source}")
        else:
            self.report.add("interface", label, Severity.REVIEW, "tunnel-source",
                            f"Junos names the tunnel source by its address; {iface.tunnel_source or 'none'} has "
                            "none, left out")
        if iface.tunnel_destination:
            self.add(*path, "tunnel", f"destination {iface.tunnel_destination}")
        self.report.add("interface", label, Severity.APPROX, "gre",
                        "written as a gr-0/0/0 unit: the platform needs tunnel services on a PIC "
                        "(chassis fpc 0 pic 0 tunnel-services) to have gr-0/0/0")

    # what Junos switches do not do

    def nat(self) -> None:
        for n, rule in enumerate(self.device.nat_rules, 1):
            self.report.skip("nat", f"rule {n} ({rule.kind})", "nat-srx",
                             "Junos switches do not translate addresses; on an SRX this is a security nat rule set "
                             "(source, destination or static); not converted")

    def ipsec(self) -> None:
        if not vpn_text.has_vpn(self.device):
            return
        for p in self.device.ipsec_peers:
            self.report.skip("vpn", vpn_text.peer_label(p), "ipsec-srx",
                             "Junos switches do not terminate IPsec; on an SRX this is security ike and ipsec with a "
                             "st0 unit; not converted")

    def port_notes(self, iface: Interface, label: str) -> None:
        if iface.nat:
            self.report.add("interface", label, Severity.REVIEW, "nat-srx",
                            f"NAT {iface.nat}: Junos switches do not translate addresses; on an SRX the port's zone "
                            "says it; not converted")
        if iface.crypto_map:
            self.report.add("interface", label, Severity.REVIEW, "ipsec-srx",
                            f"crypto map {iface.crypto_map}: Junos switches do not terminate IPsec; not converted")


# reading ------------------------------------------------------------------------------------------------------------

class IgpReader:
    def __init__(self, device: Device) -> None:
        self.device = device
        self.rip_neighbors: Dict[str, bool] = {}  # unit -> passive
        self.rip_exports: List[str] = []
        self.isis_ifaces: Dict[str, Dict[str, str]] = {}  # unit -> settings
        self.isis_exports: List[str] = []
        self.isis_disabled: List[int] = []
        self.isis_wide: List[int] = []
        self.mpls_units: List[str] = []
        self.ldp_units: List[str] = []
        self.iso_units: List[str] = []
        self.mpls_family: List[str] = []

    def rip(self, w: List[str]) -> bool:
        r = self.device.rip
        if r is None:
            r = self.device.rip = Rip()
        if w in (["send", "version-1"], ["receive", "version-1"]):
            r.version = 1
        elif w in (["send", "multicast"], ["receive", "version-2"]):
            r.version = 2
        elif w[0] == "group" and len(w) >= 3:
            rest = w[2:]
            if rest[0] == "neighbor" and len(rest) in (2, 4) and rest[2:] in ([], ["send", "none"]):
                self.rip_neighbors[rest[1]] = self.rip_neighbors.get(rest[1], False) or len(rest) == 4
            elif rest[0] == "export" and len(rest) == 2:
                self.rip_exports.append(rest[1])
            elif rest[0] == "metric-out" and len(rest) == 2:
                r.default_metric = int(rest[1])
            else:
                return False
        else:
            return False
        return True

    def isis(self, w: List[str]) -> bool:
        if self.device.isis is None:
            self.device.isis = Isis()
        if w[0] == "level" and len(w) == 3 and w[1] in ("1", "2") and w[2] in ("disable", "wide-metrics-only"):
            (self.isis_disabled if w[2] == "disable" else self.isis_wide).append(int(w[1]))
        elif w[0] == "export" and len(w) == 2:
            self.isis_exports.append(w[1])
        elif w[0] == "interface" and len(w) >= 2:
            settings = self.isis_ifaces.setdefault(w[1], {})
            rest = w[2:]
            if rest in (["passive"], ["point-to-point"]):
                settings[rest[0]] = "1"
            elif rest[:1] == ["level"] and len(rest) == 4 and rest[2] == "metric":
                settings["metric"] = rest[3]
            elif rest:
                return False
        else:
            return False
        return True

    def mpls(self, protocol: str, w: List[str]) -> bool:
        if w[0] != "interface" or len(w) != 2:
            return False
        (self.mpls_units if protocol == "mpls" else self.ldp_units).append(w[1])
        if protocol == "ldp":
            self.device.mpls.ldp = True
        return True

    def family(self, iface: Interface, unit: str, family: str, rest: List[str]) -> bool:
        if family == "iso":
            if rest[:1] == ["address"] and len(rest) == 2:
                if self.device.isis is None:
                    self.device.isis = Isis()
                self.device.isis.nets.append(rest[1])
                return True
            if not rest:
                self.iso_units.append(unit)
            return not rest
        if family == "mpls" and not rest:
            self.mpls_family.append(unit)
            return True
        return False

    def tunnel(self, iface: Interface, w: List[str]) -> bool:
        if w[0] in ("source", "destination") and len(w) == 2:
            setattr(iface, f"tunnel_{w[0]}", w[1])
            iface.tunnel_mode = "gre"
            return True
        return False

    def finish(self, canonical: Callable[[str], Optional[Interface]], export: Callable[[str], Optional[Tuple[Any, ...]]],
               policies: Dict[str, junospolicy.Policy], unread: Callable[[int, str, str], None]) -> None:
        dev = self.device
        r = dev.rip
        if r is not None:
            active: List[str] = []
            for unit, passive in self.rip_neighbors.items():
                iface = canonical(unit)
                if iface is None:
                    unread(0, f"set protocols rip group {RIP_GROUP} neighbor {unit}", "no such interface")
                    continue
                (r.passive_interfaces if passive else active).append(iface.name)
            if len(r.passive_interfaces) > len(active):  # mostly passive: passive by default, as IOS writes it
                r.passive_default, r.passive_interfaces, r.active_interfaces = True, [], active
            r.auto_summary = False  # Junos never summarises
            for name in self.rip_exports:
                policy = policies.get(name)
                networks = policy.terms.pop(RIP_NETWORKS, None) if policy is not None else None
                if networks is not None:
                    r.networks += [str(ipaddress.ip_network(f[1])) for f in networks.froms if f[0] == "route-filter"]
                found = export(name)
                if found is None:
                    unread(0, f"set protocols rip group {RIP_GROUP} export {name}",
                           "a RIP export policy RouterShift cannot read as redistribution")
                    continue
                sources, maps, _, default, _, _ = found
                r.redistribute += [s for s in sources if s not in r.redistribute]
                r.redistribute_maps.update(maps)
                r.default_originate = r.default_originate or bool(default)
        isis = dev.isis
        if isis is not None:
            enabled = [lv for lv in (1, 2) if lv not in self.isis_disabled]
            isis.level = "level-1" if enabled == [1] else "level-2" if enabled == [2] else ""
            isis.wide_metrics = bool(self.isis_wide) and all(lv in self.isis_wide for lv in enabled)
            for unit, settings in self.isis_ifaces.items():
                iface = canonical(unit)
                if iface is None:
                    unread(0, f"set protocols isis interface {unit}", "no such interface")
                    continue
                iface.isis = True
                iface.isis_passive = "passive" in settings
                iface.isis_network = "point-to-point" if "point-to-point" in settings else ""
                if "metric" in settings:
                    iface.isis_metric = int(settings["metric"])
            for name in self.isis_exports:
                found = export(name)
                if found is None:
                    unread(0, f"set protocols isis export {name}",
                           "an IS-IS export policy RouterShift cannot read as redistribution")
                    continue
                sources, maps, _, _, _, _ = found
                isis.redistribute += [s for s in sources if s not in isis.redistribute]
                isis.redistribute_maps.update(maps)
        for unit in self.mpls_units:
            iface = canonical(unit)
            if iface is None:
                unread(0, f"set protocols mpls interface {unit}", "no such interface")
                continue
            iface.mpls = True

# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Checks that run after every writer, so the report never calls an item exact when part of it was not converted.

* ``unwritten`` reports the settings of the model that only the IOS and EOS writer writes so far, on every other
  target, against the item they belong to.
* ``partly_converted`` marks an item whose block in the source has lines no reader converted (an interface with an
  unread line, a route map with an unread clause, a BGP VRF with an unread option) as needs-review, and names the
  lines. Without it, such an item would be listed as exact while the lines only show up further down the report.
"""

from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Tuple

from . import known
from . import ospf as ospf_text
from . import routemap as routemap_text
from .model import Device, Interface, Unparsed
from .report import Report, Severity, redact

# Writers that write every setting below
_FULL = ("ios", "eos")

_NAMES = {"aoscx": "AOS-CX", "aoss": "AOS-S", "comware": "Comware", "junos": "Junos", "nxos": "NX-OS"}


def _interface_item(report: Report, iface: Interface, port: Callable[[str], str]) -> str:
    source = iface.source_name or iface.name
    for kind, name in report.items:
        if kind == "interface" and name.startswith(f"{source} -> "):
            return name
    return f"{source} -> {port(iface.name)}"


def unwritten(device: Device, report: Report, target: str, port: Callable[[str], str]) -> None:
    """Settings only the IOS and EOS writer writes yet, reported on the other targets."""
    if target in _FULL:
        return
    platform = _NAMES.get(target, target)
    later = f"not written for {platform} yet; set it by hand"

    def add(kind: str, item: str, what: str, severity: Severity = Severity.REVIEW) -> None:
        report.add(kind, item, severity, "not-written", f"{what} {later}")

    for iface in device.interfaces.values():
        label = _interface_item(report, iface, port)
        if iface.virtual_ipv4 or iface.virtual_ipv6:
            add("interface", label, "anycast gateway " + ", ".join(iface.virtual_ipv4 + iface.virtual_ipv6) +
                (f" (shared MAC {device.anycast_mac})" if device.anycast_mac else "") + ":")
        if iface.helper_addresses and (iface.helper_vrf or iface.helper_source):
            add("interface", label, "the DHCP relay's server VRF and source interface:")
        hardening = [w for w, v in (("unicast RPF", iface.urpf), ("ICMP redirects", iface.ip_redirects is not None),
                                    ("ICMP unreachables", iface.ip_unreachables is not None),
                                    ("proxy ARP", iface.proxy_arp is not None)) if v]
        if hardening:
            add("interface", label, ", ".join(hardening) + ":", Severity.APPROX)
        if iface.ospf_auth:
            add("interface", label, "OSPF authentication:")
    for route in device.static_routes:
        if route.tag is not None:
            add("route", f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}", f"route tag {route.tag}:")
    for p in device.ospf:
        options = [w for w, v in (("distribute-list", p.distribute_list_in), ("SPF and LSA timers",
                                                                                p.spf_timers or p.lsa_arrival),
                                  ("max-lsa", p.max_lsa), ("graceful restart", p.graceful_restart)) if v]
        if options:
            add("ospf", ospf_text.label(p), ", ".join(options) + ":")
    bgp = device.bgp
    if bgp is not None:
        options = [w for w, v in (("aggregate-address", bgp.aggregates), ("timers bgp", bgp.keepalive is not None),
                                  ("graceful restart", bgp.graceful_restart), ("distance", bgp.distance),
                                  ("bestpath as-path multipath-relax", bgp.multipath_relax)) if v]
        if options:
            add("bgp", f"bgp {bgp.local_as}", ", ".join(options) + ":")
        for name, v in bgp.vrfs.items():
            options = [w for w, x in (("aggregate-address", v.aggregates), ("the IPv6 address family", v.redistribute6
                                                                             or any(":" in n for n in v.networks)),
                                      ("peer groups defined in the VRF", v.peer_groups)) if x]
            if options:
                add("bgp", f"bgp vrf {name}", ", ".join(options) + ":")
    for name, info in device.vrf_info.items():
        if info.export_map or info.rt_evpn:
            add("system", f"vrf {name}", "the EVPN route targets and export route map:", Severity.APPROX)
    routemap_text.lists_unsupported(device, report, platform)
    for kind, item, what, severity in later_features(device, report, port):
        add(kind, item, what, severity)
    s = device.system
    if s.syslog_transport:
        add("system", "syslog servers", "the transport of " + ", ".join(
            f"{a} ({p} {n})" for a, (p, n) in s.syslog_transport.items()) + ":")
    if device.snmp.trap_types:
        add("management", "snmp traps", "the choice of notifications (" + ", ".join(device.snmp.trap_types) + "):",
            Severity.APPROX)
    if device.management.console_login:
        add("management", "console login", f"login list {device.management.console_login} on the console:")
    for policy in device.qos_policies.values():
        for action in policy.actions:
            if action.burst_bytes:
                report.add("qos", f"policy {policy.name}", Severity.APPROX, "qos-burst",
                           f"class {action.qos_class}: the burst of {action.burst_bytes} bytes is not converted; the "
                           f"{platform} default is used")


def later_features(device: Device, report: Report, port: Callable[[str], str]) -> List[Tuple[str, str, str, Severity]]:
    """Settings of the data-centre and management features only the IOS and EOS writer writes: (report kind, item,
    what is not written, severity)."""
    found: List[Tuple[str, str, str, Severity]] = []
    vx = device.vxlan
    if vx is not None:
        named = [i.name for i in vx.evpn_instances.values() if i.rd or i.rt_import or i.rt_export or i.bundle]
        if named:
            found.append(("interface", "VXLAN", "the route distinguishers and route targets of EVPN instances "
                          + ", ".join(named) + ":", Severity.REVIEW))
        if vx.mcast_groups:
            found.append(("interface", "VXLAN", "the multicast groups of VLANs "
                          + ", ".join(str(v) for v in vx.mcast_groups) + ":", Severity.REVIEW))
    bgp = device.bgp
    if bgp is not None and (bgp.evpn_domain or bgp.evpn_remote_peers or bgp.evpn_host_flap):
        found.append(("bgp", f"bgp {bgp.local_as}", "the EVPN domain gateway and host-flap settings:",
                      Severity.REVIEW))
    m = device.mlag
    if m is not None:
        options = [w for w, v in (("the MLAG heartbeat", m.heartbeat), ("dual-primary detection", m.dual_primary_delay
                                                                         is not None),
                                  ("the reload delays", m.reload_delay or m.reload_delay_non_mlag),
                                  ("StackWise Virtual", m.stack)) if v]
        if options:
            found.append(("interface", "multi-chassis LAG", ", ".join(options) + ":", Severity.REVIEW))
    for vlan in device.vlans.values():
        if vlan.trunk_groups:
            found.append(("vlan", str(vlan.vlan_id), f"trunk group {', '.join(vlan.trunk_groups)}:", Severity.APPROX))
    for name, info in device.vrf_info.items():
        if info.leaks:
            found.append(("system", f"vrf {name}", "the routes leaked from VRF " + ", ".join(info.leaks) + ":",
                          Severity.REVIEW))
    if device.system.router_id:
        found.append(("system", "router ID", f"the global router ID {device.system.router_id}:", Severity.REVIEW))
    options = [w for w, v in (("the groups of the rendezvous points", device.pim_rp_groups),
                              ("anycast RP", device.pim_anycast), ("MSDP peers", device.msdp_peers),
                              ("multicast routing in VRFs " + ", ".join(device.multicast_vrfs), device.multicast_vrfs))
               if v]
    if options:
        found.append(("system", "multicast routing", ", ".join(options) + ":", Severity.REVIEW))
    if device.igmp_querier_address or device.igmp_querier_version or any(
            v.igmp_querier_address or v.igmp_querier_version for v in device.vlans.values()):
        found.append(("vlan", "IGMP snooping", "the querier's address and version:", Severity.APPROX))
    if device.qos_profiles or device.qos_dscp_tc or device.qos_tc_dscp:
        found.append(("qos", "DSCP to traffic-class map", "the DSCP map and the queuing profiles " +
                      ", ".join(device.qos_profiles) + ":", Severity.REVIEW))
    cp = device.control_plane
    if cp is not None and (cp.acls or cp.classes or cp.policy):
        found.append(("system", "control plane", "the control-plane ACLs and policing:", Severity.REVIEW))
    if device.macsec_profiles or device.macsec_fips:
        found.append(("system", "MACsec", "the MACsec profiles " + ", ".join(device.macsec_profiles) + ":",
                      Severity.REVIEW))
    for acl_name in device.mac_acls:
        found.append(("acl", f"mac access-list {acl_name}", "MAC access lists:", Severity.REVIEW))
    if device.dhcp_option82 is not None:
        found.append(("system", "DHCP snooping", "the DHCP option 82 setting:", Severity.APPROX))
    if device.aaa.coa:
        found.append(("system", "RADIUS CoA", "RADIUS change of authorization:", Severity.REVIEW))
    # (new device-level settings go above this line)
    for iface in device.interfaces.values():
        label = _interface_item(report, iface, port)
        options = [w for w, v in (("the EVPN ethernet segment", iface.evpn_esi),
                                  ("the LACP system ID", iface.lacp_system_id),
                                  ("the SVI MAC address", iface.mac_address), ("no autostate", iface.autostate is False),
                                  ("the unnumbered address", iface.unnumbered),
                                  ("the trunk groups", iface.trunk_groups),
                                  ("the queuing profile " + iface.qos_profile, iface.qos_profile),
                                  ("the port's own queue settings", iface.queues),
                                  ("the 802.1X fail VLAN", iface.dot1x_fail_vlan),
                                  ("the MAC access groups", iface.mac_acl_in or iface.mac_acl_out),
                                  ("the MACsec profile", iface.macsec_profile),
                                  ("the StackWise Virtual link", iface.svl_link is not None or iface.svl_dad)) if v]
        if options:
            found.append(("interface", label, ", ".join(options) + ":", Severity.REVIEW))
    return found


# Section of the source -> the report item it belongs to --------------------------------------------------------------

def _owner(report: Report, section: str) -> Optional[Tuple[str, str]]:
    head = section.split(" / ")[0]
    parts = section.split(" / ")
    w = head.split()
    items = report.items
    if not w:
        return None

    def find(kind: str, name: str) -> Optional[Tuple[str, str]]:
        return (kind, name) if (kind, name) in items else None

    if w[0] == "interface" and len(w) >= 2:
        source = " ".join(w[1:])
        return next(((k, n) for k, n in items if k == "interface" and n.startswith(f"{source} -> ")), None)
    if w[0] == "route-map" and len(w) >= 2:
        return find("policy", f"route-map {w[1]}")
    if w[0] in ("ip", "ipv6") and w[1:2] == ["prefix-list"] and len(w) >= 3:
        return find("policy", f"prefix-list {w[2]}")
    if w[0] == "router" and w[1:2] == ["bgp"]:
        vrf = next((p.split()[1] for p in parts[1:] if p.startswith("vrf ") and len(p.split()) == 2), None)
        vrf = vrf or next((p.split()[-1] for p in parts[1:] if re.match(r"address-family \S+ vrf \S+$", p)), None)
        if vrf:
            return find("bgp", f"bgp vrf {vrf}")
        return find("bgp", f"bgp {w[2]}") if len(w) >= 3 else None
    if w[0] == "vrf" and len(w) == 2:  # EOS: the lines of vrf NAME under router bgp
        return find("bgp", f"bgp vrf {w[1]}") or find("system", f"vrf {w[1]}")
    if w[0] == "router" and w[1:2] == ["ospf"] and len(w) >= 3:
        return find("ospf", f"ospf {w[2]}" + (f" vrf {w[4]}" if w[3:4] == ["vrf"] and len(w) >= 5 else ""))
    if w[0] == "vlan" and len(w) == 2:
        return find("vlan", w[1])
    if w[0] == "policy-map" and len(w) >= 2:
        return find("qos", f"policy {w[-1]}")
    if w[0] == "class-map" and len(w) >= 2:
        return find("qos", f"class {w[-1]}")
    if w[:2] == ["management", "ssh"]:
        return find("management", "ssh server")
    return None


def partly_converted(entries: List[Unparsed], report: Report) -> None:
    """Mark each converted item that has unconverted lines in its block as needs-review, naming the lines."""
    found: Dict[Tuple[str, str], List[Unparsed]] = {}
    for entry in entries:
        if not entry.section:
            continue
        owner = _owner(report, entry.section)
        if owner is None or report.items[owner].skipped:
            continue
        found.setdefault(owner, []).append(entry)
    for (kind, name), lines in found.items():
        shown = [f"{e.line}: {redact(e.text)}" for e in lines[:4]]
        more = f" and {len(lines) - 4} more" if len(lines) > 4 else ""
        groups = [e.group or (known.classify(e.text, e.section) or ("", ""))[0] for e in lines]
        where = f" (see {', '.join(sorted(set(groups)))} below)" if all(groups) else " (listed below)"
        report.add(kind, name, Severity.REVIEW, "partly-converted",
                   f"not every line of it is converted: line {'; line '.join(shown)}{more}{where}")

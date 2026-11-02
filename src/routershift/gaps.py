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
from typing import AbstractSet, Callable, Dict, List, Optional, Set, Tuple

from . import known
from . import ospf as ospf_text
from . import routemap as routemap_text
from .model import Device, Interface, Unparsed
from .report import Report, Severity, redact

# Writers that write every setting below
_FULL = ("ios", "eos")

_NAMES = {"aoscx": "AOS-CX", "aoss": "AOS-S", "comware": "Comware", "junos": "Junos", "nxos": "NX-OS"}

# The settings below each other writer writes (or reports itself, where the target has no equivalent), by key
WRITES: Dict[str, Set[str]] = {
    "junos": {"policy-lists", "anycast-gateway", "relay-vrf", "hardening", "svi-mac", "autostate", "unnumbered",
              "dot1x-fail-vlan", "option82", "evpn-instances", "vxlan-mcast", "evpn-domain", "mlag-options",
              "stackwise", "trunk-groups", "leaks", "evpn-vrf", "evpn-es", "bgp-options", "bgp-vrf-ipv6",
              "bgp-vrf-groups", "bgp-misc", "router-id", "pim-rp", "msdp", "multicast-vrf", "igmp-querier",
              "queuing", "qos-burst", "copp", "macsec", "mac-acl", "coa",
              "lldp-options", "twamp", "mirror-acl", "sflow-options", "netflow-sampling", "banners", "local-logging",
              "roles", "ssh-keys", "snmp-views", "apis", "password-length", "syslog-transport", "trap-types",
              "console-login"},
}

Option = Tuple[str, str, object]  # (key, what the report calls it, whether the device has it)


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
    written = WRITES.get(target, set())

    def add(kind: str, item: str, what: str, severity: Severity = Severity.REVIEW) -> None:
        report.add(kind, item, severity, "not-written", f"{what} {later}")

    def missing(options: List[Option]) -> List[str]:
        return [what for key, what, stated in options if stated and key not in written]

    for iface in device.interfaces.values():
        label = _interface_item(report, iface, port)
        if (iface.virtual_ipv4 or iface.virtual_ipv6) and "anycast-gateway" not in written:
            add("interface", label, "anycast gateway " + ", ".join(iface.virtual_ipv4 + iface.virtual_ipv6) +
                (f" (shared MAC {device.anycast_mac})" if device.anycast_mac else "") + ":")
        if iface.helper_addresses and (iface.helper_vrf or iface.helper_source) and "relay-vrf" not in written:
            add("interface", label, "the DHCP relay's server VRF and source interface:")
        hardening = missing([("hardening", "unicast RPF", iface.urpf),
                             ("hardening", "ICMP redirects", iface.ip_redirects is not None),
                             ("hardening", "ICMP unreachables", iface.ip_unreachables is not None),
                             ("hardening", "proxy ARP", iface.proxy_arp is not None)])
        if hardening:
            add("interface", label, ", ".join(hardening) + ":", Severity.APPROX)
        if iface.ospf_auth and "ospf-auth" not in written:
            add("interface", label, "OSPF authentication:")
    if "route-tag" not in written:
        for route in device.static_routes:
            if route.tag is not None:
                add("route", f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}", f"route tag {route.tag}:")
    for p in device.ospf:
        options = missing([("ospf-options", "distribute-list", p.distribute_list_in),
                           ("ospf-options", "SPF and LSA timers", p.spf_timers or p.lsa_arrival),
                           ("ospf-options", "max-lsa", p.max_lsa),
                           ("ospf-options", "graceful restart", p.graceful_restart)])
        if options:
            add("ospf", ospf_text.label(p), ", ".join(options) + ":")
    bgp = device.bgp
    if bgp is not None:
        options = missing([("bgp-options", "aggregate-address", bgp.aggregates),
                           ("bgp-options", "timers bgp", bgp.keepalive is not None),
                           ("bgp-options", "graceful restart", bgp.graceful_restart),
                           ("bgp-options", "distance", bgp.distance),
                           ("bgp-options", "bestpath as-path multipath-relax", bgp.multipath_relax)])
        if options:
            add("bgp", f"bgp {bgp.local_as}", ", ".join(options) + ":")
        for name, v in bgp.vrfs.items():
            options = missing([("bgp-options", "aggregate-address", v.aggregates),
                               ("bgp-vrf-ipv6", "the IPv6 address family",
                                v.redistribute6 or any(":" in n for n in v.networks)),
                               ("bgp-vrf-groups", "peer groups defined in the VRF", v.peer_groups)])
            if options:
                add("bgp", f"bgp vrf {name}", ", ".join(options) + ":")
    if "evpn-vrf" not in written:
        for name, info in device.vrf_info.items():
            if info.export_map or info.rt_evpn:
                add("system", f"vrf {name}", "the EVPN route targets and export route map:", Severity.APPROX)
    if "policy-lists" not in written:
        routemap_text.lists_unsupported(device, report, platform)
    for kind, item, what, severity in later_features(device, report, port, written):
        add(kind, item, what, severity)
    s = device.system
    if s.syslog_transport and "syslog-transport" not in written:
        add("system", "syslog servers", "the transport of " + ", ".join(
            f"{a} ({p} {n})" for a, (p, n) in s.syslog_transport.items()) + ":")
    if device.snmp.trap_types and "trap-types" not in written:
        add("management", "snmp traps", "the choice of notifications (" + ", ".join(device.snmp.trap_types) + "):",
            Severity.APPROX)
    if device.management.console_login and "console-login" not in written:
        add("management", "console login", f"login list {device.management.console_login} on the console:")
    if "qos-burst" not in written:
        for policy in device.qos_policies.values():
            for action in policy.actions:
                if action.burst_bytes:
                    report.add("qos", f"policy {policy.name}", Severity.APPROX, "qos-burst",
                               f"class {action.qos_class}: the burst of {action.burst_bytes} bytes is not converted; "
                               f"the {platform} default is used")


def later_features(device: Device, report: Report, port: Callable[[str], str],
                   written: AbstractSet[str] = frozenset()) -> List[Tuple[str, str, str, Severity]]:
    """Settings of the data-centre and management features only the IOS and EOS writer writes: (report kind, item,
    what is not written, severity). The keys in written are left out."""
    found: List[Tuple[str, str, str, Severity]] = []

    def add(key: str, kind: str, item: str, what: str, severity: Severity) -> None:
        if key not in written:
            found.append((kind, item, what, severity))

    def missing(options: List[Option]) -> List[str]:
        return [what for key, what, stated in options if stated and key not in written]

    vx = device.vxlan
    if vx is not None:
        named = [i.name for i in vx.evpn_instances.values() if i.rd or i.rt_import or i.rt_export or i.bundle]
        if named:
            add("evpn-instances", "interface", "VXLAN", "the route distinguishers and route targets of EVPN "
                "instances " + ", ".join(named) + ":", Severity.REVIEW)
        if vx.mcast_groups:
            add("vxlan-mcast", "interface", "VXLAN", "the multicast groups of VLANs "
                + ", ".join(str(v) for v in vx.mcast_groups) + ":", Severity.REVIEW)
    bgp = device.bgp
    if bgp is not None and (bgp.evpn_domain or bgp.evpn_remote_peers or bgp.evpn_host_flap):
        add("evpn-domain", "bgp", f"bgp {bgp.local_as}", "the EVPN domain gateway and host-flap settings:",
            Severity.REVIEW)
    m = device.mlag
    if m is not None:
        options = missing([("mlag-options", "the MLAG heartbeat", m.heartbeat),
                           ("mlag-options", "dual-primary detection", m.dual_primary_delay is not None),
                           ("mlag-options", "the reload delays", m.reload_delay or m.reload_delay_non_mlag),
                           ("stackwise", "StackWise Virtual", m.stack)])
        if options:
            found.append(("interface", "multi-chassis LAG", ", ".join(options) + ":", Severity.REVIEW))
    for vlan in device.vlans.values():
        if vlan.trunk_groups:
            add("trunk-groups", "vlan", str(vlan.vlan_id), f"trunk group {', '.join(vlan.trunk_groups)}:",
                Severity.APPROX)
    for name, info in device.vrf_info.items():
        if info.leaks:
            add("leaks", "system", f"vrf {name}", "the routes leaked from VRF " + ", ".join(info.leaks) + ":",
                Severity.REVIEW)
    if device.system.router_id:
        add("router-id", "system", "router ID", f"the global router ID {device.system.router_id}:", Severity.REVIEW)
    options = missing([("pim-rp", "the groups of the rendezvous points", device.pim_rp_groups),
                       ("pim-rp", "anycast RP", device.pim_anycast), ("msdp", "MSDP peers", device.msdp_peers),
                       ("multicast-vrf", "multicast routing in VRFs " + ", ".join(device.multicast_vrfs),
                        device.multicast_vrfs)])
    if options:
        found.append(("system", "multicast routing", ", ".join(options) + ":", Severity.REVIEW))
    if device.igmp_querier_address or device.igmp_querier_version or any(
            v.igmp_querier_address or v.igmp_querier_version for v in device.vlans.values()):
        add("igmp-querier", "vlan", "IGMP snooping", "the querier's address and version:", Severity.APPROX)
    if device.qos_profiles or device.qos_dscp_tc or device.qos_tc_dscp:
        add("queuing", "qos", "DSCP to traffic-class map", "the DSCP map and the queuing profiles " +
            ", ".join(device.qos_profiles) + ":", Severity.REVIEW)
    cp = device.control_plane
    if cp is not None and (cp.acls or cp.classes or cp.policy):
        add("copp", "system", "control plane", "the control-plane ACLs and policing:", Severity.REVIEW)
    if device.macsec_profiles or device.macsec_fips:
        add("macsec", "system", "MACsec", "the MACsec profiles " + ", ".join(device.macsec_profiles) + ":",
            Severity.REVIEW)
    for acl_name in device.mac_acls:
        add("mac-acl", "acl", f"mac access-list {acl_name}", "MAC access lists:", Severity.REVIEW)
    if device.dhcp_option82 is not None:
        add("option82", "system", "DHCP snooping", "the DHCP option 82 setting:", Severity.APPROX)
    if device.aaa.coa:
        add("coa", "system", "RADIUS CoA", "RADIUS change of authorization:", Severity.REVIEW)
    m_ = device.management
    options = missing([("lldp-options", "the LLDP timers", m_.lldp_timer is not None or m_.lldp_holdtime is not None),
                       ("lldp-options", "the LLDP management address", m_.lldp_mgmt_interface or m_.lldp_mgmt_vrf)])
    if options:
        found.append(("management", "LLDP", ", ".join(options) + ":", Severity.APPROX))
    if device.twamp_port is not None:
        add("twamp", "monitor", "TWAMP reflector", "the TWAMP reflector:", Severity.REVIEW)
    for session in device.mirror_sessions:
        if session.acl:
            add("mirror-acl", "monitor", f"mirror session {session.name}", f"the mirror's ACL filter {session.acl}:",
                Severity.REVIEW)
    sf = device.sflow
    if sf is not None and (sf.extensions or sf.source_vrf):
        add("sflow-options", "monitor", "sflow", "the sFlow extensions and the source interface's VRF:",
            Severity.APPROX)
    if device.netflow is not None and device.netflow.sample_rate:
        add("netflow-sampling", "monitor", "netflow", f"sampling 1 in {device.netflow.sample_rate}:", Severity.REVIEW)
    sy = device.system
    options = missing([("banners", "the login banner", sy.banner_login),
                       ("banners", "the exec banner", sy.banner_exec)])
    if options:
        found.append(("system", "banners", ", ".join(options) + ":", Severity.REVIEW))
    if sy.logging_buffer is not None or sy.logging_buffer_level is not None or sy.logging_console_level is not None \
            or sy.logging_monitor_level is not None or sy.logging_timestamp or sy.logging_hostname \
            or sy.logging_facility_levels:
        add("local-logging", "system", "local logging", "the logging buffer, console and syslog format:",
            Severity.APPROX)
    if device.roles or any(u.role for u in device.users):
        add("roles", "management", "roles", "the CLI roles " + ", ".join(device.roles) + ":", Severity.REVIEW)
    if any(u.ssh_keys for u in device.users):
        add("ssh-keys", "management", "SSH keys", "the users' SSH public keys:", Severity.REVIEW)
    if device.snmp.views or device.snmp.engine_id:
        add("snmp-views", "management", "SNMP views", "the SNMP views and engine ID:", Severity.REVIEW)
    if m_.apis:
        add("apis", "management", "programmatic interfaces", "the APIs " + ", ".join(m_.apis) + ":", Severity.REVIEW)
    if m_.password_min_length is not None:
        add("password-length", "management", "password length", "the minimum password length:", Severity.APPROX)
    if device.ptp is not None:
        add("ptp", "system", "PTP", "PTP:", Severity.REVIEW)
    for name in device.event_handlers:
        add("event-handlers", "system", f"event handler {name}", "event handlers and EEM applets:", Severity.REVIEW)
    if device.bfd_multihop is not None or device.bfd_slow_timer is not None:
        add("bfd-global", "system", "BFD", "the BFD multihop and slow timers:", Severity.APPROX)
    if device.ecmp_hash:
        add("ecmp-hash", "system", "ECMP hashing", "the ECMP hash fields:", Severity.APPROX)
    if bgp is not None:
        options = missing([("bgp-misc", "asdot notation", bgp.asdot),
                           ("bgp-misc", "missing-as-worst MED", bgp.med_missing_as_worst or any(
                               v.med_missing_as_worst for v in bgp.vrfs.values())),
                           ("bgp-misc", "the OSPF route types redistributed", bgp.ospf_match or any(
                               v.ospf_match for v in bgp.vrfs.values()))])
        if options:
            found.append(("bgp", f"bgp {bgp.local_as}", ", ".join(options) + ":", Severity.APPROX))
    # (new device-level settings go above this line)
    for iface in device.interfaces.values():
        label = _interface_item(report, iface, port)
        options = missing([("evpn-es", "the EVPN ethernet segment", iface.evpn_esi),
                           ("evpn-es", "the LACP system ID", iface.lacp_system_id),
                           ("svi-mac", "the SVI MAC address", iface.mac_address),
                           ("autostate", "no autostate", iface.autostate is False),
                           ("unnumbered", "the unnumbered address", iface.unnumbered),
                           ("trunk-groups", "the trunk groups", iface.trunk_groups),
                           ("queuing", "the queuing profile " + iface.qos_profile, iface.qos_profile),
                           ("queuing", "the port's own queue settings", iface.queues),
                           ("dot1x-fail-vlan", "the 802.1X fail VLAN", iface.dot1x_fail_vlan),
                           ("mac-acl", "the MAC access groups", iface.mac_acl_in or iface.mac_acl_out),
                           ("macsec", "the MACsec profile", iface.macsec_profile),
                           ("ptp", "PTP", iface.ptp is not None or iface.ptp_announce_interval is not None),
                           ("stackwise", "the StackWise Virtual link", iface.svl_link is not None or iface.svl_dad)])
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

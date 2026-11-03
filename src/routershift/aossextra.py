# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""AOS-S (ProCurve / ProVision, 16.x): the settings of the data-centre and management features that the other
writers write, written where AOS-S has a form and reported, with what AOS-S has instead, where it has none.

Written: the global router ID (``ip router-id``), the syslog transport (``logging A tcp|udp|tls PORT``), the LLDP
timers (``lldp refresh-interval``, ``lldp holdtime-multiplier``), the exec banner (``banner exec``) and the 802.1X
fail VLAN (``aaa port-access authenticator P unauth-vid N``). Everything else is reported here.
"""

from __future__ import annotations

from typing import Callable, List, Optional

from . import gaps
from .model import Device
from .report import Report, Severity

LLDP_TIMER = 30  # the AOS-S default refresh interval


def syslog_suffix(device: Device, host: str) -> str:
    found = device.system.syslog_transport.get(host)
    if found is None:
        return ""
    protocol, port = found
    return f" {protocol} {port}"


def read_logging(device: Device, w: List[str]) -> bool:
    """logging A udp|tcp|tls PORT"""
    if len(w) == 4 and w[2] in ("udp", "tcp", "tls"):
        device.system.syslog_servers.append(w[1])
        device.system.syslog_transport[w[1]] = (w[2], int(w[3]))
        return True
    return False


def lldp_lines(device: Device, report: Report) -> List[str]:
    m = device.management
    out: List[str] = []
    if m.lldp_timer is not None:
        out.append(f"lldp refresh-interval {m.lldp_timer}")
    if m.lldp_holdtime is not None:
        multiplier = max(2, min(10, round(m.lldp_holdtime / (m.lldp_timer or LLDP_TIMER))))
        out.append(f"lldp holdtime-multiplier {multiplier}")
        if multiplier * (m.lldp_timer or LLDP_TIMER) != m.lldp_holdtime:
            report.add("management", "LLDP", Severity.APPROX, "lldp-hold",
                       f"AOS-S sets the hold time as a multiple of the refresh interval; {m.lldp_holdtime} s becomes "
                       f"{multiplier * (m.lldp_timer or LLDP_TIMER)} s")
    if m.lldp_mgmt_interface or m.lldp_mgmt_vrf:
        report.add("management", "LLDP", Severity.APPROX, "lldp-mgmt",
                   "the LLDP management address is not written: AOS-S advertises the address of a VLAN with "
                   "'lldp config PORTS ipAddrEnable ADDRESS'; set it by hand")
    if out:
        report.item("management", "LLDP")
    return out


def read_lldp(device: Device, w: List[str]) -> bool:
    m = device.management
    if w[1:2] == ["refresh-interval"] and len(w) == 3:
        m.lldp_timer = int(w[2])
        if m.lldp_holdtime is not None:  # the multiplier came first
            m.lldp_holdtime = m.lldp_holdtime // LLDP_TIMER * m.lldp_timer
        return True
    if w[1:2] == ["holdtime-multiplier"] and len(w) == 3:
        m.lldp_holdtime = int(w[2]) * (m.lldp_timer or LLDP_TIMER)
        return True
    return False


def router_id(device: Device, ospf_router_id: str) -> List[str]:
    """ip router-id: AOS-S has one, used by OSPF; the global one when OSPF names none."""
    rid = ospf_router_id or device.system.router_id
    return [f"ip router-id {rid}"] if rid else []


def unwritable(device: Device, report: Report, port: Callable[[str], str]) -> None:
    """What AOS-S has no form for, reported once each with what to do instead."""
    d, rep = device, report
    sy, m = d.system, d.management

    def skip(kind: str, item: str, code: str, message: str) -> None:
        rep.skip(kind, item, code, message)

    def approx(kind: str, item: str, code: str, message: str) -> None:
        rep.add(kind, item, Severity.APPROX, code, message)

    def review(kind: str, item: str, code: str, message: str) -> None:
        rep.add(kind, item, Severity.REVIEW, code, message)

    # routing
    if sy.router_id and d.ospf and d.ospf[0].router_id and d.ospf[0].router_id != sy.router_id:
        approx("system", "router ID", "router-id",
               f"AOS-S has one router ID; OSPF's {d.ospf[0].router_id} is written and {sy.router_id} is left out")
    for route in d.static_routes:
        if route.tag is not None:
            approx("route", f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}", "route-tag",
                   f"AOS-S static routes carry no tag; tag {route.tag} is left out")
    for p in d.ospf:
        options = [what for what, stated in (("distribute-list", p.distribute_list_in),
                                             ("SPF and LSA timers", p.spf_timers or p.lsa_arrival),
                                             ("max-lsa", p.max_lsa), ("graceful restart", p.graceful_restart))
                   if stated]
        if options:
            approx("ospf", f"ospf {p.process}", "ospf-options",
                   f"AOS-S OSPF has no {', '.join(options)} setting; left out")
    for iface in d.interfaces.values():
        if iface.ospf_auth:
            review("interface", gaps.interface_item(rep, iface, port), "ospf-auth",
                   "the OSPF authentication is not written: AOS-S sets it on the VLAN with 'ip ospf AREA "
                   "authentication-key KEY' or 'md5-auth-key-chain CHAIN'; set the key by hand")
    for name, info in d.vrf_info.items():
        if info.export_map or info.rt_evpn or info.leaks:
            approx("system", f"vrf {name}", "evpn-vrf",
                   "AOS-S has no VRFs: the route targets, export map and leaked routes are left out")
    for cl in d.community_lists.values():
        skip("policy", f"community-list {cl.name}", "policy-lists",
             "AOS-S writes no BGP policy here (BGP is not converted to AOS-S); the community list is left out")
    for apl in d.as_path_lists.values():
        skip("policy", f"as-path list {apl.name}", "policy-lists",
             "AOS-S writes no BGP policy here (BGP is not converted to AOS-S); the AS-path list is left out")
    if d.pim_rp_groups or d.pim_anycast or d.msdp_peers or d.multicast_vrfs:
        review("system", "multicast routing", "pim-rp",
               "AOS-S PIM has no anycast RP, MSDP or multicast VRFs, and the RP group ranges are not written; "
               "configure the RP with 'router pim / rp-address' by hand")
    if d.ecmp_hash:
        approx("system", "ECMP hashing", "ecmp-hash", "AOS-S hashes on addresses; the hash fields are left out")
    if d.bfd_multihop is not None or d.bfd_slow_timer is not None:
        approx("system", "BFD", "bfd-global", "AOS-S has no BFD multihop or slow timer; left out")
    # the data-centre fabric
    vx = d.vxlan
    if vx is not None and (vx.evpn_instances or vx.mcast_groups):
        approx("interface", "VXLAN", "evpn-instances",
               "AOS-S has no EVPN or multicast underlay: the EVPN instances and multicast groups are left out")
    bgp = d.bgp
    if bgp is not None and (bgp.evpn_domain or bgp.evpn_remote_peers or bgp.evpn_host_flap):
        approx("bgp", f"bgp {bgp.local_as}", "evpn-domain", "AOS-S has no EVPN; the EVPN domain settings are left out")
    ml = d.mlag
    if ml is not None and (ml.heartbeat or ml.dual_primary_delay is not None or ml.reload_delay
                           or ml.reload_delay_non_mlag or ml.stack):
        review("interface", "multi-chassis LAG", "mlag-options",
               "the MLAG heartbeat, dual-primary detection and reload delays are not written: AOS-S pairs switches "
               "with distributed trunking ('switch-interconnect', 'distributed-trunking peer-keepalive') or stacks "
               "them with VSF; set it up by hand")
    for vlan in d.vlans.values():
        if vlan.trunk_groups:
            approx("vlan", str(vlan.vlan_id), "trunk-groups",
                   "AOS-S has no trunk groups; the VLAN is tagged on the ports that carry it")
    # queuing, security and multicast snooping
    if d.qos_profiles or d.qos_dscp_tc or d.qos_tc_dscp:
        review("qos", "DSCP to traffic-class map", "queuing",
               "the DSCP map and the queuing profiles are not written: AOS-S maps with 'qos dscp-map CODEPOINT "
               "priority N' and queues with 'qos queue-config' and 'qos type-of-service diff-services'; set them "
               "up by hand")
    cp = d.control_plane
    if cp is not None and (cp.acls or cp.classes or cp.policy):
        skip("system", "control plane", "copp",
             "AOS-S has no control-plane policy; it limits management access with 'ip authorized-managers'")
    if d.macsec_profiles or d.macsec_fips:
        skip("system", "MACsec", "macsec", "the MACsec profiles are not written: AOS-S switches do no MACsec "
             "(only some 3810M and 5400R v3 modules); set it up by hand where the hardware has it")
    for name in d.mac_acls:
        skip("acl", f"mac access-list {name}", "mac-acl",
             "AOS-S has no MAC access lists; filter by MAC with 'mac-lockout' or 'static-mac' by hand")
    if d.dhcp_option82 is not None:
        approx("system", "DHCP snooping", "option82",
               "the option 82 setting is not written: AOS-S takes 'dhcp-snooping option 82'; set it by hand")
    if d.aaa.coa:
        review("system", "RADIUS CoA", "coa",
               "RADIUS change of authorization is not written: AOS-S takes 'radius-server dyn-authorization' and "
               "'radius-server host A dyn-authorization'; set it by hand")
    if d.igmp_querier_address or d.igmp_querier_version or any(
            v.igmp_querier_address or v.igmp_querier_version for v in d.vlans.values()):
        approx("vlan", "IGMP snooping", "igmp-querier",
               "AOS-S runs the querier from the VLAN's own address; the querier's address and version are left out")
    # monitoring and management
    if d.twamp_port is not None:
        skip("monitor", "TWAMP reflector", "twamp", "AOS-S has no TWAMP reflector; left out")
    for session in d.mirror_sessions:
        if session.acl:
            review("monitor", f"mirror session {session.name}", "mirror-acl",
                   f"the mirror's ACL filter {session.acl} is not written: AOS-S mirrors by ACL with 'mirror N' on "
                   "the ACL's entries; set it by hand")
    sf = d.sflow
    if sf is not None and (sf.extensions or sf.source_vrf):
        approx("monitor", "sflow", "sflow-options", "AOS-S has no sFlow extensions or VRFs; left out")
    if d.netflow is not None and d.netflow.sample_rate:
        approx("monitor", "netflow", "netflow-sampling", "AOS-S has no NetFlow; the sampling is left out")
    if sy.banner_login:
        review("system", "banners", "banners",
               "AOS-S shows one banner before login, the motd" + (": the login banner is left out"
                                                                   if sy.banner_motd else
                                                                   ": the login banner is written as it"))
    if sy.logging_buffer is not None or sy.logging_buffer_level is not None or sy.logging_console_level is not None \
            or sy.logging_monitor_level is not None or sy.logging_timestamp or sy.logging_hostname \
            or sy.logging_facility_levels:
        approx("system", "local logging", "local-logging",
               "AOS-S has a fixed log buffer and no console level or syslog format; only 'logging severity' is "
               "written")
    if m.console_login:
        review("management", "console login", "console-login",
               f"login list {m.console_login} is not written: AOS-S takes 'aaa authentication console login'; set "
               "it by hand")
    if d.snmp.trap_types:
        approx("management", "snmp traps", "trap-types",
               "AOS-S sends its notifications by trap receiver; the choice of notifications ("
               + ", ".join(d.snmp.trap_types) + ") is left out")
    if d.roles or any(u.role for u in d.users):
        review("management", "roles", "roles",
               "the CLI roles are not written: AOS-S limits commands with 'aaa authorization group'; set them up by "
               "hand")
    if any(u.ssh_keys for u in d.users):
        review("management", "SSH keys", "ssh-keys",
               "the users' SSH keys are not written: AOS-S loads them with 'copy tftp pub-key-file' (or "
               "'ip ssh public-key manager'); load them by hand")
    if d.snmp.views or d.snmp.engine_id:
        review("management", "SNMP views", "snmp-views",
               "the SNMP views and engine ID are not written: AOS-S takes 'snmpv3 group ... read-view' with "
               "'snmp-server view'; set them by hand")
    if m.apis:
        review("management", "programmatic interfaces", "apis",
               "AOS-S offers the REST API over 'web-management ssl'; " + ", ".join(m.apis) + " is not written")
    if m.password_min_length is not None:
        approx("management", "password length", "password-length",
               "the minimum password length is not written: AOS-S sets it with 'password minimum-length'; set it "
               "by hand")
    if d.ptp is not None:
        skip("system", "PTP", "ptp", "AOS-S has no PTP; left out")
    for name in d.event_handlers:
        skip("system", f"event handler {name}", "event-handlers", "AOS-S has no event handlers; left out")
    # ports
    for iface in d.interfaces.values():
        label = gaps.interface_item(rep, iface, port)
        notes: List[Optional[str]] = [
            "the EVPN ethernet segment and LACP system ID (AOS-S has no EVPN)"
            if iface.evpn_esi or iface.lacp_system_id else None,
            "the SVI MAC address" if iface.mac_address else None,
            "no autostate" if iface.autostate is False else None,
            "the unnumbered address" if iface.unnumbered else None,
            "the trunk groups" if iface.trunk_groups else None,
            f"the queuing profile {iface.qos_profile}" if iface.qos_profile else None,
            "the port's own queue settings" if iface.queues else None,
            "the MACsec profile" if iface.macsec_profile else None,
            "the MAC access groups" if iface.mac_acl_in or iface.mac_acl_out else None,
            "unicast RPF" if iface.urpf else None,
            "ICMP redirects" if iface.ip_redirects is not None else None,
            "ICMP unreachables" if iface.ip_unreachables is not None else None,
            "proxy ARP" if iface.proxy_arp is not None else None,
            "the DHCP relay's server VRF and source interface (AOS-S has no VRFs; it relays from the VLAN)"
            if iface.helper_addresses and (iface.helper_vrf or iface.helper_source) else None,
            "the anycast gateway (AOS-S has no distributed gateway; use VRRP)"
            if iface.virtual_ipv4 or iface.virtual_ipv6 else None,
        ]
        found = [n for n in notes if n]
        if found:
            severity = Severity.REVIEW if iface.virtual_ipv4 or iface.virtual_ipv6 or iface.helper_vrf \
                or iface.helper_source or iface.unnumbered else Severity.APPROX
            rep.add("interface", label, severity, "aoss-port", "AOS-S has no form for " + ", ".join(found) +
                    "; left out")

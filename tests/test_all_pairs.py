from typing import Optional

import pytest
from helpers import DATA

from routershift import bgp as bgp_text
from routershift import nat as nat_text
from routershift import aaa as aaa_text
from routershift import snmp as snmp_text
from routershift import l2sec as l2sec_text
from routershift import mgmt as mgmt_text
from routershift import mpls as mpls_text
from routershift import qos as qos_text
from routershift import stp as stp_text
from routershift import wlan as wlan_text
from routershift import vpn as vpn_text
from routershift import vrfs as vrfs_text
from routershift import bfd as bfd_text
from routershift import igp as igp_text
from routershift import multicast as multicast_text
from routershift import monitor as monitor_text
from routershift import hosts as hosts_text
from routershift import vxlan as vxlan_text
from routershift import routemap as routemap_text
from routershift import ospf as ospf_text
from routershift.acl import safe_name
from routershift.convert import PLATFORMS, convert, parse
from routershift.model import AclAction, Device, Interface, InterfaceKind, StpMode

SAMPLES = {"ios": "ios_access.cfg", "eos": "eos_leaf.cfg", "aoscx": "aoscx_access.cfg", "aoss": "aoss_edge.cfg",
           "comware": "comware_access.cfg"}


def test_every_platform_has_a_sample() -> None:
    assert set(SAMPLES) == set(PLATFORMS)


@pytest.mark.parametrize("source", sorted(SAMPLES))
@pytest.mark.parametrize("target", sorted(PLATFORMS))
def test_converts_and_reads_back(source: str, target: str) -> None:
    text = (DATA / SAMPLES[source]).read_text(encoding="utf-8")
    first = parse(text, source)
    out, report = convert(text, source, target)
    back = parse(out, target)
    # the writer's own output holds nothing its reader does not understand
    assert [u.text for u in back.unparsed if not u.section.startswith("a trunk without")] == []
    # VLANs and layer 3 addresses survive every conversion
    assert set(first.vlans) <= set(back.vlans)
    # (the AOS switches have no tunnel interfaces)
    tunnels = target in vpn_text.SUPPORTED
    addresses = lambda dev: sorted(a for i in dev.interfaces.values() for a in i.ipv4  # noqa: E731
                                   if tunnels or i.kind != InterfaceKind.TUNNEL)
    assert addresses(first) == addresses(back)
    # every ACL arrives, with at least its convertible entries (more where a platform needs one port per entry),
    # and stays applied in the same direction
    for name, acl in first.acls.items():
        other = back.acls[safe_name(name)]
        rules = lambda a: [e for e in a.entries if e.action != AclAction.REMARK and not e.unsupported]  # noqa: E731
        assert len(rules(other)) >= len(rules(acl)), name
    bound = lambda dev: sorted((d, safe_name(getattr(i, d))) for i in dev.interfaces.values()  # noqa: E731
                               for d in ("acl_in", "acl_out", "acl6_in", "acl6_out") if getattr(i, d))
    assert bound(first) == bound(back)
    # every gateway redundancy address arrives
    virtual = lambda dev: sorted(a for i in dev.interfaces.values() for g in i.fhrp  # noqa: E731
                                 for a in [g.address] + g.secondary)
    assert virtual(first) == virtual(back)
    assert all(g.address for i in back.interfaces.values() for g in i.fhrp)
    # OSPF runs on the same number of interfaces, in the same areas, as passive or not, with the same router ID
    for p in first.ospf:
        other = next(o for o in back.ospf if o.router_id == p.router_id)
        areas = lambda dev, q: sorted((a, q.passive(i)) for i, a in ospf_text.interfaces(dev, q).items())  # noqa: E731
        assert areas(first, p) == areas(back, other)
        assert other.redistribute == p.redistribute and other.area_types == p.area_types
    costs = lambda dev: sorted(i.ospf_cost for i in dev.interfaces.values() if i.ospf_cost)  # noqa: E731
    assert costs(first) == costs(back)
    # DHCP pools keep their addresses and options (AOS-S has no VRFs)
    pools = lambda dev: sorted(  # noqa: E731
        (p.network, p.ranges, p.default_routers, p.dns_servers, p.domain_name, p.lease_seconds,
         p.vrf if target != "aoss" else "") for p in dev.dhcp_pools)
    assert pools(first) == pools(back)
    # NAT rules keep their addresses, sources and pools; EOS has no static port forwarding and the AOS switches
    # have no NAT, which the report says
    def nat(dev: Device) -> list:
        pool = lambda name: (dev.nat_pools[name].first, dev.nat_pools[name].last) if name else ()  # noqa: E731
        return sorted((r.kind, r.local, r.translated, r.protocol, r.local_port, r.translated_port,
                       safe_name(r.acl) if r.acl else "", pool(r.pool), r.overload) for r in dev.nat_rules
                      if not (target == "eos" and r.protocol))
    if target in nat_text.SUPPORTED:
        assert nat(first) == nat(back)
    else:
        assert not back.nat_rules
        assert not first.nat_rules or "do not do NAT" in report.to_text()
    # IPsec connections keep their peers, protected traffic, algorithms, PFS, lifetimes and readable keys; EOS has
    # route-based VPNs only, Comware is written with IKEv1 only, and the AOS switches have no IPsec
    def vpn(dev: Device) -> list:
        def key(address: str) -> str:
            psk = dev.psks.get(address)
            return psk.key if psk is not None and psk.key != vpn_text.PLACEHOLDER_KEY else ""
        transform = lambda name: ((t.encryption, t.integrity, t.mode)  # noqa: E731
                                  if (t := dev.ipsec_transforms.get(name)) else ())
        ike = lambda p: sorted((q.encryption, q.integrity, q.dh_groups, q.lifetime)  # noqa: E731
                               for q in vpn_text.policies_for(dev, p))
        return sorted((p.profile, vpn_text.peers_of(dev, p), [key(a) for a in vpn_text.peers_of(dev, p)],
                       safe_name(p.acl) if p.acl else "", [transform(t) for t in p.transforms], p.pfs_group,
                       p.lifetime, p.ike_version, ike(p)) for p in dev.ipsec_peers
                      if not (target == "eos" and not p.profile) and not (target == "comware" and p.ike_version != 1))
    if tunnels:
        assert vpn(first) == vpn(back)
        ikev2 = {p.name for p in first.ipsec_peers if p.ike_version == 2} if target == "comware" else set()
        tunnel = lambda dev: sorted(  # noqa: E731
            (bool(i.tunnel_source), i.tunnel_destination, i.tunnel_mode,
             i.tunnel_profile if i.tunnel_profile not in ikev2 else "")
            for i in dev.interfaces.values() if i.kind == InterfaceKind.TUNNEL)
        assert tunnel(first) == tunnel(back)
    else:
        assert not back.ipsec_peers
        assert not first.ipsec_peers or "do not terminate IPsec" in report.to_text()
    # NTP keeps its servers, keys and trust; SNMP its communities, location and contact, notification hosts and v3
    # users. Encrypted secrets come back as the placeholder. The AOS switches drop ACLs, groups and (AOS-S) VRFs and
    # SNMPv3 hosts, which the report says.
    plain = lambda value: "" if value in (snmp_text.PLACEHOLDER, vpn_text.PLACEHOLDER_KEY) else value  # noqa: E731
    ntp = lambda dev: (sorted(dev.system.ntp_servers), dev.system.ntp_prefer if target != "aoss" else "",  # noqa: E731
                       dev.system.ntp_server_keys,
                       sorted((k.number, k.algorithm, plain(k.key), k.trusted) for k in dev.system.ntp_keys.values()),
                       dev.system.ntp_authenticate or target == "aoss")
    assert ntp(first) == ntp(back)
    aos = target in ("aoscx", "aoss")
    snmp = lambda dev: (  # noqa: E731
        sorted((plain(c.name), c.access, "" if aos else safe_name(c.acl) if c.acl else "") for c in dev.snmp.communities),
        dev.snmp.location, dev.snmp.contact,
        sorted((h.address, h.version, plain(h.secret), h.informs, bool(h.vrf) and target != "aoss")
               for h in dev.snmp.hosts if not (target == "aoss" and h.version == "3")),
        sorted((u.name, "" if aos else u.group or u.name, u.auth, plain(u.auth_key), u.priv, plain(u.priv_key))
               for u in dev.snmp.users))
    assert snmp(first) == snmp(back)
    # AAA keeps every RADIUS and TACACS+ server with its key, the protocol and fallback of the login method list, and
    # every user whose password the source holds in clear text
    aaa = lambda dev: (  # noqa: E731
        sorted((s.protocol, s.address, plain(s.key)) for s in dev.aaa.servers),
        [(aaa_text.protocol_of(dev, m.methods[0]), m.methods[1:]) for m in dev.aaa.methods
         if (m.kind, m.service, m.name) == ("authentication", "login", "default")])
    assert aaa(first) == aaa(back)
    users = lambda dev: sorted(u.name for u in dev.users if u.password)  # noqa: E731
    assert users(first) == users(back)
    # 802.1X keeps the ports with 802.1X and MAB, their host mode and reauthentication, and the RADIUS servers they
    # use; TFTP and FTP keep their source interface (the AOS switches have no FTP client setting, and AOS-S takes a
    # VLAN or loopback only)
    dot1x = lambda dev: (  # noqa: E731
        dev.aaa.dot1x,
        sorted((i.dot1x, i.mab, i.dot1x_host_mode, i.dot1x_reauth, (i.dot1x_reauth_period or 3600) if i.dot1x_reauth
                else 0) for i in dev.interfaces.values() if i.dot1x or i.mab),
        [aaa_text.protocol_of(dev, m.methods[0]) for m in dev.aaa.methods if m.service == "dot1x"],
        sorted(k for k, source in dev.system.transfer_source.items() if not (aos and k == "ftp") and not (
            target == "aoss" and not source.startswith(("Vlan", "Loopback")))))
    assert dot1x(first) == dot1x(back)
    # Spanning tree keeps the bridge priority of every VLAN (per VLAN or through its MST instance), the MST region,
    # and the guards, BPDU filter, cost and priority of the ports (AOS-S has no loop guard)
    def priority(dev: Device, vlan: int) -> Optional[int]:
        instance = next((n for n, vlans in dev.stp.instances.items() if vlan in vlans), 0)
        return dev.stp.vlan_priority.get(vlan, dev.stp.priority.get(instance, dev.stp.priority.get(0)))

    vlans = sorted(first.vlans) or [1]
    assert [priority(first, v) for v in vlans] == [priority(back, v) for v in vlans]
    if first.stp_mode == StpMode.MSTP:
        region = lambda dev: (dev.stp.region, dev.stp.revision, dev.stp.instances)  # noqa: E731
        assert region(first) == region(back)
    stp_ports = lambda dev: sorted(  # noqa: E731
        ("" if target == "aoss" and i.stp_guard == "loop" else i.stp_guard, i.stp_bpdufilter, i.stp_cost,
         i.stp_port_priority) for i in dev.interfaces.values() if stp_text.has_port_settings(i)
        and not (target == "aoss" and i.stp_guard == "loop" and not (i.stp_bpdufilter or i.stp_cost or
                                                                     i.stp_port_priority)))
    assert stp_ports(first) == stp_ports(back)
    # MPLS keeps LDP on the same interfaces (known by their addresses) and the router ID; the AOS switches report it
    mpls_ports = lambda dev: sorted(tuple(i.ipv4) for i in mpls_text.interfaces(dev))  # noqa: E731
    if target in mpls_text.SUPPORTED:
        assert mpls_ports(first) == mpls_ports(back) and first.mpls.ldp == back.mpls.ldp
        assert mpls_text.router_address(first) == mpls_text.router_address(back)
    elif mpls_text.has_mpls(first):
        assert not mpls_text.has_mpls(back) and "has no MPLS" in report.to_text()
    # WLANs keep their SSID, VLAN, security and state on the controllers; the switches report each one
    wlans = lambda dev: sorted((w.ssid, w.vlan, w.security, w.enabled) for w in dev.wlans)  # noqa: E731
    if target in wlan_text.SUPPORTED:
        assert wlans(first) == wlans(back)
    elif first.wlans:
        assert not back.wlans and "is no wireless controller" in report.to_text()
    # Syslog keeps its level (AOS-S has five) and source; the management servers, the remote login limits and LLDP
    # keep what the target can say (AOS-CX has no Telnet or HTTP, EOS no web interface; only IOS and EOS take a login
    # ACL; AOS-CX only writes LLDP off; CDP lives on IOS and AOS-S)
    s1, s2 = first.system, back.system
    if s1.logging_level is not None and not (target == "aoscx" and not s1.syslog_servers):  # (set per server)
        assert s2.logging_level == (mgmt_text.level(mgmt_text.AOSS[s1.logging_level]) if target == "aoss"
                                    else s1.logging_level)
    if not (target == "aoss" and not s1.logging_source.startswith(("Vlan", "Loopback"))):
        assert bool(s2.logging_source) == bool(s1.logging_source)  # (management ports are renamed)
    m1, m2 = first.management, back.management
    assert (m2.ssh, m2.exec_timeout) == (m1.ssh or (None if target == "aoscx" else m1.ssh), m1.exec_timeout)
    # (an IOS or Comware VTY line that allows SSH shuts Telnet out)
    assert bool(m2.telnet) == bool(m1.telnet) and (m2.telnet is None) == (target == "aoscx" or m1.telnet is None
                                                                         and target not in ("ios", "comware"))
    assert m2.http == (None if target in ("aoscx", "eos") else m1.http)
    assert m2.https == (None if target == "eos" else m1.https)
    assert m2.vty_acl == (safe_name(m1.vty_acl) if target in ("ios", "eos") else "")
    assert m2.lldp == (None if target == "aoscx" and m1.lldp else m1.lldp)
    assert m2.cdp == (m1.cdp if target in ("ios", "aoss") else None)
    lldp_ports = lambda dev: sorted((i.lldp_tx, i.lldp_rx) for i in dev.interfaces.values()  # noqa: E731
                                    if not (i.lldp_tx and i.lldp_rx))
    assert lldp_ports(first) == lldp_ports(back)
    # L2 security keeps DHCP snooping (Comware snoops every VLAN), ARP inspection per VLAN, and per port the trust
    # (EOS snooping has no trusted ports), IP source guard, port security (AOS-CX writes no violation mode, EOS
    # protects for restrict) and storm control where the target has it (in whole percents on AOS-S and Comware)
    def snooped(dev: Device) -> set:
        return set(l2sec_text.snooping_vlans(dev)) or (set(dev.vlans) if dev.dhcp_snooping else set())

    assert bool(snooped(first)) == bool(snooped(back))
    if target != "comware":
        assert snooped(first) <= snooped(back)
    assert l2sec_text.inspection_vlans(first) == l2sec_text.inspection_vlans(back)
    storm_kinds = {"ios": ("broadcast", "multicast", "unicast"), "eos": ("broadcast", "multicast", "unknown-unicast"),
                   "aoscx": (), "aoss": ("broadcast",), "comware": ("broadcast", "multicast", "unknown-unicast")}

    def violation(v: str) -> str:
        # (AOS-CX states no violation mode, so the target's default is read back)
        return "" if "aoscx" in (source, target) else "protect" if target == "eos" and v == "restrict" else v

    def l2_ports(dev: Device, written: bool) -> list:
        def storm(i: Interface) -> list:
            levels = {("unicast" if k.endswith("unicast") else k): v for k, v in i.storm_control.items()}
            return sorted((k, round(v)) for k, v in levels.items()
                          if any(k == o or o.endswith("unicast") and k == "unicast" for o in storm_kinds[target]))

        return sorted((i.dhcp_trust and target != "eos", i.arp_trust, i.source_guard, i.port_security,
                       i.port_security_max, violation(i.port_security_violation) if written else
                       "" if source == "aoscx" else i.port_security_violation, storm(i)) for i in dev.interfaces.values()
                      if l2sec_text.has_port_settings(i))

    kept = lambda ports: [p for p in ports if any(p[:5]) or p[6]]  # noqa: E731
    assert kept(l2_ports(first, True)) == kept(l2_ports(back, False))
    # QoS keeps every applied policy with its classes (DSCP values, or an ACL with as many rules), markings and
    # police rates, and the trust of every port (AOS-CX has no default class; EOS takes no output policy)
    def qos(dev: Device) -> list:
        def matches(name: str) -> tuple:
            c = dev.qos_classes.get(name)
            if c is None:
                return ()
            acl = dev.acls.get(c.acl) if c.acl else None
            return (sorted(c.dscp), len([e for e in acl.entries if e.action != AclAction.REMARK]) if acl else 0)

        return sorted((d, [(matches(a.qos_class), a.set_dscp, a.police_kbps)
                                   for a in dev.qos_policies[getattr(i, d)].actions
                                   if not (target == "aoscx" and a.qos_class == qos_text.DEFAULT_CLASS)])
                      for i in dev.interfaces.values() for d in ("qos_policy_in", "qos_policy_out")
                      if getattr(i, d) and not (target == "eos" and d == "qos_policy_out"))

    assert qos(first) == qos(back)
    # (IOS writes nothing for DSCP trust, which a Catalyst 9000 does by default)
    trust = lambda dev: sorted(i.qos_trust for i in dev.interfaces.values()  # noqa: E731
                               if i.qos_trust and not (target == "ios" and i.qos_trust == "dscp"))
    assert trust(first) == trust(back)
    # BGP keeps every neighbor with its settings (peer groups may be written out on their members), networks and
    # redistribution; AOS-S leaves it to a person
    if first.bgp is not None and target == "aoss":
        assert back.bgp is None and "configure it by hand" in report.to_text()
    elif first.bgp is not None:
        assert back.bgp is not None
        assert (back.bgp.local_as, back.bgp.router_id) == (first.bgp.local_as, first.bgp.router_id)
        expected = bgp_text.flat(first.bgp)
        if target == "comware":  # EVPN is reported, not written
            for n in expected:
                n.families = [f for f in n.families if f != "evpn"]
        assert bgp_text.flat(back.bgp) == expected
        assert sorted(back.bgp.networks) == sorted(first.bgp.networks)
        assert (back.bgp.redistribute, back.bgp.redistribute6) == (first.bgp.redistribute, first.bgp.redistribute6)
    # VRF route leaking keeps every route distinguisher and route target outside the management VRF; AOS-S has no
    # VRFs and EOS sets them under router bgp
    def leaking(dev: Device) -> list:
        mgmt = {i.vrf for i in dev.interfaces.values() if i.kind == InterfaceKind.MANAGEMENT}
        return sorted((v.rd, sorted(vrfs_text.targets(v))) for name, v in dev.vrf_info.items()
                      if name not in mgmt and (v.rd or v.rt_import or v.rt_export))
    if target == "aoss" or (target == "eos" and first.bgp is None):
        assert not vrfs_text.has_leaking(back)
    else:
        assert leaking(back) == leaking(first)
    # a multi-chassis LAG pair (EOS MLAG, AOS-CX VSX) keeps its peer link and shared LAGs on EOS and AOS-CX
    if (first.mlag is not None or vrfs_text.mlag_members(first)) and target in ("eos", "aoscx"):
        assert back.mlag is not None and first.mlag is not None
        assert back.interfaces[back.mlag.peer_link].kind == InterfaceKind.LAG
        assert len(vrfs_text.mlag_members(back)) == len(vrfs_text.mlag_members(first))
        if back.mlag.peer_address:
            assert back.mlag.peer_address == first.mlag.peer_address
    elif first.mlag is not None:
        assert back.mlag is None and "multi-chassis LAG" in report.to_text()
    # prefix lists and route maps keep every entry (AOS-CX route maps match no ACL), and BGP neighbors and
    # redistribution keep the ones they apply; AOS-S writes none
    if target in routemap_text.SUPPORTED:
        prefixes = lambda dev: {n: (p.family, p.entries) for n, p in dev.prefix_lists.items()}  # noqa: E731
        assert prefixes(back) == prefixes(first)

        # (a route map only used for PBR is a PBR policy, its entries numbered anew on EOS, and missing on AOS-CX)
        pbr = bfd_text.pbr_only(first)

        def entries(dev: Device) -> dict:
            return {n: [(e.seq, e.action, e.match_prefix_lists, e.match_prefix_lists6,
                         [] if target == "aoscx" else [safe_name(a) for a in e.match_acls], e.match_tags, e.sets,
                         e.community_additive) for e in rm.entries] for n, rm in dev.route_maps.items()
                    if n not in pbr}
        assert entries(back) == entries(first)
        def pbr_entries(dev: Device) -> dict:
            return {n: [([safe_name(a) for a in e.match_acls], e.sets) for e in dev.route_maps[n].entries]
                    for n in pbr}
        if target != "aoscx":
            assert pbr_entries(back) == pbr_entries(first)
        policies = lambda dev: [(n.route_map_in, n.route_map_out, n.prefix_list_in, n.prefix_list_out)  # noqa: E731
                                for n in bgp_text.flat(dev.bgp)] if dev.bgp else []
        assert policies(back) == policies(first)
        if first.bgp is not None:
            assert back.bgp is not None and back.bgp.redistribute_maps == first.bgp.redistribute_maps
        assert [p.redistribute_maps for p in back.ospf] == [p.redistribute_maps for p in first.ospf]
    else:
        assert not back.route_maps and not back.prefix_lists
        if first.route_maps:
            assert "route maps are not written" in report.to_text()
    # BFD keeps its timers, BGP neighbors and OSPF interfaces (an "all interfaces" setting may be spread over them),
    # and PBR its route map on the interface; AOS-S has neither, AOS-CX no PBR
    if target == "aoss":
        assert not bfd_text.uses_bfd(back) and not bfd_text.pbr_maps(back)
    else:
        timers = lambda dev: sorted((i.bfd_interval, i.bfd_min_rx, i.bfd_multiplier)  # noqa: E731
                                    for i in dev.interfaces.values() if bfd_text.has_timers(i))
        assert timers(back) == timers(first)
        peers = lambda dev: [n.bfd for n in bgp_text.flat(dev.bgp)] if dev.bgp else []  # noqa: E731
        assert peers(back) == peers(first)
        assert len(bfd_text.ospf_interfaces(back)) == len(bfd_text.ospf_interfaces(first))
        if target != "aoscx":
            assert bfd_text.pbr_maps(back) == bfd_text.pbr_maps(first)
    # RIP keeps its networks, redistribution, default route and (but on EOS) version, summary and passive interfaces;
    # IS-IS its NETs, level, metric style (EOS is wide), redistribution and interfaces. AOS-CX and AOS-S write neither
    if target not in igp_text.SUPPORTED:
        assert back.rip is None and back.isis is None
    if first.rip is not None and target in igp_text.SUPPORTED:
        r1, r2 = first.rip, back.rip
        assert r2 is not None
        assert (sorted(r2.networks), r2.redistribute, r2.redistribute_maps, r2.default_originate) == (
            sorted(r1.networks), r1.redistribute, r1.redistribute_maps, r1.default_originate)
        if target != "eos":
            assert (r2.version, r2.auto_summary, r2.passive_default) == (r1.version, r1.auto_summary, r1.passive_default)
            assert (len(r2.passive_interfaces), len(r2.active_interfaces)) == (
                len(r1.passive_interfaces), len(r1.active_interfaces))
    if first.isis is not None and target in igp_text.SUPPORTED:
        i1, i2 = first.isis, back.isis
        assert i2 is not None
        assert (i2.nets, i2.level, i2.redistribute, i2.redistribute_maps) == (
            i1.nets, i1.level, i1.redistribute, i1.redistribute_maps)
        assert i2.wide_metrics == (i1.wide_metrics or target == "eos")
        ports = lambda dev: sorted((i.isis_passive, i.isis_metric or 0, i.isis_network)  # noqa: E731
                                   for i in dev.interfaces.values() if i.isis)
        assert ports(back) == ports(first)
    # IGMP snooping keeps the VLANs that snoop and (but on AOS-CX; IOS sets it for all) the querier; multicast routing
    # its RPs and the PIM mode (EOS runs sparse) and IGMP version of every interface (AOS-S writes none of it)
    assert multicast_text.snooped(back) == multicast_text.snooped(first)
    if target == "ios" and multicast_text.queriers(first):
        assert multicast_text.queriers(back) == multicast_text.snooped(first)
    elif target != "aoscx":
        assert multicast_text.queriers(back) == multicast_text.queriers(first)
    if target == "aoss":
        assert not multicast_text.uses_pim(back)
    else:
        assert (back.multicast_routing, back.pim_rps) == (first.multicast_routing, first.pim_rps)
        pim = lambda dev: sorted(("sparse" if target == "eos" and i.pim else i.pim, i.igmp_version or 0)  # noqa: E731
                                 for i in dev.interfaces.values() if i.pim or i.igmp_version)
        assert pim(back) == pim(first)
    # mirror sessions keep their sources (by direction) and destination; sFlow its collectors, rates and sampled ports
    # (IOS has none); NetFlow its collectors and the ports that record flows (written for IOS and Comware only)
    mirrors = lambda dev: sorted((sorted(s.sources.values()), bool(s.destination))  # noqa: E731
                                 for s in dev.mirror_sessions)
    assert mirrors(back) == mirrors(first)
    if first.sflow is None or target == "ios":
        assert back.sflow is None
    else:
        assert back.sflow is not None
        sflow = lambda sf: ([c.address for c in sf.collectors], sf.sample_rate, sf.polling_interval)  # noqa: E731
        assert sflow(back.sflow) == sflow(first.sflow)
        assert len(monitor_text.sflow_ports(back)) == len(monitor_text.sflow_ports(first))
    if first.netflow is None or target not in ("ios", "comware"):
        assert back.netflow is None
    else:
        assert back.netflow is not None
        flows = lambda dev: (sorted(i.flow for i in monitor_text.flow_ports(dev)),  # noqa: E731
                             [(c.address, c.port) for c in dev.netflow.collectors], dev.netflow.version)
        assert flows(back) == flows(first)
    # IP SLA probes (IOS, Comware NQA) keep target, source and timers; tracked objects what they follow and their
    # delays (EOS: interfaces only, no delays), and so do the static routes (IOS, Comware) and gateway groups that use
    # them; the Aruba switches write none of it
    slas = lambda dev: sorted((s.target, s.source_interface != "", s.source_address, s.frequency, s.timeout_ms)  # noqa
                              for s in dev.ip_slas.values())
    assert slas(back) == (slas(first) if target in ("ios", "comware") else [])
    kept = {t.name for t in first.tracks.values()
            if target in ("ios", "comware") or target == "eos" and t.interface}
    tracks = lambda ts, delays: sorted((t.sla != "", t.delay_up if delays else None,  # noqa: E731
                                        t.delay_down if delays else None) for t in ts)
    assert tracks(back.tracks.values(), target != "eos") == \
        tracks([t for t in first.tracks.values() if t.name in kept], target != "eos")
    routed = lambda dev: sum(1 for r in dev.static_routes if r.track)  # noqa: E731
    if target in ("ios", "comware"):
        assert routed(back) == sum(1 for r in first.static_routes if r.track in kept)
    else:
        assert routed(back) == 0
    decrements = lambda dev, names=None: sorted(dec for i in dev.interfaces.values() for g in i.fhrp  # noqa: E731
                                                for t, dec in g.tracks.items() if names is None or t in names)
    assert decrements(back) == decrements(first, kept)
    # the DNS client keeps lookup off (IOS), search domains (not AOS-S), source interface (IOS, EOS, Comware) and static
    # hosts (not AOS-S); PoE ports keep off (Comware: off by default), priority (the nearest the target has) and limit
    # (IOS, EOS, Comware)
    fs, bs = first.system, back.system
    assert (bs.dns_lookup is False) == (fs.dns_lookup is False and target == "ios")
    assert bs.dns_search == ([] if target == "aoss" else fs.dns_search)
    assert bool(bs.dns_source) == (bool(fs.dns_source) and target in ("ios", "eos", "comware"))
    assert bs.dns_hosts == ({} if target == "aoss" else fs.dns_hosts)
    allowed = {"ios": ("low", "high"), "eos": hosts_text.PRIORITIES}.get(target, ("low", "high", "critical"))
    on = lambda dev: [i for i in dev.interfaces.values() if i.poe is not False]  # noqa: E731
    assert sum(1 for i in back.interfaces.values() if i.poe is False) == \
        (0 if target == "comware" else sum(1 for i in first.interfaces.values() if i.poe is False))
    assert sorted(i.poe_priority for i in on(back) if i.poe_priority) == \
        sorted(hosts_text.poe_priority(i, allowed, lambda *a: None, target) for i in on(first) if i.poe_priority)
    assert sorted(i.poe_max_mw for i in on(back) if i.poe_max_mw) == \
        (sorted(i.poe_max_mw for i in on(first) if i.poe_max_mw) if target in ("ios", "eos", "comware") else [])
    # VXLAN keeps its source, the VNIs of VLANs and VRFs (IOS: VLANs only), the static flood list and the VLANs EVPN
    # advertises (IOS, EOS, AOS-CX)
    if first.vxlan is None or target in ("aoss", "comware"):
        assert back.vxlan is None
    else:
        fx, bx = first.vxlan, back.vxlan
        assert bx is not None
        assert bool(bx.source_interface) == bool(fx.source_interface)
        assert bx.vlan_vnis == fx.vlan_vnis and sorted(bx.evpn_vlans) == sorted(fx.evpn_vlans)
        assert sorted(bx.vrf_vnis.values()) == ([] if target == "ios" else sorted(fx.vrf_vnis.values()))
        assert bx.flood_vteps == (fx.flood_vteps if set(fx.vlan_vnis) - set(fx.evpn_vlans) else bx.flood_vteps)
    assert report.counts()

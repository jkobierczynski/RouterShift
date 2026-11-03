import pytest
from helpers import DATA, sample

from routershift import bgp as bgp_text
from routershift import ospf as ospf_text
from routershift.acl import safe_name
from routershift.convert import PLATFORMS, convert, parse
from routershift.model import AclAction, Device, InterfaceKind, LacpMode, SwitchportMode
from routershift.roundtrip import settings

XR = sample("iosxr_core.cfg")
SAMPLES = {"ios": "ios_access.cfg", "eos": "eos_leaf.cfg", "aoscx": "aoscx_access.cfg", "aoss": "aoss_edge.cfg",
           "comware": "comware_access.cfg", "junos": "junos_core.cfg", "nxos": "nxos_core.cfg",
           "eos-border": "eos_border_leaf.cfg"}
UNREAD = ["bfd mode ietf", "bfd address-family ipv4 fast-detect", "address-family vpnv4 unicast",
          "address-family vpnv4 unicast"]


def addresses(device: Device) -> list:
    return sorted(a for i in device.interfaces.values() if i.kind != InterfaceKind.TUNNEL for a in i.ipv4 + i.ipv6)


def virtual(device: Device) -> list:
    return sorted(a for i in device.interfaces.values() for g in i.fhrp for a in [g.address] + g.secondary)


def test_reads_the_sample() -> None:
    d = parse(XR, "iosxr")
    assert [u.text for u in d.unparsed] == UNREAD
    assert [u.group for u in d.unparsed] == ["BFD over bundle members"] * 2 + ["MPLS L3VPN (VPNv4) peering"] * 2
    sy = d.system
    assert sy.hostname == "pe-01" and sy.timezone == "Europe/Brussels" and sy.banner_motd == "Authorised access only."
    assert sy.domain_name == "example.net" and sy.dns_servers == ["10.0.0.53"] and sy.dns_lookup is False
    assert sy.service_vrf == "MGMT" and sy.syslog_servers == ["10.0.5.14"] and sy.logging_level == 4
    assert sy.logging_console_level == -1 and sy.logging_buffer == 1000000 and sy.logging_buffer_level == 6
    assert sy.ntp_servers == ["10.0.0.123"] and sy.ntp_prefer == "10.0.0.123"
    assert sy.ntp_server_keys == {"10.0.0.123": 1}
    assert sy.ntp_keys[1].key == "NtpK3y" and sy.ntp_keys[1].trusted and sy.ntp_authenticate
    assert sy.ntp_source == "Management1" and sy.logging_source == "Management1"
    assert [(u.name, u.privilege, u.hash_type) for u in d.users] == [("admin", 15, "sha512-crypt"),
                                                                    ("monitor", 1, "sha512-crypt")]
    a = d.aaa
    assert [(s.protocol, s.address, s.key, s.vrf) for s in a.servers] == [("tacacs", "10.0.0.49", "T4cacsKey", "MGMT")]
    assert a.groups["TACACS"].servers == ["10.0.0.49"] and a.source == {"tacacs": "Management1"}
    assert [(m.kind, m.service, m.methods) for m in a.methods] == [
        ("authentication", "login", ["group:TACACS", "local"]), ("authorization", "exec", ["group:TACACS", "local"]),
        ("accounting", "commands", ["group:TACACS"])]
    m = d.management
    assert m.ssh and m.vrf == "MGMT" and m.vty_acl == "MGMT-ONLY" and m.exec_timeout == 20 and m.lldp
    assert m.apis == {"netconf": ""}
    sn = d.snmp
    assert [(c.name, c.access, c.acl) for c in sn.communities] == [("r3adonly", "ro", "MGMT-ONLY")]
    assert [(h.address, h.version, h.secret, h.vrf) for h in sn.hosts] == [("10.0.5.20", "2c", "tr4ps", "MGMT")]
    assert sn.location == "Building 3" and sn.contact == "noc@example.net" and sn.traps
    i = d.interfaces
    assert i["Port-channel10"].kind == InterfaceKind.LAG and i["Port-channel10"].ipv4 == ["10.255.0.2/31"]
    assert i["Port-channel10"].mtu == 9216 and i["Port-channel10"].lacp_mode == LacpMode.ACTIVE
    assert i["Ethernet0/0/0/0"].lag == "Port-channel10" and i["Ethernet0/0/0/0"].media == "100g"
    assert i["Ethernet0/0/0/4"].media == "10g" and i["Ethernet0/0/0/4"].acl_in == "EDGE-IN"
    sub = i["Ethernet0/0/0/5.100"]
    assert sub.kind == InterfaceKind.SUBINTERFACE and sub.parent == "Ethernet0/0/0/5" and sub.encapsulation_vlan == 100
    assert sub.vrf == "CUST-A" and sub.ipv4 == ["10.100.1.1/29"]
    hsrp = sub.fhrp[0]
    assert (hsrp.protocol, hsrp.group, hsrp.version, hsrp.priority, hsrp.preempt, hsrp.address) == (
        "hsrp", 1, 2, 110, True, "10.100.1.3")
    assert i["Management1"].kind == InterfaceKind.MANAGEMENT and i["Management1"].vrf == "MGMT"
    assert i["Ethernet0/0/0/8"].shutdown and i["Port-channel10"].mpls and i["Ethernet0/0/0/4"].mpls
    assert d.mpls.ldp and d.mpls.router_id == "10.255.255.1"
    assert d.vrfs == ["MGMT", "CUST-A"]
    info = d.vrf_info["CUST-A"]
    assert (info.rd, info.rt_import, info.rt_export) == ("65000:100", ["65000:100"], ["65000:100"])
    routes = {(r.vrf, r.prefix): r for r in d.static_routes}
    assert routes[("", "0.0.0.0/0")].next_hop == "10.255.0.1" and routes[("", "10.200.0.0/16")].discard
    assert routes[("", "10.50.0.0/16")].distance == 250 and routes[("MGMT", "0.0.0.0/0")].next_hop == "192.168.255.1"
    assert routes[("CUST-A", "10.110.0.0/16")].tag == 100
    p = d.ospf[0]
    assert p.router_id == "10.255.255.1" and p.reference_bandwidth == 100000
    assert p.interface_areas == {"Loopback0": "0.0.0.0", "Port-channel10": "0.0.0.0", "Ethernet0/0/0/4": "0.0.0.0"}
    assert p.passive_interfaces == ["Loopback0"] and p.redistribute_maps == {"connected": "CONNECTED"}
    assert i["Port-channel10"].ospf_cost == 10 and i["Ethernet0/0/0/4"].ospf_network == "point-to-point"
    b = d.bgp
    assert b is not None and b.local_as == "65000" and b.router_id == "10.255.255.1"
    assert b.networks == ["10.255.255.1/32"]
    assert b.peer_groups["RR"].remote_as == "65000" and b.peer_groups["RR"].update_source == "Loopback0"
    flat = {n.address: n for n in bgp_text.flat(b)}
    assert flat["10.255.255.100"].description == "rr-01" and flat["10.255.255.100"].remote_as == "65000"
    transit = flat["10.255.0.1"]
    assert (transit.remote_as, transit.families, transit.route_map_in, transit.route_map_out) == (
        "65100", ["ipv4"], "PASS", "CONNECTED")
    v = b.vrfs["CUST-A"]
    assert v.redistribute == ["connected"] and v.neighbors[0].route_map_in == "CUST-A-IN"
    pl = d.prefix_lists["CUST-A-NETS"].entries[0]
    assert (pl.action, pl.prefix, pl.le) == (AclAction.PERMIT, "10.100.0.0/16", 24)
    e = d.route_maps["CUST-A-IN"].entries[0]
    assert e.match_prefix_lists == ["CUST-A-NETS"] and e.sets == {"local-preference": "200", "community": "65000:100"}
    assert e.community_additive and not e.unconverted
    assert [x.action for x in d.route_maps["CONNECTED"].entries] == [AclAction.PERMIT]


def test_iosxr_round_trip() -> None:
    first = parse(XR, "iosxr")
    out, report = convert(XR, "iosxr", "iosxr")
    back = parse(out, "iosxr")
    assert [u.text for u in back.unparsed] == []
    assert addresses(back) == addresses(first) and virtual(back) == virtual(first)
    # everything comes back as it was, apart from where it came from
    assert settings(back) == settings(first)
    assert "not written for IOS-XR" not in report.to_text()


@pytest.mark.parametrize("source", sorted(SAMPLES))
def test_every_sample_to_iosxr(source: str) -> None:
    platform = source.split("-")[0]
    text = (DATA / SAMPLES[source]).read_text(encoding="utf-8")
    first = parse(text, platform)
    out, report = convert(text, platform, "iosxr")
    back = parse(out, "iosxr")
    assert [u.text for u in back.unparsed] == []
    assert set(first.vlans) <= set(back.vlans)
    tunnels = lambda dev: sorted(a for i in dev.interfaces.values() if i.kind == InterfaceKind.TUNNEL  # noqa: E731
                                 and not (i.tunnel_mode == "ipsec" or i.tunnel_profile) for a in i.ipv4)
    assert addresses(back) == addresses(first) and tunnels(back) == tunnels(first)
    for name, acl in first.acls.items():
        assert len(back.acls[safe_name(name)].entries) >= len(acl.entries), name
    bound = lambda dev: sorted((d, safe_name(getattr(i, d))) for i in dev.interfaces.values()  # noqa: E731
                               if i.mode == SwitchportMode.ROUTED and not i.lag
                               for d in ("acl_in", "acl_out", "acl6_in", "acl6_out") if getattr(i, d))
    assert bound(back) == bound(first)
    assert virtual(back) == virtual(first)
    for p in first.ospf:
        other = next(o for o in back.ospf if o.vrf == p.vrf)
        areas = lambda dev, q: sorted((a, q.passive(i)) for i, a in ospf_text.interfaces(dev, q).items())  # noqa: E731
        assert areas(first, p) == areas(back, other)
    if first.bgp is not None:
        assert back.bgp is not None
        pairs = lambda b: sorted((n.address, n.remote_as) for n in bgp_text.flat(b))  # noqa: E731
        assert pairs(back.bgp) == pairs(first.bgp)
    assert set(back.prefix_lists) == set(first.prefix_lists)
    # every port keeps its layer 2 role: access ports their VLAN, trunks their VLANs
    ports = lambda dev: sorted((i.mode.value, i.access_vlan or 1) for i in dev.interfaces.values()  # noqa: E731
                               if i.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG) and not i.lag)
    assert ports(back) == ports(first)


@pytest.mark.parametrize("target", sorted(set(PLATFORMS)))
def test_iosxr_to_every_target(target: str) -> None:
    first = parse(XR, "iosxr")
    out, _ = convert(XR, "iosxr", target)
    back = parse(out, target)
    assert [u.text for u in back.unparsed if not u.section.startswith("a trunk without")] == []
    if target != "aoss":  # AOS-S has no VRFs and no subinterfaces, which the report says
        assert addresses(back) == addresses(first)


def test_vlans_become_bridge_domains() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "iosxr")
    assert "l2vpn\n bridge group VLANS\n" in out
    assert "  bridge-domain VLAN10-USERS\n   interface GigabitEthernet0/0/0/0\n" in out
    assert "   routed interface BVI99\n" in out and "interface BVI99\n" in out
    assert " encapsulation dot1q 20\n rewrite ingress tag pop 1 symmetric\n" in out
    assert " encapsulation untagged\n" in out
    back = parse(out, "iosxr")
    assert back.vlans[10].name == "USERS"
    assert "written as an l2transport port" in report.to_text()


def test_route_policy_from_route_map() -> None:
    text = "\n".join([
        "hostname r1",
        "ip prefix-list PL seq 5 deny 0.0.0.0/0",
        "ip prefix-list PL seq 10 permit 10.0.0.0/8 le 24",
        "ip as-path access-list 1 permit _65001$",
        "ip community-list standard CL permit 65000:1",
        "route-map RM deny 5",
        " match community CL",
        "route-map RM permit 10",
        " match ip address prefix-list PL",
        " match as-path 1",
        " set local-preference 150",
        " set as-path prepend 65000 65000",
        " set community 65000:2 65000:3 additive",
        "route-map RM permit 20",
        " set metric 50",
        "router bgp 65000",
        " neighbor 192.0.2.1 remote-as 65001",
        " neighbor 192.0.2.1 route-map RM in",
        " neighbor 192.0.2.2 remote-as 65002",
        " neighbor 192.0.2.3 remote-as 65003",
        " neighbor 192.0.2.3 prefix-list PL out",
        ""])
    first = parse(text, "ios")
    out, report = convert(text, "ios", "iosxr")
    assert "prefix-set PL\n  10.0.0.0/8 le 24\nend-set" in out and "prefix-set PL-DENY\n  0.0.0.0/0\nend-set" in out
    assert "as-path-set 1\n  ios-regex '_65001$'\nend-set" in out
    assert "  if community matches-any CL then\n    drop\n" in out
    assert "  elseif destination in PL and not destination in PL-DENY and as-path in 1 then\n" in out
    assert "    prepend as-path 65000 2\n    set community (65000:2, 65000:3) additive\n    pass\n" in out
    assert "  else\n    set med 50\n    pass\n  endif\n" in out
    # an eBGP neighbor without a policy keeps taking and sending routes; a prefix list becomes a policy
    assert "route-policy RS-PASS-ALL in" in out and "route-policy RS-PL-PL-OUT out" in out
    back = parse(out, "iosxr")
    entry = lambda e: (e.action, e.prefix, e.ge, e.le)  # noqa: E731
    assert list(map(entry, back.prefix_lists["PL"].entries)) == list(map(entry, first.prefix_lists["PL"].entries))
    entries = back.route_maps["RM"].entries
    assert [(e.seq, e.action) for e in entries] == [(10, AclAction.DENY), (20, AclAction.PERMIT),
                                                    (30, AclAction.PERMIT)]
    assert entries[1].sets == first.route_maps["RM"].entries[1].sets and entries[1].community_additive
    assert entries[1].match_as_paths == ["1"] and entries[1].match_prefix_lists == ["PL"]
    assert set(back.route_maps) == {"RM"}
    assert back.bgp is not None
    peers = {n.address: n for n in back.bgp.neighbors}
    assert peers["192.0.2.2"].route_map_in == "" and peers["192.0.2.3"].prefix_list_out == "PL"
    assert peers["192.0.2.1"].route_map_in == "RM"


def test_route_map_matching_an_acl_is_left_out() -> None:
    text = "\n".join(["ip access-list standard NETS", " permit 10.0.0.0 0.255.255.255",
                      "route-map RM permit 10", " match ip address NETS", " set tag 5",
                      "route-map RM permit 20", " set tag 6", ""])
    out, report = convert(text, "ios", "iosxr")
    assert "route-policy RM\n  set tag 6\n  pass\nend-policy" in out
    assert "entry 10 (permit) is left out" in report.to_text()


def test_fhrp_and_relay() -> None:
    out, report = convert(sample("nxos_core.cfg"), "nxos", "iosxr")
    assert "router hsrp\n interface BVI20\n  address-family ipv4\n   hsrp 20 version 2\n" in out
    assert "router vrrp\n interface BVI30\n  address-family ipv4\n   vrrp 30\n" in out
    assert "dhcp ipv4\n profile RS-RELAY-1 relay\n  helper-address vrf PROD 10.0.0.67\n" in out
    assert " interface BVI20 relay profile RS-RELAY-1\n" in out
    back = parse(out, "iosxr")
    assert back.interfaces["Vlan20"].helper_addresses == ["10.0.0.67"]


def test_names() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "iosxr")
    assert "interface Bundle-Ether10\n" in out and " bundle id 10 mode active\n" in out
    assert "interface Loopback0\n" in out and "interface MgmtEth0/RP0/CPU0/0\n vrf MGMT\n" in out
    assert "interface TenGigE0/0/0/" in out or "interface GigabitEthernet0/0/0/0" in out


def test_vrrp_group() -> None:
    text = ("vlan 5\ninterface Vlan5\n ip address 10.5.0.2 255.255.255.0\n vrrp 5 ip 10.5.0.1\n"
            " vrrp 5 ip 10.5.0.3 secondary\n"
            " vrrp 5 priority 120\n no vrrp 5 preempt\n vrrp 5 timers advertise 3\n vrrp 5 shutdown\n")
    out, report = convert(text, "ios", "iosxr")
    assert "router vrrp\n interface BVI5\n  address-family ipv4\n   vrrp 5\n    priority 120\n" in out
    back = parse(out, "iosxr")
    [g] = back.interfaces["Vlan5"].fhrp
    assert (g.group, g.address, g.secondary, g.priority, g.preempts(), g.hello_ms) == (
        5, "10.5.0.1", ["10.5.0.3"], 120, False, 3000)
    assert back.unparsed == []
    assert "IOS-XR has no shutdown for a group" in report.to_text()


def test_dhcp_server_and_rip() -> None:
    text = ("interface GigabitEthernet0/1\n ip address 10.20.0.1 255.255.255.0\n"
            "interface GigabitEthernet0/2\n ip address 10.30.0.1 255.255.255.0\n"
            "ip dhcp excluded-address 10.20.0.1 10.20.0.9\n"
            "ip dhcp pool VOICE\n network 10.20.0.0 255.255.255.0\n default-router 10.20.0.1\n"
            " dns-server 10.0.0.53\n domain-name voice.example\n lease 0 12\n"
            "router rip\n version 2\n network 10.0.0.0\n passive-interface GigabitEthernet0/2\n"
            " redistribute static\n default-metric 3\n no auto-summary\n")
    out, report = convert(text, "ios", "iosxr")
    assert "pool vrf default ipv4 VOICE\n network 10.20.0.0/24\n address-range 10.20.0.10 10.20.0.254\n" in out
    assert (" profile VOICE server\n  pool VOICE\n  default-router 10.20.0.1\n  dns-server 10.0.0.53\n"
            "  domain-name voice.example\n  lease 0 12 0\n") in out
    assert " interface GigabitEthernet0/0/0/0 server profile VOICE\n" in out
    assert ("router rip\n interface GigabitEthernet0/0/0/0\n !\n interface GigabitEthernet0/0/0/1\n"
            "  passive-interface\n !\n redistribute static\n default-metric 3\n") in out
    assert " yet" not in report.to_text()
    back = parse(out, "iosxr")
    assert back.unparsed == []
    [pool] = back.dhcp_pools
    assert (pool.network, pool.ranges, pool.dns_servers, pool.lease_seconds) == (
        "10.20.0.0/24", [("10.20.0.10", "10.20.0.254")], ["10.0.0.53"], 12 * 3600)
    assert back.rip is not None and back.rip.networks == ["10.20.0.0/24", "10.30.0.0/24"]
    assert back.rip.passive_interfaces == [back.interfaces[n].name for n in back.interfaces][1:2]


def test_nat_and_ipsec_are_reported() -> None:
    text = ("interface GigabitEthernet0/1\n ip address 192.0.2.1 255.255.255.0\n ip nat outside\n"
            "ip nat inside source static 10.0.0.5 192.0.2.5\n")
    _, report = convert(text, "ios", "iosxr")
    assert "CGN service card" in report.to_text() and " yet" not in report.to_text()


def test_qos_flow_mirror_and_tracking() -> None:
    text = ("ip access-list extended WEB\n permit tcp any any eq 443\n"
            "class-map match-any VOICE\n match dscp ef\nclass-map match-all WEB\n match access-group name WEB\n"
            "policy-map EDGE\n class VOICE\n  set dscp ef\n  police 2000000 8000 conform-action transmit"
            " exceed-action drop\n class WEB\n  set dscp af21\n"
            "flow exporter EXP\n destination 10.0.0.9\n source Loopback0\n transport udp 9995\n"
            "flow monitor MON\n exporter EXP\n record netflow ipv4 original-input\n"
            "ip sla 10\n icmp-echo 10.9.0.1 source-ip 10.1.0.1\n frequency 10\nip sla schedule 10 life forever"
            " start-time now\n"
            "track 1 ip sla 10 reachability\n delay down 5\ntrack 2 interface GigabitEthernet0/2 line-protocol\n"
            "interface Loopback0\n ip address 10.255.0.1 255.255.255.255\n"
            "interface GigabitEthernet0/1\n no switchport\n ip address 10.1.0.1 255.255.255.0\n"
            " service-policy input EDGE\n ip flow monitor MON input\n standby 1 ip 10.1.0.254\n"
            " standby 1 track 2 decrement 20\n"
            "interface GigabitEthernet0/2\n no switchport\n ip address 10.2.0.1 255.255.255.0\n"
            "interface GigabitEthernet0/3\n no switchport\n"
            "monitor session 1 source interface GigabitEthernet0/1 rx\n"
            "monitor session 1 destination interface GigabitEthernet0/3\n"
            "ip route 0.0.0.0 0.0.0.0 10.2.0.254 track 1\n")
    before = parse(text, "ios")
    out, report = convert(text, "ios", "iosxr")
    assert "policy-map EDGE\n class VOICE\n  set dscp ef\n  police rate 2000 kbps" in out
    assert " service-policy input EDGE\n" in out and " flow ipv4 monitor RS-MONITOR ingress\n" in out
    assert "flow exporter-map RS-EXPORTER\n" in out and " destination 10.0.0.9\n" in out
    assert "monitor-session SPAN1 ethernet\n destination interface GigabitEthernet0/0/0/2\n" in out
    assert " monitor-session SPAN1 ethernet direction rx-only\n" in out
    assert "ipsla\n operation 10\n  type icmp echo\n   destination address 10.9.0.1\n" in out
    assert "track 1\n type rtr 10 reachability\n delay down 5\n" in out
    assert " 0.0.0.0/0 10.2.0.254 track 1\n" in out and "    track object 2 20\n" in out
    back = parse(out, "iosxr")
    assert back.unparsed == []
    assert list(back.qos_classes) == ["VOICE", "WEB"] and back.qos_classes["WEB"].acl == "WEB"
    [voice, web] = back.qos_policies["EDGE"].actions
    assert (voice.set_dscp, voice.police_kbps, web.set_dscp) == (46, 2000, 18)
    g1 = back.interfaces["Ethernet0/0/0/0"]
    assert (g1.qos_policy_in, g1.flow) == ("EDGE", "input")
    assert back.netflow is not None and [(c.address, c.port) for c in back.netflow.collectors] == [("10.0.0.9", 9995)]
    [s] = back.mirror_sessions
    assert (s.name, s.destination, s.sources) == ("1", "Ethernet0/0/0/2", {"Ethernet0/0/0/0": "rx"})
    assert back.ip_slas["10"].target == "10.9.0.1" and back.ip_slas["10"].frequency == 10
    assert (back.tracks["1"].sla, back.tracks["1"].delay_down) == ("10", 5)
    assert back.tracks["2"].interface == "Ethernet0/0/0/1"
    assert [r.track for r in back.static_routes] == ["1"]
    assert back.interfaces["Ethernet0/0/0/0"].fhrp[0].tracks == {"2": 20}
    assert len(before.ip_slas) == 1 and "not written for IOS-XR" not in report.to_text()


def test_sflow_and_queuing_are_reported() -> None:
    out, report = convert(sample("eos_border_leaf.cfg"), "eos", "iosxr")
    text = report.to_text()
    assert "queuing profile" in text
    out, report = convert(sample("eos_leaf.cfg"), "eos", "iosxr")
    assert "IOS-XR has no sFlow" in report.to_text()

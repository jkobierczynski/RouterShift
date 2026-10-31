import pytest
from helpers import DATA, sample

from routershift import bgp as bgp_text
from routershift import ospf as ospf_text
from routershift.acl import safe_name
from routershift.convert import convert, parse
from routershift.model import Device, InterfaceKind, LacpMode, StpMode, SwitchportMode

NXOS = sample("nxos_core.cfg")
SAMPLES = {"ios": "ios_access.cfg", "eos": "eos_leaf.cfg", "aoscx": "aoscx_access.cfg", "aoss": "aoss_edge.cfg",
           "comware": "comware_access.cfg", "junos": "junos_core.cfg"}


def addresses(device: Device) -> list:
    return sorted(a for i in device.interfaces.values() if i.kind != InterfaceKind.TUNNEL for a in i.ipv4 + i.ipv6)


def virtual(device: Device) -> list:
    return sorted(a for i in device.interfaces.values() for g in i.fhrp for a in [g.address] + g.secondary)


def test_reads_the_sample() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == ["spanning-tree port type network"]
    sy = d.system
    assert sy.hostname == "dist-01" and sy.dns_servers == ["10.0.0.53"] and sy.service_vrf == "management"
    assert sy.ntp_servers == ["10.0.0.123"] and sy.ntp_keys[1].key == "NtpK3y" and sy.ntp_source == "Management1"
    assert sy.syslog_servers == ["10.0.5.14"] and sy.logging_level == 4
    assert [(u.name, u.privilege, u.hash_type) for u in d.users] == [("admin", 15, "sha256-crypt"),
                                                                    ("monitor", 1, "sha256-crypt")]
    assert d.management.telnet and d.management.ssh and d.management.lldp
    assert d.management.vty_acl == "MGMT-ONLY" and d.management.exec_timeout == 20
    i = d.interfaces
    assert i["Ethernet1/1"].mode == SwitchportMode.ACCESS and i["Ethernet1/1"].stp_portfast
    assert i["Ethernet1/49"].lag == "Port-channel1" and i["Ethernet1/49"].lacp_mode == LacpMode.ACTIVE
    assert i["Port-channel1"].native_vlan == 30 and i["Port-channel1"].allowed_vlans == "20,30"
    assert i["Ethernet1/51"].mode == SwitchportMode.ROUTED and i["Ethernet1/51"].ospf_network == "point-to-point"
    svi = i["Vlan20"]
    assert svi.vrf == "PROD" and svi.helper_addresses == ["10.0.0.67"] and svi.acl_in == "SERVERS-IN"
    hsrp = svi.fhrp[0]
    assert (hsrp.protocol, hsrp.group, hsrp.address, hsrp.priority, hsrp.preempt, hsrp.version) == (
        "hsrp", 20, "10.20.0.1", 110, True, 2)
    vrrp = i["Vlan30"].fhrp[0]
    assert (vrrp.protocol, vrrp.address, vrrp.priority, vrrp.preempt) == ("vrrp", "10.30.0.1", 120, True)
    assert i["Management1"].kind == InterfaceKind.MANAGEMENT and i["Management1"].vrf == "management"
    main, prod = d.ospf
    assert main.interface_areas == {"Ethernet1/51": "0.0.0.0", "Loopback0": "0.0.0.0"}
    assert main.passive_interfaces == ["Loopback0"] and main.reference_bandwidth == 100000
    assert main.redistribute_maps == {"connected": "CONNECTED"}
    assert prod.vrf == "PROD" and prod.interface_areas == {"Vlan20": "0.0.0.1"} and prod.passive("Vlan20")
    assert prod.area_types == {"0.0.0.1": "stub"}
    assert d.bgp is not None and d.bgp.networks == ["10.255.255.20/32"]
    flat = {n.address: n for n in bgp_text.flat(d.bgp)}
    assert flat["10.255.0.21"].families == ["ipv4"] and flat["10.255.0.21"].route_map_out == "CONNECTED"
    assert flat["10.255.0.21"].bfd and flat["10.255.0.21"].send_community
    assert flat["10.255.255.1"].families == ["evpn", "ipv4"] and flat["10.255.255.1"].next_hop_self
    assert flat["10.255.255.1"].update_source == "Loopback0"
    routes = {(r.vrf, r.prefix): r for r in d.static_routes}
    assert routes[("PROD", "10.210.0.0/16")].next_hop == "10.20.0.254"
    assert routes[("management", "0.0.0.0/0")].next_hop == "192.168.255.1"
    assert routes[("", "10.50.0.0/16")].distance == 250 and routes[("", "10.200.0.0/16")].discard
    assert d.stp_mode == StpMode.MSTP and d.stp.priority == {0: 8192, 1: 8192} and d.stp.instances == {1: [20, 30]}
    assert d.vrf_info["PROD"].rd == "65020:10"


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, _ = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert addresses(back) == addresses(first) and virtual(back) == virtual(first)
    assert bgp_text.flat(back.bgp) == bgp_text.flat(first.bgp)  # type: ignore[arg-type]
    assert back.system == first.system and back.stp == first.stp
    user = lambda u: (u.name, u.privilege, u.password_hash)  # noqa: E731
    assert list(map(user, back.users)) == list(map(user, first.users))
    route = lambda r: (r.vrf, r.prefix, r.next_hop, r.distance, r.discard)  # noqa: E731
    assert sorted(map(route, back.static_routes)) == sorted(map(route, first.static_routes))
    assert "feature hsrp" in out and "feature interface-vlan" in out and "nv overlay evpn" in out
    assert "no feature ssh" not in out


@pytest.mark.parametrize("source", sorted(SAMPLES))
def test_every_sample_to_nxos(source: str) -> None:
    text = (DATA / SAMPLES[source]).read_text(encoding="utf-8")
    first = parse(text, source)
    out, report = convert(text, source, "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert set(first.vlans) <= set(back.vlans)
    assert addresses(back) == addresses(first)
    # ACLs arrive with their entries and stay applied
    for name, acl in first.acls.items():
        assert len(back.acls[safe_name(name)].entries) >= len(acl.entries), name
    bound = lambda dev: sorted((d, safe_name(getattr(i, d))) for i in dev.interfaces.values()  # noqa: E731
                               for d in ("acl_in", "acl_out", "acl6_in", "acl6_out") if getattr(i, d))
    assert bound(back) == bound(first)
    assert virtual(back) == virtual(first)
    for p in first.ospf:
        other = next(o for o in back.ospf if o.vrf == p.vrf)
        areas = lambda dev, q: sorted((a, q.passive(i)) for i, a in ospf_text.interfaces(dev, q).items())  # noqa: E731
        assert areas(first, p) == areas(back, other)
    if first.bgp is not None:
        assert back.bgp is not None
        pairs = lambda b: sorted((n.address, n.remote_as, n.families) for n in bgp_text.flat(b))  # noqa: E731
        assert pairs(back.bgp) == pairs(first.bgp)
    assert set(back.prefix_lists) == set(first.prefix_lists) and set(back.route_maps) >= set(first.route_maps)
    for pool in first.dhcp_pools:
        assert report.items[("dhcp", f"{pool.name}" + (f" (vrf {pool.vrf})" if pool.vrf else ""))].skipped


@pytest.mark.parametrize("target", sorted(set(SAMPLES) - {"junos"}))
def test_nxos_to_every_target(target: str) -> None:
    first = parse(NXOS, "nxos")
    out, _ = convert(NXOS, "nxos", target)
    back = parse(out, target)
    assert [u.text for u in back.unparsed if not u.section.startswith("a trunk without")] == []
    assert set(first.vlans) <= set(back.vlans)
    assert addresses(back) == addresses(first)


def test_nxos_to_junos() -> None:
    out, _ = convert(NXOS, "nxos", "junos")
    assert [u.text for u in parse(out, "junos").unparsed] == []


def test_redistribution_gets_a_route_map() -> None:
    text = sample("ios_access.cfg").replace(" subnets route-map STATIC-TO-OSPF", " subnets")
    out, report = convert(text, "ios", "nxos")
    assert "redistribute static route-map RS-PERMIT-ALL" in out and "route-map RS-PERMIT-ALL permit 10" in out


def test_names() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "nxos")
    assert "interface port-channel10" in out and "channel-group 10 mode active" in out
    assert "interface loopback0" in out and "interface mgmt0\n  vrf member management" in out
    assert "interface Ethernet1/1\n" in out

import dataclasses

import pytest
from helpers import DATA, sample

from routershift import bgp as bgp_text
from routershift import ospf as ospf_text
from routershift.convert import convert, parse
from routershift.junostext import Tree, read
from routershift.model import Device, InterfaceKind, LacpMode, StpMode, SwitchportMode

JUNOS = sample("junos_core.cfg")
SAMPLES = {"ios": "ios_access.cfg", "eos": "eos_leaf.cfg", "aoscx": "aoscx_access.cfg", "aoss": "aoss_edge.cfg",
           "comware": "comware_access.cfg"}


def strip_lines(device: Device) -> dict:
    data = device.to_dict()

    def walk(value: object) -> object:
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items() if k not in ("origin", "line")}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return walk(data)  # type: ignore[return-value]


def addresses(device: Device) -> list:
    return sorted(a for i in device.interfaces.values() if i.kind != InterfaceKind.TUNNEL for a in i.ipv4 + i.ipv6)


def test_braces_and_set_lines_read_the_same() -> None:
    set_text = "\n".join(s.text for s in read(JUNOS))
    assert set_text.startswith("set version 21.4R3-S5.4\nset system host-name core-01")
    assert strip_lines(parse(set_text, "junos")) == strip_lines(parse(JUNOS, "junos"))


def test_reads_the_sample() -> None:
    d = parse(JUNOS, "junos")
    assert [u.text.split()[:3] for u in d.unparsed] == [["set", "system", "root-authentication"],
                                                         ["set", "system", "services"]]
    assert d.system.hostname == "core-01" and d.system.timezone == "Europe/Brussels"
    assert d.system.ntp_servers == ["10.0.0.123", "10.0.0.124"] and d.system.ntp_prefer == "10.0.0.123"
    assert d.system.ntp_keys[1].trusted and d.system.ntp_source == "Loopback0"
    assert d.system.syslog_servers == ["10.0.5.14"] and d.system.logging_level == 4
    assert d.system.banner_motd == "Authorised access only."
    assert [(u.name, u.privilege, u.hash_type) for u in d.users] == [("netops", 15, "sha512-crypt"),
                                                                    ("viewer", 1, "md5-crypt")]
    assert {v.vlan_id: v.name for v in d.vlans.values()} == {99: "MGMT", 10: "USERS", 20: "VOICE", 1: "default"}
    i = d.interfaces
    assert i["Ethernet0/0/0"].mode == SwitchportMode.ACCESS and i["Ethernet0/0/0"].access_vlan == 10
    assert i["Ethernet0/0/0"].stp_portfast and i["Ethernet0/0/0"].stp_bpduguard
    assert i["Ethernet0/0/1"].shutdown and not i["Ethernet0/0/1"].lldp_tx
    assert i["Ethernet0/1/0"].media == "10g" and i["Ethernet0/1/0"].lag == "Port-channel1"
    assert i["Ethernet0/1/0"].lacp_mode == LacpMode.ACTIVE
    lag = i["Port-channel1"]
    assert (lag.mode, lag.allowed_vlans, lag.native_vlan, lag.stp_cost) == (SwitchportMode.TRUNK, "10,20,99", 99, 2000)
    sub = i["Ethernet0/1/3.100"]
    assert sub.kind == InterfaceKind.SUBINTERFACE and sub.encapsulation_vlan == 100 and sub.parent == "Ethernet0/1/3"
    assert i["Vlan10"].vrf == "PROD" and i["Vlan99"].ipv6 == ["2001:db8:99::1/64"]
    assert i["Management0"].ipv4 == ["192.168.255.11/24"]
    assert d.vrf_info["PROD"].rd == "65010:10" and d.vrf_info["PROD"].rt_import == ["65000:10"]
    routes = {(r.vrf, r.prefix): r for r in d.static_routes}
    assert routes[("", "10.50.0.0/16")].distance == 250 and routes[("", "10.200.0.0/16")].discard
    assert routes[("PROD", "10.210.0.0/16")].next_hop == "10.10.0.254"
    main, prod = d.ospf
    assert main.router_id == "10.255.255.11" and main.reference_bandwidth == 100000
    assert main.interface_areas == {"Ethernet0/1/2": "0.0.0.0", "Loopback0": "0.0.0.0", "Vlan99": "0.0.0.0"}
    assert main.passive_interfaces == ["Loopback0"] and i["Ethernet0/1/2"].ospf_network == "point-to-point"
    assert prod.vrf == "PROD" and prod.area_types == {"0.0.0.1": "stub no-summary"} and prod.process == "2"
    assert d.bgp is not None and d.bgp.local_as == "65010"
    flat = {n.address: n for n in bgp_text.flat(d.bgp)}
    assert flat["10.255.0.11"].remote_as == "65000" and flat["10.255.0.11"].bfd
    assert flat["10.255.255.1"].remote_as == "65010" and flat["10.255.255.1"].update_source == "Loopback0"
    assert flat["10.255.255.1"].families == ["evpn", "ipv4"]
    assert d.stp_mode == StpMode.RSTP and d.stp.priority == {0: 8192}
    assert d.management.ssh and d.management.lldp


def test_secrets_stay_out_of_the_report() -> None:
    _, report = convert(JUNOS, "junos", "ios")
    assert "RootHashValue" not in report.to_text()


def test_junos_round_trip() -> None:
    first = parse(JUNOS, "junos")
    out, report = convert(JUNOS, "junos", "junos")
    back = parse(out, "junos")
    assert [u.text for u in back.unparsed] == []
    assert addresses(back) == addresses(first)
    assert {k: v.name for k, v in back.vlans.items()} == {k: v.name for k, v in first.vlans.items()}
    assert bgp_text.flat(back.bgp) == bgp_text.flat(first.bgp)  # type: ignore[arg-type]
    assert [dataclasses.replace(o, origin=first.ospf[0].origin) for o in back.ospf] == first.ospf
    assert sorted(map(repr, back.static_routes)) == sorted(map(repr, first.static_routes))
    assert back.system == first.system and back.users == first.users and back.stp == first.stp
    assert "members [ USERS VOICE MGMT ];" in out
    assert 'description "desk 1.01";' in out


@pytest.mark.parametrize("source", sorted(SAMPLES))
def test_every_sample_to_junos(source: str) -> None:
    text = (DATA / SAMPLES[source]).read_text(encoding="utf-8")
    first = parse(text, source)
    out, report = convert(text, source, "junos")
    back = parse(out, "junos")
    assert [u.text for u in back.unparsed] == []
    assert set(first.vlans) <= set(back.vlans)
    assert addresses(back) == addresses(first)
    # one OSPF per routing instance: each arrives on the same interfaces, in the same areas, passive or not
    for p in first.ospf:
        other = next(o for o in back.ospf if o.vrf == p.vrf)
        areas = lambda dev, q: sorted((a, q.passive(i)) for i, a in ospf_text.interfaces(dev, q).items())  # noqa: E731
        assert areas(first, p) == areas(back, other)
    route = lambda r: (r.vrf if r.vrf not in mgmt(first) else "mgmt_junos", r.prefix, r.next_hop, r.discard)  # noqa
    assert sorted(map(route, back.static_routes)) == sorted(map(route, first.static_routes))
    if first.bgp is not None:
        assert back.bgp is not None
        pairs = lambda b: sorted((n.address, bgp_text.remote_as(b, n)) for n in b.neighbors)  # noqa: E731
        assert pairs(back.bgp) == pairs(first.bgp)
    # what is not written yet is listed, not dropped
    for name in first.acls:
        assert report.items[("acl", name)].skipped


def mgmt(device: Device) -> set:
    return {i.vrf for i in device.interfaces.values() if i.kind == InterfaceKind.MANAGEMENT and i.vrf}


@pytest.mark.parametrize("target", sorted(SAMPLES))
def test_junos_to_every_target(target: str) -> None:
    first = parse(JUNOS, "junos")
    out, _ = convert(JUNOS, "junos", target)
    back = parse(out, target)
    assert [u.text for u in back.unparsed if not u.section.startswith("a trunk without")] == []
    assert set(first.vlans) <= set(back.vlans)
    if target != "aoss":  # (no subinterfaces: the routed port becomes a VLAN)
        assert addresses(back) == addresses(first)


def test_names() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "junos")
    assert "    ae9 {" in out and "802.3ad ae9;" in out and "device-count 20;" in out
    assert "l3-interface irb.100;" in out and "    me0 {" in out
    assert "interface irb.100;" in out  # in its routing instance


def test_fixed_time_zone() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "junos")
    assert "time-zone Etc/GMT-1;" in out
    assert report.items[("system", "time zone")].status == "approximated"


def test_tree_lists_and_inactive_set_lines() -> None:
    tree = Tree()
    tree.add("vlans", "A", "vlan-id 10")
    tree.add("x", "members A")
    tree.add("x", "members B")
    assert tree.render() == ["vlans {", "    A {", "        vlan-id 10;", "    }", "}", "x {", "    members [ A B ];",
                             "}"]
    statements = read("set system host-name a\ndeactivate system host-name\n")
    assert [s.inactive for s in statements] == [False, True]

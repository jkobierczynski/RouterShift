import pytest
from helpers import sample

from routershift import ospf as ospf_text
from routershift.convert import PLATFORMS, convert, parse


def test_area_forms() -> None:
    assert ospf_text.area("0") == ospf_text.area("backbone") == "0.0.0.0"
    assert ospf_text.area("10") == "0.0.0.10" and ospf_text.area("0.0.1.0") == "0.0.1.0"
    assert ospf_text.area_number("0.0.1.0") == "256"


def test_ios_reader() -> None:
    device = parse(sample("ios_access.cfg"), "ios")
    [p] = device.ospf
    assert (p.process, p.router_id, p.passive_default, p.active_interfaces, p.redistribute) == (
        "1", "10.255.255.1", True, ["Vlan99"], ["static"])
    assert [(n.prefix, n.area) for n in p.networks] == [("10.99.0.0/24", "0.0.0.0")]
    assert ospf_text.interfaces(device, p) == {"Vlan99": "0.0.0.0"}
    assert device.interfaces["Vlan99"].ospf_cost == 20


def test_ios_interface_areas_and_options() -> None:
    text = ("interface Loopback0\n ip address 10.0.0.1 255.255.255.255\n ip ospf 2 area 1\n"
            "interface GigabitEthernet0/1\n ip address 10.1.0.1 255.255.255.252\n ip ospf network point-to-point\n"
            " ip ospf 2 area 1\n"
            "router ospf 2\n auto-cost reference-bandwidth 100000\n area 1 nssa no-summary\n"
            " default-information originate always\n redistribute connected route-map RM\n log-adjacency-changes\n")
    device = parse(text, "ios")
    [p] = device.ospf
    assert p.interface_areas == {"Loopback0": "0.0.0.1", "Ethernet0/1": "0.0.0.1"}
    assert (p.reference_bandwidth, p.area_types, p.default_originate, p.redistribute) == (
        100000, {"0.0.0.1": "nssa no-summary"}, "always", ["connected"])
    assert p.redistribute_maps == {"connected": "RM"}
    assert device.interfaces["Ethernet0/1"].ospf_network == "point-to-point"
    assert device.unparsed == []
    out, _ = convert(text, "ios", "ios")
    assert " ip ospf 2 area 1\n" in out and " area 1 nssa no-summary\n" in out
    out, _ = convert(text, "ios", "eos")
    assert "   ip ospf area 0.0.0.1\n" in out and "   area 0.0.0.1 nssa no-summary\n" in out


def test_eos_reader_vrf_process() -> None:
    [p] = parse(sample("eos_leaf.cfg"), "eos").ospf
    assert (p.process, p.vrf, p.area_types) == ("10", "PROD", {"0.0.0.1": "stub"})


def test_aoscx_reader() -> None:
    device = parse(sample("aoscx_access.cfg"), "aoscx")
    [p] = device.ospf
    assert (p.router_id, p.passive_default, p.active_interfaces, p.interface_areas, p.redistribute) == (
        "10.255.255.2", True, ["Vlan99"], {"Vlan99": "0.0.0.0"}, ["connected"])


def test_comware_reader() -> None:
    device = parse(sample("comware_access.cfg"), "comware")
    [p] = device.ospf
    assert (p.router_id, p.passive_default, p.active_interfaces, p.redistribute) == (
        "10.255.255.4", True, ["Vlan99"], ["connected"])
    assert ospf_text.interfaces(device, p) == {"Vlan99": "0.0.0.0"}
    text = ("interface Vlan-interface5\n ip binding vpn-instance RED\n ip address 10.5.0.1 255.255.255.0\n"
            " ospf 2 area 0.0.0.3\n ospf network-type p2p\n#\nospf 2 vpn-instance RED router-id 10.5.0.1\n"
            " bandwidth-reference 10000\n area 0.0.0.3\n  nssa\n#\n")
    device = parse(text, "comware")
    [p] = device.ospf
    assert (p.process, p.vrf, p.router_id, p.interface_areas, p.area_types, p.reference_bandwidth) == (
        "2", "RED", "10.5.0.1", {"Vlan5": "0.0.0.3"}, {"0.0.0.3": "nssa"}, 10000)
    assert device.interfaces["Vlan5"].ospf_network == "point-to-point"
    assert device.unparsed == []


AOSS = ("ip routing\nip router-id 10.0.0.1\nrouter ospf\n   area backbone\n   area 0.0.0.2 stub 5 no-summary\n"
        "   redistribute connected\n   enable\n   exit\nvlan 10\n   ip address 10.10.0.1 255.255.255.0\n"
        "   ip ospf area backbone\n   ip ospf cost 15\n   exit\nvlan 20\n   ip address 10.20.0.1 255.255.255.0\n"
        "   ip ospf 10.20.0.1 area 0.0.0.2\n   ip ospf passive\n   exit\n")


def test_aoss_reader() -> None:
    device = parse(AOSS, "aoss")
    [p] = device.ospf
    assert (p.router_id, p.interface_areas, p.passive_interfaces, p.area_types, p.redistribute) == (
        "10.0.0.1", {"Vlan10": "0.0.0.0", "Vlan20": "0.0.0.2"}, ["Vlan20"], {"0.0.0.2": "stub no-summary"},
        ["connected"])
    assert device.interfaces["Vlan10"].ospf_cost == 15
    assert device.unparsed == []


def test_aoss_writer() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert "ip router-id 10.255.255.1\nrouter ospf\n   area backbone\n   redistribute static\n" in out
    assert "   ip ospf area backbone\n   ip ospf cost 20\n" in out
    out, report = convert(sample("comware_access.cfg"), "comware", "aoss")
    assert "   ip ospf area backbone\n" in out and "ip ospf passive" not in out


def test_aoss_runs_one_process() -> None:
    text = ("interface Vlan1\n ip address 10.1.0.1 255.255.255.0\n ip ospf 1 area 0\n"
            "interface Vlan2\n ip address 10.2.0.1 255.255.255.0\n ip ospf 2 area 0\n"
            "router ospf 1\nrouter ospf 2\n default-information originate\n")
    _, report = convert("vlan 1\nvlan 2\n" + text, "ios", "aoss")
    text = report.to_text()
    assert "ospf 2: skipped" in text and "AOS-S runs one OSPF process" in text


def test_redistribute_bgp_needs_a_bgp_process() -> None:
    text = "router ospf 1\n redistribute bgp 65000 subnets\n"
    out, report = convert(text, "ios", "ios")
    assert "redistribute bgp" not in out
    assert "redistribution of BGP left out" in report.to_text()


@pytest.mark.parametrize("target", sorted(set(PLATFORMS) - {"junos"}))
def test_every_writer_round_trips_a_process(target: str) -> None:
    text = ("vlan 10\nvlan 20\ninterface Vlan10\n ip address 10.10.0.1 255.255.255.0\n ip ospf cost 7\n"
            "interface Vlan20\n ip address 10.20.0.1 255.255.255.0\n"
            "router ospf 1\n router-id 10.0.0.1\n passive-interface Vlan20\n network 10.10.0.0 0.0.0.255 area 0\n"
            " network 10.20.0.0 0.0.255.255 area 0.0.0.2\n area 2 stub\n redistribute connected subnets\n")
    device = parse(text, "ios")
    out, _ = convert(text, "ios", target)
    back = parse(out, target)
    [p], [q] = device.ospf, back.ospf
    assert ospf_text.interfaces(back, q) == ospf_text.interfaces(device, p) == {
        "Vlan10": "0.0.0.0", "Vlan20": "0.0.0.2"}, target
    assert [q.passive(n) for n in ("Vlan10", "Vlan20")] == [False, True], target
    assert (q.router_id, q.area_types, q.redistribute) == ("10.0.0.1", {"0.0.0.2": "stub"}, ["connected"]), target
    assert back.interfaces["Vlan10"].ospf_cost == 7
    assert back.unparsed == [], target

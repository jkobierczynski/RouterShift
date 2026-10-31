from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    eos = parse(sample("eos_leaf.cfg"), "eos")
    vx = eos.vxlan
    assert vx is not None and (vx.source_interface, vx.udp_port) == ("Loopback0", 4789)
    assert (vx.vlan_vnis, vx.vrf_vnis, vx.flood_vteps, vx.evpn_vlans) == (
        {100: 10100, 200: 10200}, {"PROD": 50001}, ["10.255.255.9"], [100])
    assert eos.bgp is not None and [n.families for n in eos.bgp.neighbors if n.address == "10.255.255.9"] == \
        [["evpn", "ipv4"]]
    cx = parse(sample("aoscx_access.cfg"), "aoscx").vxlan
    assert cx is not None and (cx.source_interface, cx.vlan_vnis, cx.flood_vteps) == (
        "Loopback0", {10: 10010}, ["10.255.255.9"])
    ios_text = ("interface Loopback1\n ip address 10.0.0.1 255.255.255.255\n"
                "l2vpn evpn\n replication-type ingress\nl2vpn evpn instance 10 vlan-based\n encapsulation vxlan\n"
                "vlan configuration 10\n member evpn-instance 10 vni 10010\nvlan configuration 901\n member vni 50001\n"
                "interface nve1\n no ip address\n source-interface Loopback1\n host-reachability protocol bgp\n"
                " member vni 10010 ingress-replication\n member vni 50001 vrf PROD\n")
    ios = parse(ios_text, "ios")
    assert ios.vxlan is not None and (ios.vxlan.vlan_vnis, ios.vxlan.vrf_vnis, ios.vxlan.evpn_vlans) == (
        {10: 10010}, {"PROD": 50001}, [10])
    assert not ios.unparsed


def test_writers() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert "vlan configuration 100\n member evpn-instance 100 vni 10100\n" in out
    assert " host-reachability protocol bgp\n member vni 10100 ingress-replication\n member vni 10200\n" \
        "  ingress-replication 10.255.255.9\n" in out
    assert " address-family l2vpn evpn\n  neighbor 10.255.255.9 activate\n" in out
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "eos")
    assert "interface Vxlan1\n   vxlan source-interface Loopback0\n   vxlan vlan 10 vni 10010\n" \
        "   vxlan flood vtep 10.255.255.9\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "interface vxlan 1\n    source ip 10.255.255.1\n    no shutdown\n    vni 10100\n        vlan 100\n" in out
    assert "evpn\n    vlan 100\n        rd auto\n" in out


def test_reports() -> None:
    _, report = convert(sample("eos_leaf.cfg"), "eos", "comware")
    text = report.to_text()
    assert "Comware: VXLAN (VNIs 10100, 10200, 50001) is not written" in text
    assert "Comware: the EVPN address family of 10.255.255.9 is not written" in text
    _, report = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert "the VNIs of PROD are not written" in report.to_text()

"""Junos fabric: VXLAN and EVPN instances, L3 VNIs, ESI multihoming, MC-LAG, VRF route targets and leaks, and BGP in
VRFs, written from the border leaf and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _round_trip():
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def test_vxlan_and_evpn_instances() -> None:
    first, out, report, back = _round_trip()
    assert first.vxlan is not None and back.vxlan is not None
    assert back.vxlan.vlan_vnis == first.vxlan.vlan_vnis
    assert back.vxlan.vrf_vnis == first.vxlan.vrf_vnis
    assert "encapsulation vxlan;" in out and "extended-vni-list [ 10100 10110 " in out
    for name, inst in first.vxlan.evpn_instances.items():
        got = back.vxlan.evpn_instances[name]
        assert (got.vlans, got.rt_import, got.rt_export) == (inst.vlans, inst.rt_import, inst.rt_export), name
    # Junos' default switch has one route distinguisher: the instances' own are reported, not kept
    assert report.items[("interface", "VXLAN")].status == "approximated"
    assert first.bgp is not None and back.bgp is not None
    assert back.bgp.evpn_host_flap == first.bgp.evpn_host_flap
    # no EVPN domain gateway on Junos
    assert "EVPN domain gateway" in report.to_text() and back.bgp.evpn_domain == ""


def test_multihoming_and_mc_lag() -> None:
    first, out, report, back = _round_trip()
    esi = {i.source_name or i.name: i.evpn_esi for i in back.interfaces.values() if i.evpn_esi}
    assert esi == {"Port-channel20": "0000:0000:0021:0022:0020"} or list(esi.values()) == ["0000:0000:0021:0022:0020"]
    assert {i.mlag_id for i in back.interfaces.values() if i.mlag_id} == {10, 30}
    assert first.mlag is not None and back.mlag is not None
    for field in ("peer_link", "peer_address", "local_interface", "heartbeat", "reload_delay"):
        assert getattr(back.mlag, field) == getattr(first.mlag, field), field
    assert "multi-chassis-protection" in out and "mc-ae-id 10;" in out
    assert report.items[("interface", "multi-chassis LAG")].status == "approximated"  # made-up LACP IDs


def test_vrf_route_targets_and_leaks() -> None:
    first, out, report, back = _round_trip()
    for name, info in first.vrf_info.items():
        got = back.vrf_info[name]
        assert (got.rt_import, got.rt_export, got.export_map, got.leaks) == \
            (info.rt_import, info.rt_export, info.export_map, info.leaks), name
    assert "vrf-target target:50001:50001;" in out  # one target each way
    assert "vrf-import DMZ-IMPORT;" in out  # two import targets need a policy
    assert "instance-import PROD-LEAK;" in out


def test_bgp_in_vrfs() -> None:
    first, out, report, back = _round_trip()
    assert first.bgp is not None and back.bgp is not None
    assert set(back.bgp.vrfs) == set(first.bgp.vrfs)
    inet, src = back.bgp.vrfs["INET"], first.bgp.vrfs["INET"]
    assert [(n.address, n.peer_group, n.description) for n in sorted(inet.neighbors, key=lambda n: n.address)] == \
        [(n.address, n.peer_group, n.description) for n in sorted(src.neighbors, key=lambda n: n.address)]
    isp = inet.peer_groups["ISP-A"]
    assert (isp.remote_as, isp.local_as, isp.route_map_in, isp.maximum_prefix) == ("64496", "65021", "RM-ISP-A-IN",
                                                                                    1100000)
    assert inet.redistribute == src.redistribute and inet.aggregates == src.aggregates
    # a VRF neighbor of a global peer group stays in that peer group
    assert "MLAG-IPv4-UNDERLAY-PEER" not in back.bgp.vrfs["PROD"].peer_groups
    assert back.bgp.vrfs["DMZ"].neighbors[0].peer_group == "MLAG-IPv4-UNDERLAY-PEER"
    text = report.to_text()
    assert "TTL security (GTSM) not written for Junos" in text
    assert "Junos sends communities to every peer" in text  # ISP-B gets none on EOS
    assert "one export policy serves IPv4 and IPv6" in text  # DMZ redistributes static for IPv4 only


def test_reads_native_junos_fabric() -> None:
    text = """\
set vlans V10 vlan-id 10
set vlans V10 vxlan vni 10010
set vlans V20 vlan-id 20
set vlans V20 vxlan vni 10020
set switch-options vtep-source-interface lo0.0
set switch-options route-distinguisher 10.0.0.1:1
set switch-options vrf-target target:65000:1
set protocols evpn encapsulation vxlan
set protocols evpn extended-vni-list all
set interfaces ae1 esi 00:11:22:33:44:55:66:77:88:99
set interfaces ae1 esi all-active
set interfaces ae1 aggregated-ether-options lacp system-id 00:00:00:00:00:01
set interfaces ae1 unit 0 family ethernet-switching vlan members V10
set interfaces lo0 unit 0 family inet address 10.0.0.1/32
set routing-instances T1 instance-type vrf
set routing-instances T1 route-distinguisher 10.0.0.1:100
set routing-instances T1 vrf-target target:65000:100
set routing-instances T1 protocols evpn ip-prefix-routes vni 50100
set routing-options autonomous-system 65000
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    assert d.vxlan is not None and d.vxlan.vlan_vnis == {10: 10010, 20: 10020}
    assert d.vxlan.evpn_vlans == [10, 20] and d.vxlan.vrf_vnis == {"T1": 50100}
    assert d.vrf_info["T1"].rt_import == ["65000:100"] and d.vrf_info["T1"].rt_export == ["65000:100"]
    ae1 = d.interfaces["Port-channel2"]  # ae0 is Port-channel1
    assert ae1.evpn_esi and not ae1.evpn_single_active and ae1.lacp_system_id

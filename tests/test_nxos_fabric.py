"""NX-OS fabric: VXLAN and EVPN, the anycast gateway, vPC, VRF route targets, BGP templates and options."""

from helpers import sample

from routershift.convert import convert, parse

NXOS = sample("nxos_fabric.cfg")
EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    return first, out, report, back


def test_reads_nxos_fabric() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    vx = d.vxlan
    assert vx is not None and vx.source_interface == "Loopback1"
    assert vx.vlan_vnis == {100: 10100, 200: 10200} and vx.vrf_vnis == {"PROD": 50001}
    assert vx.evpn_vlans == [100, 200] and vx.mcast_groups == {200: "239.1.1.200"}
    assert vx.vrf_vlans == {"PROD": 3001} and 3001 not in d.vlans and "Vlan3001" not in d.interfaces
    assert vx.evpn_instances["100"].rt_import == ["65000:10100"] and "200" not in vx.evpn_instances
    assert d.anycast_mac == "00:1c:73:00:dc:01"
    assert d.interfaces["Vlan100"].virtual_ipv4 == ["10.1.100.1/24"] and d.interfaces["Vlan100"].ipv4 == []
    m = d.mlag
    assert m is not None and (m.domain, m.peer_link, m.heartbeat, m.heartbeat_vrf) == (
        "10", "Port-channel10", "192.168.0.2", "management")
    assert (m.reload_delay, m.reload_delay_non_mlag) == (300, 330)
    assert d.interfaces["Port-channel20"].mlag_id == 20
    assert d.vrf_info["PROD"].rt_evpn
    b = d.bgp
    assert b is not None and (b.keepalive, b.hold, b.graceful_restart_time, b.distance, b.multipath_relax) == (
        10, 30, 300, (20, 200, 220), True)
    assert b.peer_groups["SPINES"].remote_as == "65000" and b.neighbors[0].peer_group == "SPINES"
    assert b.neighbors[0].families == ["evpn"]
    assert b.vrfs["PROD"].aggregates[0].as_set and b.vrfs["PROD"].redistribute6 == ["connected"]
    assert "RS-PERMIT-ALL" not in d.route_maps and b.vrfs["PROD"].redistribute_maps == {}


def test_nxos_round_trip() -> None:
    first, out, report, back = _back(NXOS, "nxos")
    assert "  template peer SPINES\n" in out and "    inherit peer SPINES\n" in out
    assert back.vxlan == first.vxlan or (back.vxlan.vlan_vnis, back.vxlan.vrf_vnis, back.vxlan.evpn_vlans,
                                         back.vxlan.mcast_groups, back.vxlan.vrf_vlans) == (
        first.vxlan.vlan_vnis, first.vxlan.vrf_vnis, first.vxlan.evpn_vlans, first.vxlan.mcast_groups,
        first.vxlan.vrf_vlans)
    assert back.mlag == first.mlag
    assert back.anycast_mac == first.anycast_mac
    assert back.bgp.peer_groups == first.bgp.peer_groups and back.bgp.neighbors == first.bgp.neighbors
    for attr in ("keepalive", "hold", "graceful_restart", "graceful_restart_time", "distance", "multipath_relax",
                 "aggregates"):
        assert getattr(back.bgp, attr) == getattr(first.bgp, attr), attr
    assert back.bgp.vrfs["PROD"] == first.bgp.vrfs["PROD"]
    assert back.vrf_info == first.vrf_info


def test_from_eos_border_leaf() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "fabric forwarding anycast-gateway-mac 001c.7300.dc01\n" in out
    assert "interface Vlan100\n  description PROD-WEB\n  vrf member PROD\n  ip address 10.1.100.1/24\n" \
           "  fabric forwarding mode anycast-gateway\n" in out
    assert "  vpc peer-link\n" in out and "  vpc 10\n" in out
    assert "  peer-keepalive destination 10.100.10.22 source 10.100.10.21 vrf management\n" in out
    assert "  member vni 50001 associate-vrf\n" in out and "evpn\n  vni 10100 l2\n" in out
    assert "  ethernet-segment 20\n    system-mac 0021.0022.0020\n" in out
    assert "l2rib dup-host-mac-detection" in out
    vx, wx = first.vxlan, back.vxlan
    assert wx.vlan_vnis == vx.vlan_vnis and wx.vrf_vnis == vx.vrf_vnis
    assert sorted(wx.evpn_vlans) == sorted(vx.evpn_vlans) and wx.mcast_groups == vx.mcast_groups
    assert back.anycast_mac == first.anycast_mac
    for name, iface in first.interfaces.items():
        if iface.virtual_ipv4:
            assert back.interfaces[name].virtual_ipv4 == iface.virtual_ipv4
        if iface.mlag_id is not None:
            assert back.interfaces[name].mlag_id == iface.mlag_id
    assert back.mlag.peer_link == first.mlag.peer_link and back.mlag.heartbeat == first.mlag.heartbeat
    assert (back.mlag.reload_delay, back.mlag.reload_delay_non_mlag) == (300, 330)
    for name, info in first.vrf_info.items():
        if name in back.vrf_info and name != "MGMT":
            assert set(info.rt_export) <= set(back.vrf_info[name].rt_export)
    assert sorted(back.bgp.peer_groups) == sorted(set(first.bgp.peer_groups) | {
        g for v in first.bgp.vrfs.values() for g in v.peer_groups})
    for n in first.bgp.neighbors:
        m = next(x for x in back.bgp.neighbors if x.address == n.address)
        assert (m.peer_group, m.families) == (n.peer_group, n.families), n.address
    for attr in ("keepalive", "graceful_restart", "distance", "multipath_relax", "aggregates"):
        assert getattr(back.bgp, attr) == getattr(first.bgp, attr), attr
    assert _findings(report, "evpn-bundle") and _findings(report, "trunk-group") and _findings(report, "evpn-domains")
    assert not [m for m in _findings(report, "not-written") if "anycast gateway" in m or "EVPN" in m or "MLAG" in m]

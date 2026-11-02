"""AOS-CX data-centre fabric: EVPN instances, VSX options and VSF, VRF route targets and leaking, BGP options,
written and read back."""

from helpers import sample

from routershift import bgp as bgp_text
from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "aoscx")
    back = parse(out, "aoscx")
    assert [u.text for u in back.unparsed] == []
    return first, out, report, back


def test_evpn_instances() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "    vlan 100\n        rd auto\n        route-target both 50001:50001\n" in out
    assert back.vxlan is not None and back.vxlan.evpn_vlans == first.vxlan.evpn_vlans
    assert back.vxlan.evpn_instances["100"].rt_import == ["50001:50001"]
    [bundle] = [m for m in _findings(report, "evpn-bundle") if "PROD" in m]
    assert "10.255.0.21:50001 is left out" in bundle
    assert any("239.1.1.100" in m for m in _findings(report, "vxlan-mcast"))
    assert _findings(report, "evpn-domain") and _findings(report, "evpn-host-flap")


def test_vlan_based_instance_round_trip() -> None:
    text = ("hostname l1\nvlan 10\nevpn\n    vlan 10\n        rd 10.0.0.1:10\n        route-target export 65000:10\n"
            "        route-target import 65000:11\n")
    first, out, report, back = _back(text, "aoscx")
    inst = back.vxlan.evpn_instances["10"]
    assert (inst.rd, inst.rt_import, inst.rt_export) == ("10.0.0.1:10", ["65000:11"], ["65000:10"])
    assert "        rd 10.0.0.1:10\n" in out


def test_vrf_targets_and_leaking() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "        route-target both 50001:50001 evpn\n        route-target import 50004:50004 evpn\n" in out
    assert back.vrf_info["PROD"].rt_evpn and "50004:50004" in back.vrf_info["PROD"].rt_import
    [leak] = [m for m in _findings(report, "vrf-leak") if "INET" in m]
    assert "route map RM-INET-TO-EVPN is left out" in leak
    assert any("RM-EVPN-EXPORT-DMZ" in m for m in _findings(report, "vrf-export-map"))


def test_vsx_options() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "    keepalive peer 10.100.10.22 source 10.100.10.21 vrf mgmt\n" in out
    assert "    linkup-delay-timer 300\n" in out
    assert back.mlag is not None and back.mlag.reload_delay == 300
    assert _findings(report, "vsx-split") and _findings(report, "mlag-heartbeat")
    assert any("330 seconds" in m for m in _findings(report, "vsx-linkup"))
    assert any("LEAF_PEER_L3" in m for m in _findings(report, "trunk-group"))
    assert any("0000:0000:0021:0022:0020" in m for m in _findings(report, "evpn-es"))


def test_stackwise_virtual_as_vsf() -> None:
    ios = ("hostname core\nstackwise-virtual\n domain 7\ninterface TenGigabitEthernet1/0/47\n"
           " stackwise-virtual link 1\ninterface TenGigabitEthernet2/0/47\n stackwise-virtual link 1\n"
           "interface GigabitEthernet1/0/1\n stackwise-virtual dual-active-detection\n")
    first, out, report, back = _back(ios, "ios")
    assert "vsx" not in out.split()
    assert "vsf member 1\n    link 1 1/1/47\n" in out and "vsf member 2\n    link 1 2/1/47\n" in out
    assert "vsf split-detect mgmt\n" in out
    assert back.mlag is not None and back.mlag.stack
    assert sorted(i.svl_link for i in back.interfaces.values() if i.svl_link) == [1, 1]
    assert any("domain 7" in m for m in _findings(report, "vsf"))


def test_bgp_options() -> None:
    first, out, report, back = _back(EOS, "eos")
    for line in ("timers bgp 5 15", "graceful-restart restart-time 300", "distance bgp 20 200 200",
                 "bgp bestpath as-path multipath-relax", "bgp bestpath med missing-as-worst",
                 "aggregate-address 203.0.113.0/24 summary-only", "neighbor 10.0.1.0 maximum-prefix 12000"):
        assert line in out, line
    b, f = back.bgp, first.bgp
    assert (b.keepalive, b.hold, b.graceful_restart, b.graceful_restart_time, b.distance, b.multipath_relax) == \
        (f.keepalive, f.hold, f.graceful_restart, f.graceful_restart_time, f.distance, f.multipath_relax)
    assert [a.prefix for a in b.vrfs["INET"].aggregates] == [a.prefix for a in f.vrfs["INET"].aggregates]
    for name, v in f.vrfs.items():
        assert back.bgp.vrfs[name].redistribute6 == v.redistribute6, name
    isp = {n.address: n for n in b.vrfs["INET"].neighbors}["198.51.100.0"]
    assert (isp.remote_as, isp.maximum_prefix, isp.maximum_prefix_warning) == ("64496", 1100000, 90)
    assert not any("timers bgp" in m or "IPv6 address family" in m for m in _findings(report, "not-written"))


def test_global_router_id() -> None:
    eos = "hostname r\nrouter general\n   router-id ipv4 10.9.9.9\n!\nrouter bgp 65000\n   neighbor 10.0.0.2 " \
          "remote-as 65001\n"
    first, out, report, back = _back(eos, "eos")
    assert "bgp router-id 10.9.9.9" in out
    assert _findings(report, "router-id")


def test_neighbor_options() -> None:
    first, out, report, back = _back(EOS, "eos")
    isp = {n.address: n for n in back.bgp.vrfs["INET"].neighbors}
    src = {n.address: n for n in first.bgp.vrfs["INET"].neighbors}
    for address, peer in isp.items():
        want = bgp_text.effective(first.bgp, src[address], first.bgp.vrfs["INET"])
        assert (peer.local_as, peer.ttl_security, peer.remove_private_as) == \
            (want.local_as, want.ttl_security, want.remove_private_as), address
    assert not _findings(report, "bgp-option")
    assert _findings(report, "bgp-remove-private")

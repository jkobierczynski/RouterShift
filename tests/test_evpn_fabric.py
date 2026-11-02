"""EVPN beyond the VNIs: instances with their RD and route targets, VLAN-aware bundles, layer 3 VNIs on IOS,
multihoming, the multicast underlay and the DCI domain gateway, both ways between EOS and IOS."""

from helpers import sample

from routershift.convert import convert, parse

EOS = """\
hostname leaf
vlan 100
vlan 110
vlan 300
vrf instance PROD
interface Ethernet10/1
   channel-group 20 mode active
interface Port-Channel20
   switchport mode trunk
   switchport trunk allowed vlan 300
   evpn ethernet-segment
      identifier 0000:0000:0021:0022:0020
      route-target import 00:21:00:22:00:20
      designated-forwarder election algorithm preference value 200
   lacp system-id 0021.0022.0020
interface Loopback0
   ip address 10.255.0.21/32
interface Loopback1
   ip address 10.255.1.21/32
interface Vlan100
   vrf PROD
   ip address virtual 10.1.100.1/24
ip virtual-router mac-address 00:1c:73:00:dc:01
interface Vxlan1
   vxlan source-interface Loopback1
   vxlan virtual-router encapsulation mac-address mlag-system-id
   vxlan udp-port 4789
   vxlan vlan 100 vni 10100
   vxlan vlan 110 vni 10110
   vxlan vlan 300 vni 10300
   vxlan vrf PROD vni 50001
   vxlan mcast-group 239.1.1.100 vlan 100
   vxlan qos ecn propagation
router bgp 65021
   router-id 10.255.0.21
   neighbor EVPN peer group
   neighbor EVPN remote-as 65000
   neighbor EVPN update-source Loopback0
   neighbor DCI peer group
   neighbor DCI remote-as 65121
   neighbor 10.255.0.1 peer group EVPN
   neighbor 10.254.0.21 peer group DCI
   vlan-aware-bundle PROD
      rd 10.255.0.21:50001
      route-target both 50001:50001
      redistribute learned
      redistribute igmp
      vlan 100,110
   vlan 300
      rd 10.255.0.21:10300
      route-target import 300:300
      route-target export 300:301
      redistribute learned
   address-family evpn
      neighbor EVPN activate
      neighbor DCI activate
      neighbor DCI domain remote
      neighbor default next-hop-self received-evpn-routes route-type ip-prefix inter-domain
      domain identifier 65021:1
      domain identifier 65121:1 remote
      route import match-failure action discard
      host-flap detection window 180 threshold 5 expiry timeout 600
   vrf PROD
      rd 10.255.0.21:50001
      route-target import evpn 50001:50001
      route-target export evpn 50001:50001
      redistribute connected
"""


def test_eos_reads_instances_segments_and_domains() -> None:
    d = parse(EOS, "eos")
    vx = d.vxlan
    assert vx is not None and sorted(vx.evpn_vlans) == [100, 110, 300]
    bundle = vx.evpn_instances["PROD"]
    assert bundle.bundle and bundle.vlans == [100, 110] and bundle.rd == "10.255.0.21:50001" and bundle.igmp
    assert bundle.rt_import == bundle.rt_export == ["50001:50001"]
    v300 = vx.evpn_instances["300"]
    assert v300.rt_import == ["300:300"] and v300.rt_export == ["300:301"]
    assert vx.mcast_groups == {100: "239.1.1.100"} and vx.mlag_shared_mac and vx.qos_propagation == ["ecn"]
    po = d.interfaces["Port-channel20"]
    assert po.evpn_esi == "0000:0000:0021:0022:0020" and po.evpn_df_preference == 200
    assert po.lacp_system_id == "0021.0022.0020"
    assert d.bgp is not None and d.bgp.evpn_domain == "65021:1" and d.bgp.evpn_remote_domain == "65121:1"
    assert d.bgp.evpn_remote_peers == ["DCI"] and d.bgp.evpn_inter_domain_nhs and d.bgp.evpn_host_flap == (180, 5, 600)
    assert d.unparsed == []


def test_eos_to_eos_keeps_everything() -> None:
    out, _ = convert(EOS, "eos", "eos")
    assert "   vlan-aware-bundle PROD\n      rd 10.255.0.21:50001\n      route-target both 50001:50001\n" \
        "      redistribute learned\n      redistribute igmp\n      vlan 100,110\n" in out
    assert "   vlan 300\n      rd 10.255.0.21:10300\n      route-target import 300:300\n" \
        "      route-target export 300:301\n" in out
    assert "      neighbor DCI domain remote\n" in out and "      domain identifier 65121:1 remote\n" in out
    assert "   evpn ethernet-segment\n      identifier 0000:0000:0021:0022:0020\n" in out
    assert "   vxlan mcast-group 239.1.1.100 vlan 100\n" in out
    assert parse(out, "eos").unparsed == []


def test_eos_to_ios() -> None:
    out, report = convert(EOS, "eos", "ios")
    # one VLAN-based instance per VLAN of the bundle, with its route targets; the RD is automatic
    assert "l2vpn evpn instance 100 vlan-based\n encapsulation vxlan\n replication-type static\n" \
        " route-target import 50001:50001\n route-target export 50001:50001\n" in out
    assert "l2vpn evpn instance 300 vlan-based\n encapsulation vxlan\n rd 10.255.0.21:10300\n" \
        " route-target import 300:300\n route-target export 300:301\n" in out
    # the layer 3 VNI gets a VLAN, an SVI in the VRF and a member line on nve1
    assert "vlan configuration 3900\n member vni 50001\n" in out
    assert "interface Vlan3900\n description L3VNI PROD\n vrf forwarding PROD\n ip unnumbered Loopback1\n" \
        " no autostate\n" in out
    assert " member vni 50001 vrf PROD\n" in out and " member vni 10100 mcast-group 239.1.1.100\n" in out
    assert "  advertise l2vpn evpn\n" in out
    # multihoming
    assert "l2vpn evpn ethernet-segment 20\n identifier type 0 00.00.00.00.21.00.22.00.20\n" \
        " redundancy all-active\n df-election preference 200\n" in out
    assert "interface Port-channel20\n" in out and " evpn ethernet-segment 20\n" in out
    assert " mac duplication limit 5 time 180\n" in out and " default-gateway advertise enable\n" in out
    text = report.to_text()
    assert "VLAN-aware bundle PROD becomes one VLAN-based EVPN instance per VLAN (100,110)" in text
    assert "IOS XE has no EVPN domain gateway" in text
    assert "VNI 50001 (PROD) in VLAN 3900" in text
    # the reader takes it all back
    back = parse(out, "ios")
    assert back.unparsed == [] or all("CHANGE-ME" in u.text for u in back.unparsed)


def test_ios_to_eos_round_trip() -> None:
    ios, _ = convert(EOS, "eos", "ios")
    back = parse(ios, "ios")
    vx = back.vxlan
    assert vx is not None and vx.vrf_vnis == {"PROD": 50001} and vx.vrf_vlans == {"PROD": 3900}
    assert 3900 not in back.vlans and "Vlan3900" not in back.interfaces
    assert vx.mcast_groups == {100: "239.1.1.100"}
    assert vx.evpn_instances["300"].rd == "10.255.0.21:10300"
    assert back.interfaces["Port-channel20"].evpn_esi == "0000:0000:0021:0022:0020"
    # the distributed anycast gateway comes back as an EOS virtual address
    assert back.interfaces["Vlan100"].virtual_ipv4 == ["10.1.100.1/24"] and back.anycast_mac == "00:1c:73:00:dc:01"
    eos, report = convert(ios, "ios", "eos")
    assert "vlan 3900" not in eos and "Vlan3900" not in eos
    assert "   vxlan vrf PROD vni 50001\n" in eos and "   ip address virtual 10.1.100.1/24\n" in eos
    assert "      route-target import 300:300\n" in eos
    assert "   evpn ethernet-segment\n      identifier 0000:0000:0021:0022:0020\n" in eos
    findings = [f.message for item in report.items.values() for f in item.findings]
    assert any("left out: EOS maps a VRF to its VNI directly" in m for m in findings)


def test_border_leaf_sample_round_trips() -> None:
    text = sample("eos_border_leaf.cfg")
    ios, _ = convert(text, "eos", "ios")
    eos, _ = convert(ios, "ios", "eos")
    back = parse(eos, "eos")
    first = parse(text, "eos")
    assert first.vxlan is not None and back.vxlan is not None
    assert back.vxlan.vrf_vnis == first.vxlan.vrf_vnis and back.vxlan.vlan_vnis == first.vxlan.vlan_vnis
    assert back.interfaces["Port-channel20"].evpn_esi == first.interfaces["Port-channel20"].evpn_esi

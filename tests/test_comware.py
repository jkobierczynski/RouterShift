from helpers import sample

from routershift.convert import convert, parse
from routershift.model import InterfaceKind, LacpMode, StpMode, SwitchportMode
from routershift.parsers.comware import canonical, ranges, vlan_list


def test_names_and_vlan_lists() -> None:
    assert canonical("Ten-GigabitEthernet1/0/49") == ("Ethernet1/0/49", InterfaceKind.ETHERNET, "10g")
    assert canonical("XGE1/0/49")[0] == "Ethernet1/0/49"
    assert canonical("Bridge-Aggregation1")[:2] == ("Port-channel1", InterfaceKind.LAG)
    assert canonical("Vlan-interface99")[:2] == ("Vlan99", InterfaceKind.VLAN)
    assert canonical("M-GigabitEthernet0/0/0")[1] == InterfaceKind.MANAGEMENT
    assert vlan_list(["10", "20", "30", "to", "33"]) == [10, 20, 30, 31, 32, 33]
    assert ranges([33, 10, 31, 32, 30, 20]) == "10,20,30-33"


def test_parse_comware_access_switch() -> None:
    dev = parse(sample("comware_access.cfg"), "comware")
    assert dev.system.hostname == "sw-access-04"
    assert dev.system.timezone == "CET 1 0"
    assert dev.system.service_vrf == "mgmt"
    assert dev.system.banner_motd == "Authorised access only."
    assert dev.stp_mode == StpMode.RSTP
    desk = dev.interfaces["Ethernet1/0/1"]  # a hybrid port with a voice VLAN
    assert (desk.mode, desk.access_vlan, desk.voice_vlan) == (SwitchportMode.ACCESS, 10, 20)
    assert desk.stp_portfast and desk.stp_bpduguard  # global bpdu-protection guards the edge ports
    assert dev.interfaces["Ethernet1/0/3"].stp_bpduguard is None
    assert dev.interfaces["Ethernet1/0/48"].mode == SwitchportMode.ROUTED
    uplink = dev.interfaces["Ethernet1/0/49"]
    assert (uplink.lag, uplink.lacp_mode, uplink.media) == ("Port-channel1", LacpMode.ACTIVE, "10g")
    bagg = dev.interfaces["Port-channel1"]
    assert (bagg.mode, bagg.native_vlan, bagg.allowed_vlans) == (SwitchportMode.TRUNK, 99, "10,20,99")
    assert dev.interfaces["Vlan99"].helper_addresses == ["10.0.0.67"]
    assert dev.interfaces["Management1"].vrf == "mgmt"
    assert "NULL0" not in {i.source_name for i in dev.interfaces.values()}
    routes = [(r.prefix, r.vrf, r.next_hop, r.discard, r.distance, r.name) for r in dev.static_routes]
    assert ("10.50.0.0/16", "", "10.255.0.4", False, 250, "backup path") in routes
    assert ("10.200.0.0/16", "PROD", "", True, None, "") in routes


def test_trunk_permits_vlan_1_by_default() -> None:
    dev = parse("interface GigabitEthernet1/0/1\n port link-type trunk\n port trunk permit vlan 10\n#\n", "comware")
    assert dev.interfaces["Ethernet1/0/1"].allowed_vlans == "1,10"


def test_comware_to_ios() -> None:
    out, report = convert(sample("comware_access.cfg"), "comware", "ios")
    assert " switchport voice vlan 20\n" in out
    assert "ip route 10.50.0.0 255.255.0.0 10.255.0.4 250 name backup_path\n" in out
    assert "clock timezone CET 1 0\n" in out
    text = report.to_text()
    assert "abcdefSecret" not in text and "secrethash" not in text


def test_ios_to_comware() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert " sysname sw-access-01\n" in out
    assert " clock timezone CET add 01:00:00\n" in out
    assert "vlan 10\n name USERS\n arp detection enable\n#\n" in out
    assert (" port link-type hybrid\n port hybrid vlan 20 tagged\n port hybrid vlan 10 untagged\n"
            " port hybrid pvid vlan 10\n voice-vlan 20 enable\n") in out
    assert " undo port trunk permit vlan 1\n port trunk permit vlan 10 20 99\n port trunk pvid vlan 99\n" in out
    assert "interface Bridge-Aggregation1\n" in out and " link-aggregation mode dynamic\n" in out
    assert out.index("interface Bridge-Aggregation1") < out.index(" port link-aggregation group 1")
    assert " stp bpdu-protection\n" in out and " stp mode pvst\n" in out
    assert "interface M-GigabitEthernet0/0/0\n ip binding vpn-instance Mgmt-vrf\n" in out
    assert " ip route-static vpn-instance Mgmt-vrf 0.0.0.0 0 192.168.255.1\n" in out


def test_eos_to_comware_routed() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert " port link-mode route\n description spine-01\n" in out
    assert " ip route-static vpn-instance PROD 10.200.0.0 16 NULL0\n" in out


def test_comware_round_trip() -> None:
    first = parse(sample("comware_access.cfg"), "comware")
    out, _ = convert(sample("comware_access.cfg"), "comware", "comware")
    back = parse(out, "comware")
    assert first.interfaces.keys() == back.interfaces.keys()
    for name, iface in first.interfaces.items():
        other = back.interfaces[name]
        assert (iface.mode, iface.access_vlan, iface.voice_vlan, iface.native_vlan, iface.allowed_vlans,
                iface.shutdown, iface.lag, iface.lacp_mode, iface.ipv4, iface.vrf, iface.stp_bpduguard) == (
            other.mode, other.access_vlan, other.voice_vlan, other.native_vlan, other.allowed_vlans,
            other.shutdown, other.lag, other.lacp_mode, other.ipv4, other.vrf, other.stp_bpduguard), name
    assert [(r.prefix, r.vrf, r.next_hop, r.name) for r in back.static_routes] == [
        (r.prefix, r.vrf, r.next_hop, r.name) for r in first.static_routes]
    for key in back.system.ntp_keys.values():  # an encrypted key comes back as the placeholder
        key.key = "" if key.key == "CHANGE-ME" else key.key
    assert back.system == first.system

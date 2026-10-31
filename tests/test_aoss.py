import re

from helpers import sample

from routershift.convert import convert, parse
from routershift.model import LacpMode, StpMode, SwitchportMode
from routershift.emitters.aoss import port_list
from routershift.parsers.aoss import ports


def test_port_lists() -> None:
    assert ports("1-3,5,A1-A2,Trk1,1/1-1/2") == ["1", "2", "3", "5", "A1", "A2", "Trk1", "1/1", "1/2"]
    assert port_list(["5", "1", "2", "3", "Trk1", "A1", "A2"]) == "1-3,5,A1-A2,Trk1"
    assert port_list(["1/1", "1/2", "2/1"]) == "1/1-1/2,2/1"


def test_parse_aoss_edge_switch() -> None:
    dev = parse(sample("aoss_edge.cfg"), "aoss")
    assert dev.system.hostname == "sw-edge-03"
    assert dev.system.timezone == "UTC+01:00"
    assert dev.system.banner_motd == "Authorised access only."
    assert dev.stp_mode == StpMode.MSTP
    desk = dev.interfaces["Ethernet1"]
    assert (desk.mode, desk.access_vlan, desk.voice_vlan, desk.description) == (
        SwitchportMode.ACCESS, 10, 20, "desk 1.03")
    assert desk.stp_portfast and desk.stp_bpduguard
    printer = dev.interfaces["Ethernet2"]
    assert printer.shutdown and printer.speed == 100 and printer.access_vlan == 10
    assert dev.interfaces["Ethernet4"].access_vlan == 1
    assert dev.interfaces["Ethernet47"].lag == "Port-channel1"
    assert dev.interfaces["Ethernet47"].lacp_mode == LacpMode.ACTIVE
    trk = dev.interfaces["Port-channel1"]
    assert (trk.mode, trk.native_vlan, trk.allowed_vlans) == (SwitchportMode.TRUNK, 99, "10,20,99")
    assert dev.interfaces["Vlan99"].ipv4 == ["10.99.0.13/24"]
    assert dev.interfaces["Management1"].ipv4 == ["192.168.255.13/24"]
    routes = [(r.prefix, r.vrf, r.next_hop) for r in dev.static_routes]
    assert routes == [("0.0.0.0/0", "", "10.99.0.1"), ("0.0.0.0/0", "oobm", "192.168.255.1")]


def test_aoss_to_aoscx() -> None:
    out, report = convert(sample("aoss_edge.cfg"), "aoss", "aoscx")
    assert "interface 1/1/1\n    no shutdown\n    description desk 1.03\n" in out
    assert "interface 1/1/47\n    no shutdown\n    description uplink core-01\n    lag 1\n" in out
    assert "interface mgmt\n    no shutdown\n    ip static 192.168.255.13/24\n    default-gateway 192.168.255.1\n" in out
    assert "s3cret" not in report.to_text()


def test_ios_to_aoss() -> None:
    # without its HSRP group and OSPF the switch only needs a default gateway (test_fhrp and test_ospf cover those)
    text = re.sub(r"router ospf 1\n( .*\n)*|  ?standby .*\n", "", sample("ios_access.cfg"))
    out, report = convert(text, "ios", "aoss")
    assert 'hostname "sw-access-01"\n' in out
    assert "time timezone 60\n" in out
    assert "ip default-gateway 10.99.0.1\n" in out and "ip routing" not in out
    assert "trunk 3-4 trk1 lacp\n" in out
    assert 'vlan 10\n   name "USERS"\n   untagged 1-2\n   tagged Trk1\n' in out
    assert 'vlan 20\n   name "VOICE"\n   tagged 1,Trk1\n   voice\n' in out
    assert "   untagged Trk1\n   ip address 10.99.0.11 255.255.255.0\n   ip helper-address 10.0.0.67\n" in out
    assert "oobm\n   ip address 192.168.255.11 255.255.255.0\n   ip default-gateway 192.168.255.1\n" in out
    assert "spanning-tree 1 admin-edge-port\n" in out


def test_eos_to_aoss_routed_port_and_vrf() -> None:
    out, report = convert(sample("eos_leaf.cfg"), "eos", "aoss")
    # a routed port gets a VLAN of its own
    assert 'vlan 3999\n   name "routed 3"\n   untagged 3\n   ip address 10.255.0.1 255.255.255.254\n' in out
    # a trunk that does not allow its native VLAN takes no untagged VLAN
    assert "vlan 1\n   name \"DEFAULT_VLAN\"\n   no untagged 1-3,Trk10,Trk20\n" in out
    assert "ip route 10.200.0.0 255.255.0.0 blackhole\n" in out
    assert "AOS-S has no VRFs" in report.to_text()


def test_aoss_round_trip() -> None:
    first = parse(sample("aoss_edge.cfg"), "aoss")
    out, _ = convert(sample("aoss_edge.cfg"), "aoss", "aoss")
    back = parse(out, "aoss")
    for name, iface in first.interfaces.items():
        other = back.interfaces[name]
        assert (iface.mode, iface.access_vlan, iface.voice_vlan, iface.native_vlan, iface.allowed_vlans,
                iface.shutdown, iface.lag, iface.ipv4) == (
            other.mode, other.access_vlan, other.voice_vlan, other.native_vlan, other.allowed_vlans,
            other.shutdown, other.lag, other.ipv4), name
    assert [(r.prefix, r.vrf, r.next_hop) for r in back.static_routes] == [
        (r.prefix, r.vrf, r.next_hop) for r in first.static_routes]

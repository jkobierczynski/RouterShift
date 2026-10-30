from helpers import sample

from routershift.convert import convert, parse
from routershift.model import InterfaceKind, LacpMode, StpMode, SwitchportMode
from routershift.parsers.aoscx import canonical


def test_canonical_names() -> None:
    assert canonical("1/1/1") == ("Ethernet1/1/1", InterfaceKind.ETHERNET)
    assert canonical("lag 10") == ("Port-channel10", InterfaceKind.LAG)
    assert canonical("vlan 99") == ("Vlan99", InterfaceKind.VLAN)
    assert canonical("loopback 0") == ("Loopback0", InterfaceKind.LOOPBACK)
    assert canonical("mgmt") == ("Management1", InterfaceKind.MANAGEMENT)
    assert canonical("1/1/1.100") == ("Ethernet1/1/1.100", InterfaceKind.SUBINTERFACE)


def test_parse_aoscx_access_switch() -> None:
    dev = parse(sample("aoscx_access.cfg"), "aoscx")
    assert dev.system.hostname == "sw-access-02"
    assert dev.system.timezone == "europe/brussels"
    assert dev.system.service_vrf == "mgmt"
    assert dev.system.banner_motd == "Authorised access only."
    assert dev.stp_mode == StpMode.RAPID_PVST
    # a trunk of a data VLAN and a voice VLAN is an access port with a voice VLAN
    desk = dev.interfaces["Ethernet1/1/1"]
    assert (desk.mode, desk.access_vlan, desk.voice_vlan) == (SwitchportMode.ACCESS, 10, 20)
    assert desk.stp_portfast and desk.stp_bpduguard
    # ports are shut down unless the configuration says otherwise
    assert dev.interfaces["Ethernet1/1/2"].shutdown
    assert dev.interfaces["Ethernet1/1/3"].speed == 100 and dev.interfaces["Ethernet1/1/3"].duplex == "full"
    # LACP is set on the LAG and lands on its members
    assert dev.interfaces["Ethernet1/1/49"].lacp_mode == LacpMode.ACTIVE
    assert dev.interfaces["Port-channel1"].mode == SwitchportMode.TRUNK
    assert dev.interfaces["Ethernet1/1/51"].mode == SwitchportMode.ROUTED
    mgmt = dev.interfaces["Management1"]
    assert mgmt.vrf == "mgmt" and mgmt.ipv4 == ["192.168.255.12/24"]
    routes = [(r.prefix, r.vrf, r.next_hop, r.discard, r.distance) for r in dev.static_routes]
    assert ("0.0.0.0/0", "mgmt", "192.168.255.1", False, None) in routes
    assert ("10.200.0.0/16", "PROD", "", True, None) in routes
    assert ("10.50.0.0/16", "", "10.255.0.2", False, 250) in routes
    assert dev.interfaces["Vlan10"].vrf == "PROD"


def test_aoscx_to_ios() -> None:
    out, report = convert(sample("aoscx_access.cfg"), "aoscx", "ios")
    assert "interface GigabitEthernet1/0/1\n" in out  # AOS-CX slot 1 is the IOS slot 0
    assert " switchport voice vlan 20\n" in out
    assert "ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 192.168.255.1\n" in out
    assert "logging host 10.0.5.14 vrf Mgmt-vrf\n" in out
    text = report.to_text()
    assert "AQBapQ1bXyzSecretHashValue" not in text
    assert "password ciphertext <removed>" in text


def test_aoscx_to_eos_time_zone() -> None:
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "eos")
    assert "clock timezone Europe/Brussels\n" in out


def test_ios_to_aoscx() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "interface mgmt\n    no shutdown\n    ip static 192.168.255.11/24\n    default-gateway 192.168.255.1\n" in out
    assert "vlan 20\n    name VOICE\n    voice\n" in out
    assert ("interface 1/1/1\n    no shutdown\n    description desk 1.01\n    no routing\n"
            "    vlan trunk native 10\n    vlan trunk allowed 10,20\n") in out
    assert "    speed 100-full\n" in out
    # the LAG comes before its members, and carries the LACP mode
    assert out.index("interface lag 1\n") < out.index("    lag 1\n")
    assert "    lacp mode active\n" in out
    assert "ip route 0.0.0.0/0 10.99.0.1\n" in out
    assert "vrf Mgmt-vrf" not in out
    assert "time zone" in report.to_text()


def test_eos_to_aoscx_routed_and_vrfs() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "vrf PROD\n" in out
    assert "    routing\n    ip address 10.255.0.1/31\n" in out
    assert "ip route 10.200.0.0/16 blackhole vrf PROD\n" in out
    assert "ntp vrf mgmt\n" in out and "logging" not in out


def test_aoscx_round_trip() -> None:
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "aoscx")
    first, back = parse(sample("aoscx_access.cfg"), "aoscx"), parse(out, "aoscx")
    assert first.to_dict()["interfaces"].keys() == back.to_dict()["interfaces"].keys()
    for name, iface in first.interfaces.items():
        other = back.interfaces[name]
        assert (iface.mode, iface.access_vlan, iface.voice_vlan, iface.ipv4, iface.shutdown, iface.lag) == (
            other.mode, other.access_vlan, other.voice_vlan, other.ipv4, other.shutdown, other.lag), name
    assert [(r.prefix, r.vrf, r.next_hop, r.discard) for r in first.static_routes] == [
        (r.prefix, r.vrf, r.next_hop, r.discard) for r in back.static_routes]

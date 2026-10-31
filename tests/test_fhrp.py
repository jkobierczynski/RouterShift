from typing import List

import pytest
from helpers import sample

from routershift.convert import PLATFORMS, convert, parse
from routershift.model import FhrpGroup


def groups(text: str, platform: str, iface: str) -> List[FhrpGroup]:
    return parse(text, platform).interfaces[iface].fhrp


# readers -------------------------------------------------------------------------------------------------------------

def test_ios_hsrp() -> None:
    [g] = groups(sample("ios_access.cfg"), "ios", "Vlan99")
    assert (g.protocol, g.group, g.address, g.priority, g.preempt, g.hello_ms, g.hold_ms, g.version, g.name) == (
        "hsrp", 99, "10.99.0.254", 110, True, 1000, 3000, 2, "MGMT-GW")


def test_ios_hsrp_group_0_msec_timers_and_auth() -> None:
    text = ("interface Vlan5\n ip address 10.5.0.2 255.255.255.0\n standby ip 10.5.0.1\n"
            " standby ip 10.5.0.3 secondary\n standby timers msec 250 msec 800\n"
            " standby authentication md5 key-string Xyz123\n")
    device = parse(text, "ios")
    [g] = device.interfaces["Vlan5"].fhrp
    assert (g.group, g.address, g.secondary, g.hello_ms, g.hold_ms, g.preempts()) == (
        0, "10.5.0.1", ["10.5.0.3"], 250, 800, False)
    assert [u.text for u in device.unparsed] == ["standby authentication md5 key-string Xyz123"]


def test_ios_vrrp_classic_and_v3() -> None:
    text = ("interface Vlan5\n ip address 10.5.0.2 255.255.255.0\n vrrp 5 ip 10.5.0.1\n vrrp 5 priority 120\n"
            " no vrrp 5 preempt\n vrrp 5 timers advertise msec 500\n vrrp 5 description users\n")
    [g] = groups(text, "ios", "Vlan5")
    assert (g.protocol, g.group, g.address, g.priority, g.preempts(), g.hello_ms, g.name, g.version) == (
        "vrrp", 5, "10.5.0.1", 120, False, 500, "users", None)
    text = ("fhrp version vrrp v3\ninterface Vlan5\n ip address 10.5.0.2 255.255.255.0\n"
            " vrrp 5 address-family ipv4\n  address 10.5.0.1 primary\n  priority 120\n  timers advertise 300\n"
            "  vrrpv2\n  exit-vrrp\n")
    device = parse(text, "ios")
    [g] = device.interfaces["Vlan5"].fhrp
    assert (g.address, g.priority, g.hello_ms, g.version, g.preempts()) == ("10.5.0.1", 120, 300, 2, True)
    assert device.unparsed == []


def test_eos_vrrp_and_varp() -> None:
    [g] = groups(sample("eos_leaf.cfg"), "eos", "Vlan100")
    assert (g.protocol, g.address, g.mac) == ("anycast", "10.100.0.254", "00:1c:73:00:00:99")
    text = ("interface Vlan5\n   ip address 10.5.0.2/24\n   vrrp 5 ipv4 10.5.0.1\n   vrrp 5 priority-level 90\n"
            "   vrrp 5 advertisement interval 2\n   vrrp 5 ipv4 version 3\n   vrrp 5 session description users\n"
            "   vrrp 5 disabled\n")
    [g] = groups(text, "eos", "Vlan5")
    assert (g.address, g.priority, g.hello_ms, g.version, g.name, g.shutdown) == (
        "10.5.0.1", 90, 2000, 3, "users", True)


def test_aoscx_vrrp_and_active_gateway() -> None:
    [g] = groups(sample("aoscx_access.cfg"), "aoscx", "Vlan10")
    assert (g.protocol, g.group, g.address, g.priority, g.hello_ms, g.shutdown) == (
        "vrrp", 10, "10.10.0.254", 120, 2000, False)
    text = ("interface vlan 5\n    ip address 10.5.0.2/24\n    active-gateway ip mac 12:00:00:00:01:00\n"
            "    active-gateway ip 10.5.0.1\n    vrrp 6 address-family ipv4\n        address 10.5.0.9 primary\n")
    anycast, vrrp = groups(text, "aoscx", "Vlan5")
    assert (anycast.protocol, anycast.address, anycast.mac) == ("anycast", "10.5.0.1", "12:00:00:00:01:00")
    assert vrrp.shutdown  # until "no shutdown"


def test_aoss_vrrp() -> None:
    text = ("ip routing\nrouter vrrp\n   ipv4 enable\n   exit\nvlan 5\n   ip address 10.5.0.2 255.255.255.0\n"
            "   vrrp vrid 5\n      backup\n      virtual-ip-address 10.5.0.1 255.255.255.0\n      priority 90\n"
            "      no preempt-mode\n      advertise-interval 3\n      enable\n      exit\n   exit\n")
    device = parse(text, "aoss")
    [g] = device.interfaces["Vlan5"].fhrp
    assert (g.group, g.address, g.priority, g.preempts(), g.hello_ms, g.shutdown) == (
        5, "10.5.0.1", 90, False, 3000, False)
    assert device.unparsed == []


def test_comware_vrrp() -> None:
    [g] = groups(sample("comware_access.cfg"), "comware", "Vlan10")
    assert (g.group, g.address, g.priority, g.hello_ms, g.version) == (10, "10.10.0.254", 120, 2000, 3)
    text = ("vrrp version 2\n#\ninterface Vlan-interface5\n ip address 10.5.0.2 255.255.255.0\n"
            " vrrp vrid 5 virtual-ip 10.5.0.1\n undo vrrp vrid 5 preempt-mode\n")
    [g] = groups(text, "comware", "Vlan5")
    assert (g.version, g.preempts()) == (2, False)


# writers -------------------------------------------------------------------------------------------------------------

def test_hsrp_becomes_vrrp_off_cisco() -> None:
    for target in ("eos", "aoscx", "aoss", "comware"):
        out, report = convert(sample("ios_access.cfg"), "ios", target)
        [g] = parse(out, target).interfaces["Vlan99"].fhrp
        assert (g.protocol, g.group, g.address, g.priority, g.preempts()) == (
            "vrrp", 99, "10.99.0.254", 110, True), target
        assert "HSRP group 99 becomes VRRP group 99" in report.to_text(), target


def test_hsrp_preempt_default_is_kept() -> None:
    text = "interface Vlan5\n ip address 10.5.0.2 255.255.255.0\n standby 5 ip 10.5.0.1\n"
    out, _ = convert(text, "ios", "eos")
    assert "   no vrrp 5 preempt\n" in out  # HSRP does not preempt unless told to


def test_hsrp_group_0_gets_a_vrrp_number() -> None:
    text = "interface Vlan5\n ip address 10.5.0.2 255.255.255.0\n standby ip 10.5.0.1\n"
    out, _ = convert(text, "ios", "comware")
    assert " vrrp vrid 1 virtual-ip 10.5.0.1\n" in out


def test_ios_writes_hsrp_and_vrrp() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "ios")
    assert (" standby version 2\n standby 99 ip 10.99.0.254\n standby 99 priority 110\n standby 99 preempt\n"
            " standby 99 timers 1 3\n standby 99 name MGMT-GW\n") in out
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "ios")
    assert "fhrp version vrrp v3" not in out
    assert " vrrp 10 ip 10.10.0.254\n vrrp 10 priority 120\n vrrp 10 timers advertise 2\n" in out
    out, report = convert(sample("comware_access.cfg"), "comware", "ios")  # VRRPv3 by default
    assert "fhrp version vrrp v3\n" in out
    assert (" vrrp 10 address-family ipv4\n  address 10.10.0.254 primary\n  priority 120\n"
            "  timers advertise 2000\n  track 5 decrement 30\n  exit-vrrp\n") in out


def test_anycast_gateway() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "    active-gateway ip mac 00:1c:73:00:00:99\n    active-gateway ip 10.100.0.254\n" in out
    out, _ = convert(out, "aoscx", "eos")
    assert "ip virtual-router mac-address 00:1c:73:00:00:99\n" in out
    assert "   ip virtual-router address 10.100.0.254\n" in out
    out, report = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert " vrrp 1 ip 10.100.0.254\n" in out
    assert "anycast gateway 10.100.0.254 becomes VRRP group 1" in report.to_text()


def test_aoss_writes_owner_and_routing() -> None:
    text = "vlan 5\ninterface Vlan5\n ip address 10.5.0.1 255.255.255.0\n vrrp 5 ip 10.5.0.1\n vrrp 5 priority 254\n"
    out, _ = convert(text, "ios", "aoss")
    assert "ip routing\nrouter vrrp\n   ipv4 enable\n   exit\n" in out
    assert ("   vrrp vrid 5\n      owner\n      virtual-ip-address 10.5.0.1 255.255.255.0\n      enable\n"
            "      exit\n") in out


def test_timer_rounding_is_reported() -> None:
    text = ("interface Vlan5\n ip address 10.5.0.2 255.255.255.0\n vrrp 5 ip 10.5.0.1\n"
            " vrrp 5 timers advertise msec 250\n")
    out, report = convert(text, "ios", "eos")
    assert "   vrrp 5 advertisement interval 1\n" in out
    assert "interval 250 ms written as 1000 ms" in report.to_text()


def test_comware_version_2_when_needed() -> None:
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "comware")
    assert "vrrp version 2" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "comware")
    assert "vrrp version" not in out


def test_hsrp_auth_never_in_report() -> None:
    text = ("interface Vlan5\n ip address 10.5.0.2 255.255.255.0\n standby 5 ip 10.5.0.1\n"
            " standby 5 authentication md5 key-string Xyz123\n standby 6 authentication cisco\n")
    _, report = convert(text, "ios", "eos")
    assert "Xyz123" not in report.to_text() and "cisco" not in report.to_text()


@pytest.mark.parametrize("target", sorted(set(PLATFORMS) - {"junos", "nxos"}))
def test_every_writer_round_trips_a_vrrp_group(target: str) -> None:
    text = ("vlan 5\ninterface Vlan5\n ip address 10.5.0.2 255.255.255.0\n vrrp 5 ip 10.5.0.1\n"
            " vrrp 5 ip 10.5.0.3 secondary\n"
            " vrrp 5 priority 120\n no vrrp 5 preempt\n vrrp 5 timers advertise 3\n vrrp 5 shutdown\n")
    out, _ = convert(text, "ios", target)
    back = parse(out, target)
    [g] = back.interfaces["Vlan5"].fhrp
    assert (g.group, g.address, g.secondary, g.priority, g.preempts(), g.hello_ms, g.shutdown) == (
        5, "10.5.0.1", ["10.5.0.3"], 120, False, 3000, True), target
    assert back.unparsed == [], target

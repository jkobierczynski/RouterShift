from typing import Dict, Optional, Tuple

from helpers import sample

from routershift.convert import convert, parse
from routershift.model import Device


def ports(device: Device) -> Dict[str, Tuple[bool, bool, str, bool, Optional[int]]]:
    return {i.name: (i.dot1x, i.mab, i.dot1x_host_mode, i.dot1x_reauth, i.dot1x_reauth_period)
            for i in device.interfaces.values() if i.dot1x or i.mab}


def test_ios_reader() -> None:
    device = parse(sample("ios_access.cfg"), "ios")
    assert device.aaa.dot1x
    assert ports(device) == {"Ethernet1/0/1": (True, True, "multi-auth", True, 7200),
                             "Ethernet1/0/2": (False, True, "single-host", False, None)}
    assert [m.methods for m in device.aaa.methods if m.service == "dot1x"] == [["group:radius"]]
    assert device.system.transfer_source == {"tftp": "Vlan99"}


def test_each_platform_reads_its_host_mode() -> None:
    assert ports(parse(sample("eos_leaf.cfg"), "eos")) == {"Ethernet1": (True, False, "multi-host", True, 1800)}
    assert list(ports(parse(sample("aoscx_access.cfg"), "aoscx")).values()) == [
        (True, True, "single-host", False, None)]
    assert list(ports(parse(sample("aoss_edge.cfg"), "aoss")).values()) == [
        (True, False, "single-host", True, 3600), (False, True, "single-host", False, None)]
    assert list(ports(parse(sample("comware_access.cfg"), "comware")).values()) == [
        (True, True, "multi-auth", True, 1800)]


def test_eos_writer() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    assert ("   dot1x pae authenticator\n   dot1x port-control auto\n   dot1x host-mode multi-host authenticated\n"
            "   dot1x mac based authentication\n   dot1x reauthentication\n   dot1x timeout reauth-period 7200\n") in out
    assert "dot1x system-auth-control" in out and "ip tftp client source-interface Vlan99" in out


def test_aoscx_writer() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert ("    aaa authentication port-access client-limit 32\n    aaa authentication port-access dot1x authenticator\n"
            "        reauth\n        reauth-period 7200\n        enable\n") in out
    assert "aaa authentication port-access dot1x authenticator\n    radius server-group radius\n    enable" in out
    assert "multi-auth written as client mode with up to 32 clients" in report.to_text()
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "    aaa authentication port-access auth-mode device-mode\n" in out


def test_aoss_writer() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    for line in ("aaa authentication port-access eap-radius", "aaa authentication mac-based chap-radius",
                 "aaa port-access authenticator 1 client-limit 32", "aaa port-access authenticator 1 reauth-period 7200",
                 "aaa port-access authenticator active", "aaa port-access mac-based 1-2",
                 "aaa port-access mac-based 1 addr-limit 32", "ip source-interface tftp vlan 99"):
        assert f"{line}\n" in out, line
    out, report = convert(sample("eos_leaf.cfg"), "eos", "aoss")
    assert "client-limit" not in out  # multi-host: the port opens for everyone once one client logs in
    assert "not a VLAN or loopback; set 'ip source-interface tftp' by hand" in report.to_text()


def test_comware_writer() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert " dot1x\n mac-authentication\n dot1x timer reauth-period 7200\n" in out
    assert " authentication lan-access radius-scheme RADIUS\n authorization lan-access radius-scheme RADIUS\n" in out
    assert " dot1x\n dot1x re-authenticate\n mac-authentication\n" in out
    assert " mac-authentication\n mac-authentication max-user 1\n" in out
    assert " tftp client source interface Vlan-interface99" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert " dot1x port-method portbased\n" in out


def test_ftp_source_is_reported_on_aos_switches() -> None:
    text = "interface Vlan99\n ip address 10.99.0.2 255.255.255.0\n!\nip ftp source-interface Vlan99\n"
    for target, name in (("aoscx", "AOS-CX"), ("aoss", "AOS-S")):
        _, report = convert(text, "ios", target)
        assert f"{name} has no FTP client source setting" in report.to_text()


def test_tacacs_only_lan_access_is_flagged_for_comware() -> None:
    text = ("aaa new-model\ntacacs server T\n address ipv4 10.0.0.9\n key 0 k\n!\n"
            "aaa authentication dot1x default group tacacs+ local\n")
    out, report = convert(text, "ios", "comware")
    assert " authentication lan-access local" in out
    assert "RADIUS only for LAN access" in report.to_text()

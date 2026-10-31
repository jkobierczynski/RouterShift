from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    m = ios.management
    assert (m.ssh, m.telnet, m.http, m.https, m.vty_acl, m.exec_timeout, m.lldp) == (
        True, False, False, True, "MGMT-ONLY", 15, True)
    assert (ios.system.logging_level, ios.system.logging_source) == (6, "Vlan99")
    port = ios.interfaces["Ethernet1/0/2"]
    assert (port.lldp_tx, port.lldp_rx, port.cdp) == (False, True, False)
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert (eos.management.vrf, eos.management.vty_acl, eos.management.exec_timeout) == ("MGMT", "SERVERS-IN", 30)
    aoscx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert (aoscx.management.ssh, aoscx.management.https, aoscx.management.vrf) == (True, True, "mgmt")
    assert (aoscx.management.exec_timeout, aoscx.system.logging_level) == (20, 4)
    aoss = parse(sample("aoss_edge.cfg"), "aoss")
    assert (aoss.management.telnet, aoss.management.http, aoss.management.exec_timeout) == (False, False, 15)
    assert (aoss.interfaces["Ethernet2"].lldp_tx, aoss.interfaces["Ethernet2"].lldp_rx) == (False, False)
    comware = parse(sample("comware_access.cfg"), "comware")
    assert (comware.management.ssh, comware.management.telnet, comware.management.exec_timeout) == (True, False, 15)
    assert (comware.system.logging_level, comware.system.logging_source) == (4, "Vlan99")


def test_ios_writes_lines_and_servers() -> None:
    out, report = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "line vty 0 15\n transport input ssh\n exec-timeout 15 0\n" in out
    assert "ip ssh version 2\n" in out and "ip http secure-server\n" in out
    assert "logging trap warnings\nlogging source-interface Vlan99\n" in out
    assert "crypto key generate rsa" in report.to_text()


def test_eos_writes_management_ssh() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "management ssh\n   ip access-group MGMT-ONLY in\n   idle-timeout 15\n" in out
    assert "management telnet\n   shutdown\n" in out
    assert "EOS has no web interface" in report.to_text()
    assert "   no lldp transmit\n" in out


def test_aos_and_comware_writers() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "logging 10.0.5.14 severity info" in out and "ssh server vrf mgmt\n" in out
    assert "cli-session\n    timeout 15\n" in out
    assert "apply ACL MGMT-ONLY to the control plane by hand" in report.to_text()
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert "ip ssh\nno telnet-server\nno web-management plaintext\nweb-management ssl\nconsole idle-timeout 900\n" in out
    assert "logging severity info\n" in out and "no cdp run" not in out
    assert "ip authorized-managers" in report.to_text()
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert " info-center source default loghost level informational\n" in out
    assert " ssh server enable\n undo telnet server enable\n undo ip http enable\n ip https enable\n" in out
    assert " lldp admin-status rx\n" in out


def test_aoss_has_five_severities() -> None:
    out, report = convert("hostname s\nlogging 10.0.0.1\nlogging trap notifications\n", "ios", "aoss")
    assert "logging severity info\n" in out
    assert "AOS-S has no level notifications; info is written" in report.to_text()

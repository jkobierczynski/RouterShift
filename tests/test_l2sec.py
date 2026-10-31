from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert ios.dhcp_snooping and (ios.vlans[10].dhcp_snooping, ios.vlans[20].dhcp_snooping) == (True, True)
    assert ios.vlans[10].arp_inspection and not ios.vlans[20].arp_inspection
    port = ios.interfaces["Ethernet1/0/1"]
    assert (port.port_security, port.port_security_max, port.port_security_violation, port.source_guard,
            port.storm_control) == (True, 3, "restrict", True, {"broadcast": 10.0})
    assert ios.interfaces["Port-channel1"].dhcp_trust and ios.interfaces["Port-channel1"].arp_trust
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert eos.interfaces["Ethernet1"].storm_control == {"broadcast": 5.0, "unknown-unicast": 20.0}
    assert eos.interfaces["Ethernet1"].port_security_violation == "shutdown"  # the default
    aoscx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert aoscx.vlans[10].dhcp_snooping and aoscx.interfaces["Ethernet1/1/1"].port_security_max == 4
    aoss = parse(sample("aoss_edge.cfg"), "aoss")
    assert aoss.interfaces["Ethernet1"].port_security_violation == "shutdown"  # send-disable
    assert aoss.interfaces["Port-channel1"].dhcp_trust
    comware = parse(sample("comware_access.cfg"), "comware")
    assert comware.dhcp_snooping and not any(v.dhcp_snooping for v in comware.vlans.values())
    assert comware.interfaces["Ethernet1/0/1"].port_security_violation == "shutdown"  # disableport


def test_writers() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "ip dhcp snooping\nip dhcp snooping vlan 10,20\nip arp inspection vlan 10\n" in out
    assert "   switchport port-security violation protect\n" in out
    assert "does not drop server replies on untrusted ports" in report.to_text()
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert "dhcp-snooping vlan 10 20\n" in out and "arp-protect vlan 10\n" in out
    assert "dhcp-snooping trust Trk1\n" in out and "ip source-lockdown 1\n" in out
    assert "port-security 1 learn-mode static address-limit 3 action send-alarm\n" in out
    out, report = convert(sample("ios_access.cfg"), "ios", "comware")
    assert " port-security intrusion-mode blockmac\n" in out and " broadcast-suppression 10\n" in out
    assert "Comware snoops every VLAN, not only 10,20" in report.to_text()
    out, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "    port-access port-security\n        enable\n        client-limit 3\n" in out
    assert "AOS-CX rate-limits in kbps or pps" in report.to_text()


def test_comware_snooping_lists_every_vlan_elsewhere() -> None:
    out, report = convert(sample("comware_access.cfg"), "comware", "ios")
    vlans = sorted(parse(sample("comware_access.cfg"), "comware").vlans)
    assert f"ip dhcp snooping vlan {','.join(map(str, vlans))}\n" in out
    assert "the source snoops every VLAN" in report.to_text()

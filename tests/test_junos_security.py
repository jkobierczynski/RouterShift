"""Junos device security: control-plane ACLs on lo0 and me0, CoPP classes as DDoS protection policers, MACsec, MAC
ACLs and ACLs on switch ports as ethernet-switching filters, and RADIUS change of authorization."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _round_trip():
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def test_control_plane() -> None:
    first, out, report, back = _round_trip()
    assert first.control_plane is not None and back.control_plane is not None
    assert back.control_plane.acls == {"mgmt_junos": "ACL-CPP-MGMT"}  # the management port's input filter
    assert [(c.name, c.pps) for c in back.control_plane.classes] == \
        [(c.name, c.pps) for c in first.control_plane.classes if c.name != "copp-system-default"]
    assert "ddos-protection {" in out and "bandwidth 5000;" in out
    text = report.to_text()
    assert "default control-plane ACL has no Junos counterpart" in text
    assert "copp-system-default (2000 pps)" in text


def test_macsec() -> None:
    first, out, report, back = _round_trip()
    profile = back.macsec_profiles["MACSEC-DCI"]
    src = first.macsec_profiles["MACSEC-DCI"]
    assert (profile.cipher, profile.ckn, profile.key_server_priority, profile.rekey_period, profile.sci,
            profile.lldp_bypass) == (src.cipher, src.ckn, src.key_server_priority, src.rekey_period, src.sci,
                                     src.lldp_bypass)
    assert "cak CHANGE-ME;" in out and report.items[("security", "MACsec profile MACSEC-DCI")].status == "needs-review"
    assert [i.macsec_profile for i in back.interfaces.values() if i.macsec_profile] == ["MACSEC-DCI"]
    assert "FIPS is a mode of the whole Junos install" in report.to_text()


def test_mac_acls_and_switch_port_acls() -> None:
    first, out, report, back = _round_trip()
    assert back.mac_acls["MACL-PROTECT-LEGACY"].entries == first.mac_acls["MACL-PROTECT-LEGACY"].entries
    assert "ether-type 0x88cc;" in out and "learn-vlan-id 900;" in out
    assert [i.mac_acl_in for i in back.interfaces.values() if i.mac_acl_in] == ["MACL-PROTECT-LEGACY"]
    # an IP ACL on a switch port: an ethernet-switching filter with the same terms
    assert back.interfaces["Port-channel30"].acl_in == "ACL-DMZ-IN"
    assert "ip-destination-address 203.0.113.0/26;" in out and "input ACL-DMZ-IN;" in out
    assert back.aaa.coa and "radius-disconnect-port 3799;" in out


def test_reads_native_junos_security() -> None:
    text = """\
set interfaces lo0 unit 0 family inet filter input PROTECT-RE
set interfaces lo0 unit 0 family inet address 10.0.0.1/32
set firewall family inet filter PROTECT-RE term ssh from protocol tcp
set firewall family inet filter PROTECT-RE term ssh from destination-port ssh
set firewall family inet filter PROTECT-RE term ssh then accept
set firewall family ethernet-switching filter NO-BPDU term 1 from destination-mac-address 01:80:c2:00:00:00/48
set firewall family ethernet-switching filter NO-BPDU term 1 then discard
set system ddos-protection protocols lacp aggregate bandwidth 500
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    assert d.control_plane is not None and d.control_plane.acls == {"": "PROTECT-RE"}
    assert [(c.name, c.pps) for c in d.control_plane.classes] == [("copp-system-lacp", 500)]
    assert d.mac_acls["NO-BPDU"].entries[0].destination == "01:80:c2:00:00:00 00:00:00:00:00:00"

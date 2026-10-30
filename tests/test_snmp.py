from helpers import sample

from routershift import snmp as snmp_text
from routershift.convert import convert, parse


def test_ios_reader() -> None:
    device = parse(sample("ios_snmp.cfg"), "ios")
    assert device.unparsed == []
    s = device.system
    assert (s.ntp_servers, s.ntp_prefer, s.ntp_server_keys, s.ntp_authenticate, s.ntp_source) == (
        ["10.0.0.123", "10.0.0.124"], "10.0.0.123", {"10.0.0.123": 1, "10.0.0.124": 1}, True, "Loopback0")
    assert [(k.number, k.key, k.trusted) for k in s.ntp_keys.values()] == [(1, "NtpK3y", True), (2, "", False)]
    snmp = device.snmp
    assert [(c.name, c.access, c.acl) for c in snmp.communities] == [("s3cret", "ro", "MGMT-ONLY"), ("wr1te", "rw", "")]
    assert (snmp.location, snmp.contact, snmp.traps, snmp.source) == (
        "Brussels DC1 rack 4", "noc@example.net", True, "Loopback0")
    assert (snmp.groups["NMS"].level, snmp.groups["NMS"].read_view) == ("priv", "ALL")
    [user] = snmp.users
    assert (user.group, user.auth, user.auth_key, user.priv, user.priv_key) == (
        "NMS", "sha", "AuthPass1", "aes128", "PrivPass1")
    assert [(h.address, h.version, h.secret, h.level, h.informs) for h in snmp.hosts] == [
        ("10.0.5.20", "2c", "s3cret", "", False), ("10.0.5.21", "3", "nms", "priv", True)]


def test_eos_reader() -> None:
    device = parse(sample("eos_leaf.cfg"), "eos")
    assert device.system.ntp_keys[3].algorithm == "sha1" and device.system.ntp_keys[3].key == ""  # type 7
    assert device.system.ntp_prefer == "10.0.0.123"
    [host] = device.snmp.hosts
    assert (host.vrf, host.secret) == ("MGMT", "r3adonly")


def test_aoscx_reader_and_writer() -> None:
    device = parse(sample("aoscx_access.cfg"), "aoscx")
    assert not [u for u in device.unparsed if "snmp" in u.text or "ntp" in u.text]
    assert [(c.name, c.access) for c in device.snmp.communities] == [("c0mmunity", "rw")]
    [user] = device.snmp.users
    assert (user.auth, user.auth_key, user.priv) == ("sha", "", "aes128")  # ciphertext
    out, _ = convert(sample("ios_snmp.cfg"), "ios", "aoscx")
    assert "snmp-server community s3cret\n    access-level ro\n" in out
    assert "snmpv3 user nms auth sha auth-pass plaintext AuthPass1 priv aes priv-pass plaintext PrivPass1" in out
    assert "ntp authentication-key 1 md5 plaintext NtpK3y trusted" in out


def test_aoss_reader_and_writer() -> None:
    text = ('snmp-server community "pub" operator restricted\nsnmp-server location "Hall 2"\n'
            'snmpv3 enable\nsnmpv3 user "nms" auth sha "a1" priv aes "p1"\n'
            'snmpv3 group managerpriv user "nms" sec-model ver3\n'
            'ntp authentication key-id 4 authentication-mode md5 key-value "k" trusted\n'
            'ntp server 10.0.0.1 key 4 iburst\nntp enable\ntimesync ntp\n')
    device = parse(text, "aoss")
    assert device.unparsed == []
    assert [(c.name, c.access) for c in device.snmp.communities] == [("pub", "ro")]
    assert device.snmp.location == "Hall 2"
    assert (device.snmp.users[0].group, device.snmp.groups["managerpriv"].level) == ("managerpriv", "priv")
    assert device.system.ntp_keys[4].key == "k" and device.system.ntp_server_keys == {"10.0.0.1": 4}
    out, report = convert(sample("ios_snmp.cfg"), "ios", "aoss")
    assert 'snmpv3 group managerpriv user "nms" sec-model ver3' in out
    assert "AOS-S has fixed groups" in report.to_text()
    assert "SNMPv3 notification targets are not written for AOS-S" in report.to_text()


def test_comware_reader_and_writer() -> None:
    device = parse(sample("comware_access.cfg"), "comware")
    [community] = device.snmp.communities
    assert (community.name, community.access) == ("", "ro")  # cipher
    assert device.system.ntp_keys[5].trusted and device.system.ntp_prefer == "10.0.0.123"
    [host] = device.snmp.hosts
    assert (host.version, host.level, host.vrf) == ("3", "priv", "mgmt")
    out, report = convert(sample("comware_access.cfg"), "comware", "ios")
    assert f"snmp-server community {snmp_text.PLACEHOLDER} RO" in out
    assert "community is stored encrypted" in report.to_text()
    out, _ = convert(sample("ios_snmp.cfg"), "ios", "comware")
    assert " snmp-agent community read simple s3cret acl name MGMT-ONLY" in out
    assert " snmp-agent target-host inform address udp-domain 10.0.5.21 params securityname nms v3 privacy" in out


def test_report_shows_no_secret() -> None:
    for target in ("ios", "eos", "aoscx", "aoss", "comware"):
        _, report = convert(sample("ios_snmp.cfg"), "ios", target)
        text = report.to_text()
        for secret in ("s3cret", "wr1te", "AuthPass1", "PrivPass1", "NtpK3y"):
            assert secret not in text, (target, secret)

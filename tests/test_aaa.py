from helpers import sample

from routershift import aaa as aaa_text
from routershift.convert import convert, parse
from routershift.report import redact

COMWARE = """radius scheme RAD
 primary authentication 10.0.0.11 key simple radkey
 primary accounting 10.0.0.11 1646 key simple radkey
 secondary authentication 10.0.0.12 1645 key cipher $c$3$abc==
 vpn-instance mgmt
 timer response-timeout 5
#
hwtacacs scheme TAC
 primary authentication 10.0.0.21 key simple tackey
 primary authorization 10.0.0.21 key simple tackey
#
domain system
 authentication login hwtacacs-scheme TAC local
 authorization command hwtacacs-scheme TAC local
 authentication super hwtacacs-scheme TAC
#
 super password role network-admin simple Enabl3
#
local-user ops class manage
 password hash $h$6$abc==
 authorization-attribute user-role level-5
#
"""


def test_type7_decodes() -> None:
    assert aaa_text.decode_type7("0822455D0A16") == "cisco"
    assert aaa_text.decode_type7("zz") == ""


def test_ios_reader() -> None:
    device = parse(sample("ios_access.cfg"), "ios")
    assert [(u.name, u.privilege, u.password) for u in device.users] == [
        ("admin", 15, "Adm1nPass"), ("backup", None, "cisco")]
    assert device.aaa.enable_secret is not None and device.aaa.enable_secret.hash_type == "md5-crypt"
    assert [(s.protocol, s.address, s.key) for s in device.aaa.servers] == [
        ("tacacs", "10.0.5.31", "TacKey1"), ("tacacs", "10.0.5.32", "TacKey2"), ("radius", "10.0.5.41", "RadKey1")]
    assert device.aaa.groups["TAC"].servers == ["10.0.5.31", "10.0.5.32"]
    assert device.aaa.source == {"tacacs": "Vlan99"}
    assert [aaa_text.method_label(m) for m in device.aaa.methods] == [
        "authentication login default", "authorization exec default", "accounting commands 15 default",
        "authentication dot1x default"]


def test_comware_reader() -> None:
    device = parse(COMWARE, "comware")
    assert device.unparsed == []
    rad1, rad2, tac = device.aaa.servers
    assert (rad1.acct_port, rad1.timeout, rad1.vrf, rad1.key) == (1646, 5, "mgmt", "radkey")
    assert (rad2.auth_port, rad2.key) == (1645, "")  # cipher: not readable
    assert tac.key == "tackey"
    assert [(m.kind, m.service, m.methods) for m in device.aaa.methods] == [
        ("authentication", "login", ["group:TAC", "local"]), ("authorization", "commands", ["group:TAC", "local"]),
        ("authentication", "enable", ["group:TAC"])]
    assert device.aaa.enable_secret is not None and device.aaa.enable_secret.password == "Enabl3"
    [user] = device.users
    assert (user.privilege, user.hash_type) == (5, "comware-hash")


def test_comware_writer() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "comware")
    assert ("hwtacacs scheme TAC\n primary authentication 10.0.5.31 key simple TacKey1\n"
            " primary authorization 10.0.5.31 key simple TacKey1\n") in out
    assert " secondary accounting 10.0.5.32 key simple TacKey2\n" in out
    assert "local-user admin class manage\n password simple Adm1nPass\n" in out
    assert " authorization-attribute user-role network-admin" in out
    assert "domain system\n authentication login hwtacacs-scheme TAC local\n" in out
    assert " hwtacacs nas-ip 10.99.0.11" in out
    assert "line vty 0 63\n authentication-mode scheme" in out
    assert "the password hash (md5-crypt) cannot be used on the target" in report.to_text()


def test_comware_to_ios_keeps_vrf_and_ports() -> None:
    out, report = convert(COMWARE, "comware", "ios")
    assert "radius server RADIUS-10.0.0.11\n address ipv4 10.0.0.11 auth-port 1812 acct-port 1646" in out
    assert " ip vrf forwarding mgmt" in out
    assert "enable secret 0 Enabl3" in out
    assert "aaa authentication enable default group TAC" in out
    assert "user ops: skipped" in report.to_text()
    assert "CHANGE-ME" in out and "stored encrypted in the source" in report.to_text()


def test_eos_writer_keeps_sha512_hash() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "eos")
    assert "username admin privilege 15 role network-admin secret sha512 $6$salt$0123456789abcdef" in out
    assert "ip radius vrf MGMT source-interface Management1" in out


def test_aos_switch_limits() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert 'password manager user-name "admin" plaintext "Adm1nPass"' in out
    assert 'aaa authentication ssh login tacacs server-group "TAC" local' in out
    assert "AOS-S has no enable secret" in report.to_text()
    out, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "user admin group administrators password plaintext Adm1nPass" in out
    assert "ip source-interface tacacs interface vlan99" in out
    assert "AOS-CX has no authorization for exec" in report.to_text()


def test_method_comware_cannot_take_is_flagged() -> None:
    text = "aaa new-model\nradius server R\n address ipv4 10.0.0.1\n key 0 k\n!\n" \
           "aaa authorization commands 15 default group radius local\n"
    out, report = convert(text, "ios", "comware")
    assert " authorization command local" in out
    assert "HWTACACS only for commands" in report.to_text()


def test_report_shows_no_secret() -> None:
    for source, platform in (("ios_access.cfg", "ios"), ("eos_leaf.cfg", "eos"), ("aoscx_access.cfg", "aoscx"),
                             ("aoss_edge.cfg", "aoss"), ("comware_access.cfg", "comware")):
        for target in ("ios", "eos", "aoscx", "aoss", "comware"):
            _, report = convert(sample(source), platform, target)
            text = report.to_text()
            for secret in ("Adm1nPass", "cisco\n", "TacKey1", "TacKey2", "RadKey1", "0822455D0A16", "$6$salt"):
                assert secret not in text, (source, target, secret)
    for line in ("super password role network-admin simple Enabl3", 'password manager user-name "a" sha1 "Pw1"',
                 "snmp-agent usm-user v3 u G cipher authentication-mode sha Pw1 privacy-mode aes128 Pw1",
                 "ntp authentication-key 3 sha1 7 Pw1", "local-user x\n password simple Pw1"):
        assert "Pw1" not in redact(line) and "Enabl3" not in redact(line), line

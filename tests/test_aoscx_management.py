"""AOS-CX management: banners, user groups and SSH keys, the REST API, password length, syslog transport and the
console's login list, written and read back; what AOS-CX has no setting for is reported."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "aoscx")
    back = parse(out, "aoscx")
    assert [u.text for u in back.unparsed] == []
    return first, out, report, back


def test_users_roles_and_keys() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert 'user-group NOC-READONLY\n    10 permit cli command "(show|ping|traceroute|bash timeout).*"\n' in out
    assert [(r.action, r.command) for r in back.roles["NOC-READONLY"].rules] == \
        [(r.action, r.command) for r in first.roles["NOC-READONLY"].rules]
    assert _findings(report, "role-group")
    # users with a hashed secret are left to a person, and their role and keys with them
    assert any("role NOC-READONLY" in m for m in _findings(report, "user-left-out"))
    eos = ("hostname s\nrole OPS\n   10 permit command show\n   20 deny command .*\n!\n"
           "username ops role OPS secret 0 s3cret\nusername ops ssh-key ssh-rsa AAAAB3 ops@host\n")
    first, out, report, back = _back(eos, "eos")
    assert "user ops group OPS password plaintext s3cret\nuser ops authorized-key ssh-rsa AAAAB3 ops@host\n" in out
    [user] = back.users
    assert (user.role, user.ssh_keys) == ("OPS", ["ssh-rsa AAAAB3 ops@host"])


def test_banner_api_password_syslog() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert back.system.banner_motd == first.system.banner_login
    assert "https-server rest access-mode read-write\n" in out
    assert back.management.apis == {"http": "mgmt"}
    assert any("gnmi" in m for m in _findings(report, "api")) and any("netconf" in m for m in _findings(report, "api"))
    assert "password complexity\n    minimum-length 12\n    enable\n" in out
    assert back.management.password_min_length == 12
    assert "logging 10.100.1.50 tls " in out
    assert back.system.syslog_transport == first.system.syslog_transport
    assert back.management.console_login == "console"
    for code in ("local-logging", "snmp-views", "trap-types"):
        assert _findings(report, code), code
    assert not _findings(report, "not-written") or not any(
        "banner" in m or "roles" in m or "SSH" in m or "APIs" in m for m in _findings(report, "not-written"))


def test_exec_banner_and_console_from_ios() -> None:
    ios = ("hostname r\nbanner motd ^C\nHello\n^C\nbanner exec ^C\nWelcome\n^C\n"
           "aaa new-model\naaa authentication login CONS local\nline con 0\n login authentication CONS\n")
    first, out, report, back = _back(ios, "ios")
    assert back.system.banner_motd == "Hello" and back.system.banner_exec == "Welcome"
    assert "aaa authentication login console local" in out
    assert _findings(report, "console-login")

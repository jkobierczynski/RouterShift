"""Junos management: users with SSH keys and login classes for roles, the remote-login filter, banners, local
logging, syslog transport, SNMPv3, the APIs and the password policy, written and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _round_trip():
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def test_users_roles_and_login() -> None:
    first, out, report, back = _round_trip()
    users = {u.name: u for u in back.users}
    assert set(users) == {u.name for u in first.users}
    assert users["automation"].ssh_keys == next(u.ssh_keys for u in first.users if u.name == "automation")
    assert (users["noc"].role, users["admin"].privilege) == ("NOC-READONLY", 15)
    assert report.items[("management", "user admin")].status == "needs-review"  # the hash cannot be carried
    role = back.roles["NOC-READONLY"]
    assert [(r.action, r.mode, r.command) for r in role.rules] == \
        [(r.action, r.mode, r.command) for r in first.roles["NOC-READONLY"].rules]
    assert back.management.exec_timeout == 30 and "idle-timeout 30;" in out
    assert back.management.vty_acl == "ACL-MGMT-IN" and "input-list [ ACL-CPP-MGMT ACL-MGMT-IN-LOGIN ];" in out
    assert back.management.password_min_length == 12
    assert back.system.banner_login == first.system.banner_login


def test_logging_and_snmp() -> None:
    first, out, report, back = _round_trip()
    sy, src = back.system, first.system
    assert (sy.logging_buffer_level, sy.logging_console_level, sy.logging_timestamp) == \
        (src.logging_buffer_level, src.logging_console_level, src.logging_timestamp)
    assert sy.syslog_transport == src.syslog_transport and "transport tls;" in out
    assert sy.service_vrf == "mgmt_junos"  # the management instance
    sn, s0 = back.snmp, first.snmp
    assert (sn.engine_id, sn.views) == (s0.engine_id, s0.views)
    assert [(g.name, g.level, g.read_view, g.write_view) for g in sn.groups.values()] == \
        [(g.name, g.level, g.read_view, g.write_view) for g in s0.groups.values()]
    assert [(u.name, u.group, u.auth) for u in sn.users] == [(u.name, u.group, u.auth) for u in s0.users]
    assert sn.users[0].priv == "aes128"  # aes256 is written as the privacy every release has
    assert [(h.address, h.version, h.secret, h.level) for h in sn.hosts] == \
        [(h.address, h.version, h.secret, h.level) for h in s0.hosts]
    assert set(back.management.apis) == {"http", "gnmi", "netconf"}
    assert "netconf {" in out and "rest {" in out


def test_reads_native_junos_management() -> None:
    text = """\
set system login class NOC permissions view
set system login class NOC allow-commands "(show)|(ping)"
set system login user ops class NOC
set system login user ops authentication ssh-rsa "ssh-rsa AAAAB3 ops@host"
set system login announcement "Welcome"
set system syslog file messages any warning
set system syslog host 192.0.2.9 port 1514
set system syslog host 192.0.2.9 transport tcp
set snmp trap-group public version v2
set snmp trap-group public targets 192.0.2.50
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    assert [(r.action, r.command) for r in d.roles["NOC"].rules] == [("permit", "show"), ("permit", "ping"),
                                                                     ("deny", ".*")]
    ops = d.users[0]
    assert ops.role == "NOC" and ops.ssh_keys == ["ssh-rsa AAAAB3 ops@host"]
    assert d.system.banner_motd == "Welcome" and d.system.logging_buffer_level == 4
    assert d.system.syslog_transport == {"192.0.2.9": ("tcp", 1514)}
    assert [(h.address, h.version, h.secret) for h in d.snmp.hosts] == [("192.0.2.50", "2c", "public")]

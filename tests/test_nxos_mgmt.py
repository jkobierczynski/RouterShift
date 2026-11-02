"""NX-OS management: banners, local logging, syslog transport, roles, SSH keys, APIs, password length, time zones."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")
NXOS = """\
feature nxapi
feature netconf
feature grpc
banner motd #
Authorised access only.
#
banner exec #
Welcome.
#
clock timezone CET 1 0
clock summer-time CEST 5 Sunday March 02:00 5 Sunday October 03:00 60
logging server 10.0.0.50 6 port 6514 secure use-vrf management
logging logfile messages 6 size 65536
logging console 3
logging monitor 5
logging timestamp milliseconds
logging origin-id hostname
logging level bgp 6
nxapi use-vrf management
grpc use-vrf management
userpassphrase min-length 10
role name NOC
  rule 3 permit command show *
  rule 2 permit command ping *
  rule 1 deny command *
username admin password 5 $5$abc$def role network-admin
username noc password 5 $5$ghi$jkl role NOC
username noc sshkey ssh-rsa AAAAB3NzaC1yc2E noc@example
vrf context management
interface mgmt0
  vrf member management
  ip address 192.168.0.10/24
"""


def _findings(report, code):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_reads_nxos_management() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    s = d.system
    assert s.banner_motd == "Authorised access only." and s.banner_exec == "Welcome."
    assert s.timezone == "Europe/Amsterdam"
    assert s.syslog_transport == {"10.0.0.50": ("tls", 6514)} and s.logging_level == 6
    assert (s.logging_buffer, s.logging_buffer_level, s.logging_console_level, s.logging_monitor_level) == \
        (65536, 6, 3, 5)
    assert (s.logging_timestamp, s.logging_hostname, s.logging_facility_levels) == ("msec", "hostname", {"bgp": 6})
    m = d.management
    assert m.apis == {"http": "management", "netconf": "", "gnmi": "management"} and m.password_min_length == 10
    assert [(r.action, r.command) for r in d.roles["NOC"].rules] == \
        [("permit", "show *"), ("permit", "ping *"), ("deny", "*")]
    noc = next(u for u in d.users if u.name == "noc")
    assert noc.role == "NOC" and noc.ssh_keys == ["ssh-rsa AAAAB3NzaC1yc2E noc@example"]


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, report = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert vars(back.system) == vars(first.system)
    assert back.management.apis == first.management.apis
    assert back.management.password_min_length == first.management.password_min_length
    assert [(r.action, r.command) for r in back.roles["NOC"].rules] == \
        [(r.action, r.command) for r in first.roles["NOC"].rules]
    assert [(u.name, u.role, u.ssh_keys) for u in back.users] == [(u.name, u.role, u.ssh_keys) for u in first.users]
    assert "not written for NX-OS yet" not in report.to_text()


def test_from_eos() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "clock summer-time CEST 5 Sunday March 02:00 5 Sunday October 03:00 60\n" in out
    assert back.system.banner_motd == first.system.banner_login
    assert back.system.syslog_transport == first.system.syslog_transport
    assert back.system.logging_buffer == first.system.logging_buffer
    assert back.management.password_min_length == first.management.password_min_length
    assert set(back.management.apis) == {"http", "gnmi", "netconf"}
    assert "  rule 5 permit command show *\n" in out
    assert _findings(report, "role-rules") and _findings(report, "timezone") and _findings(report, "logging-facility")
    text = report.to_text()
    for gone in ("login banner: not written", "CLI roles", "minimum password length: not written",
                 "the APIs http"):
        assert gone not in text, gone

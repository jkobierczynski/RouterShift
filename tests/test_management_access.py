"""Roles, SSH keys, banners, local logging, SNMP views, the programmatic interfaces and the password length between
EOS and IOS."""
from routershift.convert import convert, parse

EOS = """hostname leaf1
vrf instance MGMT
banner login
AUTHORIZED ACCESS ONLY
EOF
role NOC-READONLY
   10 permit mode exec command show|ping|traceroute
   20 deny mode exec command .*
   30 deny mode config-all command .*
username noc privilege 1 role NOC-READONLY secret 0 n0c-pass
username automation privilege 15 role network-admin nopassword
username automation ssh-key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample automation@ci
management security
   password
      minimum length 12
management api http-commands
   no shutdown
   vrf MGMT
      no shutdown
      ip access-group ACL-MGMT-IN
management api gnmi
   transport grpc MGMT
      vrf MGMT
   provider eos-native
management api netconf
   transport ssh MGMT
      vrf MGMT
logging buffered 64000 debugging
logging console errors
logging format timestamp high-resolution
logging format hostname fqdn
logging level BGP informational
snmp-server engineID local 000000000000000000BEEF21
snmp-server view RESTRICTED iso included
snmp-server view RESTRICTED snmpUsmMIB excluded
snmp-server group NMS-RO v3 priv read RESTRICTED
ip access-list standard ACL-MGMT-IN
   10 permit 10.0.0.0/8
"""

IOS = """hostname core1
banner exec ^CWelcome^C
banner login ^CKeep out^C
service timestamps log datetime msec localtime show-timezone
logging buffered 32000 informational
logging monitor warnings
logging origin-id ip
parser view NOC
 secret 5 $1$abc
 commands exec include all show
 commands exec include ping
username noc privilege 1 view NOC secret 0 n0c-pass
ip ssh pubkey-chain
  username netops
   key-string
    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQExample netops@host
    exit
security passwords min-length 10
netconf-yang
restconf
ip http secure-server
snmp-server view V1 iso included
snmp-server engineID local 800000090300AABBCCDDEEFF
"""


def _clean(text: str, brand: str) -> None:
    left = [u.text for u in parse(text, brand).unparsed]
    assert left == [], left


def test_eos_management_to_ios() -> None:
    dev = parse(EOS, "eos")
    _clean(EOS, "eos")
    assert dev.roles["NOC-READONLY"].rules[0].command == "show|ping|traceroute"
    users = {u.name: u for u in dev.users}
    assert users["noc"].role == "NOC-READONLY" and users["automation"].ssh_keys
    assert dev.management.apis == {"http": "MGMT", "gnmi": "MGMT", "netconf": "MGMT"}
    assert dev.management.password_min_length == 12 and dev.snmp.views["RESTRICTED"][1] == ("snmpUsmMIB", False)
    out, report = convert(EOS, "eos", "ios")
    assert "parser view NOC-READONLY\n" in out and " commands exec include all ping\n" in out
    assert "username noc privilege 1 view NOC-READONLY" in out
    assert "ip ssh pubkey-chain\n  username automation\n   key-string\n" in out
    assert "banner login ^C\nAUTHORIZED ACCESS ONLY\n^C\n" in out
    assert "logging buffered 64000 debugging\nlogging console errors\n" in out
    assert "service timestamps log datetime msec" in out and "logging origin-id hostname\n" in out
    assert "snmp-server engineID local 000000000000000000BEEF21\n" in out
    assert "snmp-server view RESTRICTED snmpUsmMIB excluded\n" in out
    assert "restconf\n" in out and "netconf-yang\n" in out and "gnxi\n" in out
    assert "security passwords min-length 12\n" in out
    text = report.to_text()
    assert "parser view" in text and "RESTCONF" in text and "per-facility" in text
    assert "MIB views are not converted" not in text
    _clean(out, "ios")


def test_ios_management_to_eos() -> None:
    dev = parse(IOS, "ios")
    _clean(IOS, "ios")
    assert dev.system.banner_exec == "Welcome" and dev.system.banner_login == "Keep out"
    assert dev.roles["NOC"].rules[1].command == "ping"
    assert {u.name: u.ssh_keys for u in dev.users}["netops"]
    out, report = convert(IOS, "ios", "eos")
    assert "role NOC\n   10 permit mode exec command show\n" in out and "deny mode config-all command .*" in out
    assert "username noc privilege 1 role NOC" in out
    assert "username netops ssh-key ssh-rsa AAAAB3" in out
    assert "banner login\nKeep out\nEOF\n" in out and "Welcome" not in out
    assert "logging format timestamp high-resolution\n" in out and "logging format hostname ipv4\n" in out
    assert "logging monitor warnings\n" in out
    assert "management api netconf\n" in out and "management api http-commands\n" in out
    assert "management security\n   password\n      minimum length 10\n" in out
    assert "EOS has no banner after login" in report.to_text()
    _clean(out, "eos")
    again, _ = convert(out, "eos", "ios")
    assert "parser view NOC\n" in again and "security passwords min-length 10\n" in again


def test_management_on_other_targets() -> None:
    _, report = convert(EOS, "eos", "junos")
    assert "the CLI roles NOC-READONLY" in report.to_text()

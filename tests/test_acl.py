import pytest
from helpers import sample

from routershift import acl as acl_text
from routershift.convert import convert, parse
from routershift.model import Acl, AclAction, AclEntry


def entry(text: str, family: int = 4, wildcards: bool = True, standard: bool = False) -> AclEntry:
    return acl_text.read_entry(text.split(), family, wildcards, standard)


def test_read_entries() -> None:
    e = entry("permit tcp 10.0.0.0 0.0.0.255 host 10.1.1.1 eq www 443 established log")
    assert (e.action, e.protocol, e.source, e.destination, e.dst_ports, e.established, e.log) == (
        AclAction.PERMIT, "tcp", "10.0.0.0/24", "10.1.1.1/32", "80,443", True, True)
    e = entry("deny udp any range 1000 2000 10.0.0.0/8 gt 1023")
    assert (e.src_ports, e.destination, e.dst_ports) == ("1000-2000", "10.0.0.0/8", "1024-65535")
    assert entry("permit icmp any any echo-reply").icmp_type == 0
    assert entry("permit icmp any any icmp-type 8").icmp_type == 8
    assert entry("permit 192.168.0.0 0.0.255.255", standard=True).source == "192.168.0.0/16"
    assert entry("permit ip 0.0.0.0 255.255.255.255 any").source == "any"
    # AOS-CX: a bare address is a host, masks follow a slash
    e = entry("permit any 10.0.0.1 10.2.0.0/255.255.0.0", wildcards=False)
    assert (e.protocol, e.source, e.destination) == ("ip", "10.0.0.1/32", "10.2.0.0/16")
    e = entry("permit icmp any 2001:db8::/32", family=6)
    assert (e.protocol, e.destination) == ("icmpv6", "2001:db8::/32")
    assert entry("remark keep this").remark == "keep this"


@pytest.mark.parametrize("text", ["permit tcp object-group A any", "permit ip 10.0.0.0 0.255.0.255 any",
                                  "permit tcp any any neq 80", "permit tcp any any eq 80 time-range WORK"])
def test_unsupported_entries(text: str) -> None:
    with pytest.raises(acl_text.Unsupported):
        entry(text)


def test_numbering_keeps_or_renumbers() -> None:
    acl = Acl("A", entries=[AclEntry(AclAction.PERMIT, sequence=5, protocol="tcp", dst_ports="22"),
                            AclEntry(AclAction.DENY, sequence=7)])
    assert [seq for seq, *_ in acl_text.numbered(acl)] == [5, 7]
    acl.entries[0].dst_ports = "22,80"  # two entries on platforms with one port match per side
    assert [seq for seq, *_ in acl_text.numbered(acl)] == [10, 20, 30]
    assert acl_text.port_items("0-1023,8080,1024-65535,5000-5010") == [
        ("lt", [1024]), ("eq", [8080]), ("gt", [1023]), ("range", [5000, 5010])]


def test_parse_acls_and_bindings_everywhere() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert set(ios.acls) == {"USERS-IN", "MGMT-ONLY", "101", "V6-IN", "VIDEO"}
    assert ios.acls["USERS-IN"].entries[0].action == AclAction.REMARK
    assert ios.acls["USERS-IN"].entries[5].unsupported.startswith("50 permit tcp object-group")
    assert ios.acls["V6-IN"].family == 6 and ios.acls["V6-IN"].entries[0].sequence == 10
    assert (ios.interfaces["Vlan99"].acl_in, ios.interfaces["Vlan99"].acl6_in) == ("USERS-IN", "V6-IN")
    assert parse(sample("eos_leaf.cfg"), "eos").interfaces["Vlan100"].acl_in == "SERVERS-IN"
    cx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert cx.interfaces["Vlan10"].acl_in == "USERS-IN" and cx.acls["USERS-IN"].entries[3].protocol == "ip"
    aoss = parse(sample("aoss_edge.cfg"), "aoss")
    assert aoss.acls["MGMT-IN"].entries[2].source == "any" and aoss.interfaces["Vlan99"].acl_in == "MGMT-IN"
    cw = parse(sample("comware_access.cfg"), "comware")
    rules = cw.acls["USERS-IN"].entries
    assert rules[0].remark == "allow web" and rules[1].dst_ports == "443" and rules[3].log
    assert cw.interfaces["Vlan10"].acl_in == "USERS-IN"


def test_acl_writers() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "   30 permit tcp 10.10.0.0/24 any eq 80\n   40 permit tcp 10.10.0.0/24 any eq 443\n" in out
    assert "   70 remark RouterShift could not convert: 50 permit tcp object-group CLIENTS any eq 8443\n" in out
    assert "ip access-list ACL-101\n" in out and "   ipv6 access-group V6-IN in\n" in out
    assert any(i.status == "needs-review" for i in report.items.values() if i.kind == "acl")
    out, _ = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "    20 permit udp 10.10.0.0/255.255.255.0 10.0.0.53 eq 53\n" in out
    assert "    apply access-list ip USERS-IN routed-in\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert '   10 remark "allow DNS and web"\n   20 permit udp 10.10.0.0 0.0.0.255 host 10.0.0.53 eq 53\n' in out
    assert '   ip access-group "USERS-IN" in\n' in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert (" rule 10 permit udp source 10.10.0.0 0.0.0.255 destination 10.0.0.53 0.0.0.0 destination-port eq 53\n"
            " rule 10 comment allow DNS and web\n") in out
    assert " rule 10 permit tcp destination 2001:db8:: 32 destination-port eq 443\n" in out
    assert " packet-filter name USERS-IN inbound\n packet-filter ipv6 name V6-IN inbound\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "ios")
    assert " 20 permit tcp 10.10.0.0 0.0.0.255 any eq 443\n" in out  # rule 0 is renumbered

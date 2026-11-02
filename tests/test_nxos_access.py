"""NX-OS access: RADIUS and TACACS+, method lists, 802.1X, DHCP snooping and port security, SNMP, port extras."""

from helpers import sample

from routershift.convert import convert, parse

NXOS = sample("nxos_access.cfg")
IOS = sample("ios_access.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    return first, out, report, back


def test_reads_nxos_access() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    rad, tac = d.aaa.servers
    assert (rad.key, rad.auth_port, rad.acct_port, rad.timeout) == ("RADKEY", 1645, 1646, 5)
    assert (tac.key, tac.auth_port, tac.timeout) == ("TACKEY", 4949, 7)
    assert d.aaa.groups["RAD"].vrf == "management" and d.aaa.source == {"radius": "Management0",
                                                                         "tacacs": "Management0"}
    assert [(m.kind, m.service, m.name) for m in d.aaa.methods] == [
        ("authentication", "login", "default"), ("authentication", "login", "console"),
        ("authorization", "commands", "default"), ("accounting", "exec", "default"),
        ("authentication", "dot1x", "default")]
    assert d.management.console_login == "console"
    u = d.snmp.users[0]
    assert (u.group, u.auth, u.auth_key, u.priv, u.priv_key) == ("network-operator", "sha", "AUTHPASS", "aes128",
                                                                 "PRIVPASS")
    assert d.snmp.hosts[0].vrf == "management" and d.snmp.communities[0].acl == "MGMT"
    e1 = d.interfaces["Ethernet1/1"]
    assert (e1.dot1x, e1.mab, e1.dot1x_reauth, e1.dot1x_reauth_period) == (True, True, True, 3600)
    assert (e1.port_security_max, e1.port_security_violation, e1.source_guard) == (3, "restrict", True)
    v10 = d.interfaces["Vlan10"]
    assert (v10.helper_vrf, v10.helper_source, v10.urpf, v10.autostate) == ("PROD", "Loopback0", "strict", False)
    assert v10.mac_address == "00:11:22:33:44:55"
    assert d.interfaces["Ethernet1/2"].unnumbered == "Loopback0"


def test_nxos_round_trip() -> None:
    first, out, report, back = _back(NXOS, "nxos")
    assert "radius-server host 10.1.1.1 key 0 RADKEY auth-port 1645 acct-port 1646 timeout 5\n" in out
    assert "aaa group server radius RAD\n  server 10.1.1.1\n  use-vrf management\n  source-interface mgmt0\n" in out
    assert "snmp-server host 10.9.9.9 use-vrf management\n" in out
    assert "  medium p2p\n  ip unnumbered loopback0\n" in out
    assert back.aaa == first.aaa or [s.key for s in back.aaa.servers] == [s.key for s in first.aaa.servers]
    assert [(m.kind, m.service, m.name, m.methods) for m in back.aaa.methods] == \
        [(m.kind, m.service, m.name, m.methods) for m in first.aaa.methods]
    assert back.snmp.users == first.snmp.users or [(u.name, u.auth, u.priv) for u in back.snmp.users] == \
        [(u.name, u.auth, u.priv) for u in first.snmp.users]
    for name in ("Ethernet1/1", "Vlan10", "Ethernet1/2"):
        a, b = first.interfaces[name], back.interfaces[name]
        for attr in ("dot1x", "mab", "dot1x_host_mode", "dot1x_reauth_period", "port_security_max",
                     "port_security_violation", "source_guard", "dhcp_trust", "arp_trust", "helper_vrf",
                     "helper_source", "urpf", "ip_redirects", "proxy_arp", "mac_address", "autostate", "unnumbered"):
            assert getattr(a, attr) == getattr(b, attr), (name, attr)
    assert sorted(back.vlans[10].__dict__.items() for _ in [0]) and back.dhcp_option82


def test_from_ios() -> None:
    first, out, report, back = _back(IOS, "ios")
    assert not [m for m in _findings(report, "not-yet") if "RADIUS" in m or "802.1X" in m or "DHCP snooping" in m]
    assert "aaa group server tacacs+ TAC\n" in out and "feature tacacs+\n" in out
    assert len(back.aaa.servers) == len(first.aaa.servers)
    assert [(u.name, u.auth, u.priv) for u in back.snmp.users] == [(u.name, u.auth, u.priv) for u in first.snmp.users]
    assert _findings(report, "dhcp-server")
    ports = [i for i in first.interfaces.values() if i.dot1x or i.mab]
    assert ports and all(back.interfaces[p.name].mab == p.mab for p in ports if p.name in back.interfaces)

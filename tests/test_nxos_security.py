"""NX-OS security: MACsec policies and key chains, MAC ACLs, NAT; IPsec is reported."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")
IOS = sample("ios_access.cfg")
NXOS = """\
feature macsec
feature nat
key chain KC-DCI macsec
  key 0102
    key-octet-string 00112233445566778899aabbccddeeff cryptographic-algorithm AES_128_CMAC
macsec policy DCI
  cipher-suite GCM-AES-128
  key-server-priority 16
  sak-expiry-time 1800
mac access-list BLOCK
  10 remark legacy
  20 deny 0011.2233.4455 0000.0000.0000 any 0x0806 vlan 10
  30 permit any any
ip access-list INSIDE
  10 permit ip 10.0.0.0/8 any
ip nat pool PUB 192.0.2.10 192.0.2.20 prefix-length 28
ip nat inside source list INSIDE pool PUB overload
ip nat inside source static tcp 10.0.0.5 443 192.0.2.5 8443
interface Ethernet1/1
  macsec keychain KC-DCI policy DCI
  no switchport
  ip address 198.51.100.1/30
  ip nat outside
interface Ethernet1/2
  mac port access-group BLOCK
interface Vlan10
  ip address 10.0.10.1/24
  ip nat inside
"""


def _findings(report, code):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_reads_nxos_security() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    p = d.macsec_profiles["DCI"]
    assert (p.cipher, p.key_server_priority, p.rekey_period, p.ckn, p.cak) == \
        ("aes128-gcm", 16, 1800, "0102", "00112233445566778899aabbccddeeff")
    assert d.interfaces["Ethernet1/1"].macsec_profile == "DCI"
    e = d.mac_acls["BLOCK"].entries
    assert e[1].source == "00:11:22:33:44:55 00:00:00:00:00:00" and (e[1].ethertype, e[1].vlan) == (0x0806, 10)
    assert d.interfaces["Ethernet1/2"].mac_acl_in == "BLOCK"
    assert d.nat_pools["PUB"].prefix_len == 28 and [r.kind for r in d.nat_rules] == ["dynamic", "static"]
    assert d.nat_rules[0].overload and d.nat_rules[1].translated_port == 8443
    assert (d.interfaces["Ethernet1/1"].nat, d.interfaces["Vlan10"].nat) == ("outside", "inside")


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, _ = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []

    def plain(d, attr):
        return {k: {f: x for f, x in vars(v).items() if f != "origin"} for k, v in getattr(d, attr).items()}
    for attr in ("macsec_profiles", "mac_acls", "nat_pools"):
        assert plain(back, attr) == plain(first, attr), attr
    assert [(r.kind, r.acl, r.pool, r.overload, r.local, r.translated_port) for r in back.nat_rules] == \
        [(r.kind, r.acl, r.pool, r.overload, r.local, r.translated_port) for r in first.nat_rules]
    for name in ("Ethernet1/1", "Ethernet1/2", "Vlan10"):
        a, b = first.interfaces[name], back.interfaces[name]
        assert (a.macsec_profile, a.mac_acl_in, a.nat) == (b.macsec_profile, b.mac_acl_in, b.nat), name


def test_from_eos() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "feature macsec\n" in out and "  cipher-suite GCM-AES-XPN-256\n" in out
    p, q = first.macsec_profiles["MACSEC-DCI"], back.macsec_profiles["MACSEC-DCI"]
    assert (q.cipher, q.ckn, q.key_server_priority, q.rekey_period) == \
        (p.cipher, p.ckn, p.key_server_priority, p.rekey_period)
    assert {n: [(e.action, e.source, e.destination, e.ethertype, e.vlan) for e in a.entries]
            for n, a in back.mac_acls.items()} == \
        {n: [(e.action, e.source, e.destination, e.ethertype, e.vlan) for e in a.entries]
         for n, a in first.mac_acls.items()}
    assert sorted(i.macsec_profile for i in back.interfaces.values() if i.macsec_profile) == \
        sorted(i.macsec_profile for i in first.interfaces.values() if i.macsec_profile)
    assert _findings(report, "macsec-options") and _findings(report, "macsec-key")
    assert "MAC access lists: not written" not in report.to_text()


def test_from_ios_nat_and_ipsec() -> None:
    out, report = convert(IOS, "ios", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "feature nat\n" in out and "ip nat inside source static tcp 10.10.0.5 80 10.99.0.20 8080\n" in out
    assert len(back.nat_rules) == len(parse(IOS, "ios").nat_rules)
    assert _findings(report, "nat-tcam") and _findings(report, "vpn-unsupported")
    assert "NAT is not written" not in report.to_text() and "IPsec is not written" not in report.to_text()

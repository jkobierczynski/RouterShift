"""AOS-CX device security: control-plane ACLs and CoPP classes, MACsec, MAC ACLs, written and read back."""

from helpers import sample

from routershift.convert import convert, parse
from routershift.names import PortMapper
from routershift.parsers.aoscx import canonical

EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "aoscx")
    back = parse(out, "aoscx")
    assert [u.text for u in back.unparsed] == []
    return first, out, report, back


def test_control_plane() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "apply access-list ip ACL-CPP-MGMT control-plane vrf mgmt\n" in out
    assert "copp-policy RS-COPP\n    class bgp-ipv4 priority 6 rate 5000\n" in out
    assert back.control_plane is not None and back.control_plane.acls == {"mgmt": "ACL-CPP-MGMT"}
    assert [(c.name, c.pps) for c in back.control_plane.classes] == \
        [(c.name, c.pps) for c in first.control_plane.classes]
    assert _findings(report, "copp-default-acl")


def test_macsec() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "mka policy MACSEC-DCI\n    pre-shared-key ckn 0a cak plaintext CHANGE-ME\n" in out
    p, q = first.macsec_profiles["MACSEC-DCI"], back.macsec_profiles["MACSEC-DCI"]
    assert (q.cipher, q.ckn, q.key_server_priority, q.sci) == (p.cipher, p.ckn, p.key_server_priority, p.sci)
    ports = PortMapper(first, "aoscx")
    for name, iface in first.interfaces.items():
        if iface.macsec_profile:
            assert back.interfaces[canonical(ports(name))[0]].macsec_profile == iface.macsec_profile
    assert _findings(report, "macsec-key") and _findings(report, "macsec-options")


def test_mac_acls() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "access-list mac MACL-PROTECT-LEGACY\n    10 deny any any 0x88cc vlan 900\n    20 permit any any any\n" in out
    for name, acl in first.mac_acls.items():
        assert [vars(e) for e in back.mac_acls[name].entries] == [vars(e) for e in acl.entries]
    ports = PortMapper(first, "aoscx")
    for name, iface in first.interfaces.items():
        if iface.mac_acl_in:
            assert back.interfaces[canonical(ports(name))[0]].mac_acl_in == iface.mac_acl_in


def test_mac_masks_from_ios() -> None:
    ios = ("hostname s\nmac access-list extended M\n permit host 0011.2233.4455 any\n"
           " deny 0011.2200.0000 0000.00ff.ffff any 0x806 0x0\n")
    first, out, report, back = _back(ios, "ios")
    assert "    10 permit 00:11:22:33:44:55 any any\n" in out
    assert "    20 deny 00:11:22:00:00:00/ff:ff:ff:00:00:00 any 0x0806\n" in out
    assert [vars(e) for e in back.mac_acls["M"].entries] == \
        [{**vars(e), "sequence": e.sequence or 10 * n} for n, e in enumerate(first.mac_acls["M"].entries, 1)]

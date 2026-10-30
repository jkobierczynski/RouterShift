from helpers import sample

from routershift import nat as nat_text
from routershift.convert import convert, parse


def test_ios_reader() -> None:
    device = parse(sample("ios_access.cfg"), "ios")
    assert device.interfaces["Vlan99"].nat == "outside"
    pool = device.nat_pools["PUBLIC"]
    assert (pool.first, pool.last, pool.prefix_len) == ("10.99.0.100", "10.99.0.110", 24)
    assert [nat_text.label(r) for r in device.nat_rules] == [
        "dynamic MGMT-ONLY -> interface overload", "dynamic 101 -> pool PUBLIC", "static 10.10.0.6 -> 10.99.0.7",
        "static 10.10.0.5 -> 10.99.0.20 tcp 80->8080"]
    assert device.nat_rules[0].interface == "Vlan99"
    port = device.nat_rules[3]
    assert (port.protocol, port.local_port, port.translated_port) == ("tcp", 80, 8080)


def test_ios_netmask_pool_and_vrf() -> None:
    text = ("ip nat pool P 192.0.2.1 192.0.2.6 netmask 255.255.255.248\n"
            "ip nat inside source list 10 pool P overload vrf RED\n")
    device = parse(text, "ios")
    assert device.nat_pools["P"].prefix_len == 29
    [rule] = device.nat_rules
    assert (rule.acl, rule.pool, rule.overload, rule.vrf) == ("10", "P", True, "RED")


def test_eos_reader() -> None:
    device = parse(sample("eos_leaf.cfg"), "eos")
    assert device.interfaces["Ethernet49/1"].nat == "outside"
    assert [(nat_text.label(r), r.interface) for r in device.nat_rules] == [
        ("static 10.100.0.10 -> 10.255.0.10", "Ethernet49/1"),
        ("dynamic NAT-SRC -> interface overload", "Ethernet49/1")]


def test_comware_reader() -> None:
    device = parse(sample("comware_access.cfg"), "comware")
    assert (device.nat_pools["1"].first, device.nat_pools["1"].last) == ("10.255.0.8", "10.255.0.9")
    assert [nat_text.label(r) for r in device.nat_rules] == [
        "static 10.10.0.6 -> 10.255.0.7", "dynamic USERS-IN -> pool 1 overload",
        "static 10.10.0.5 -> 10.255.0.5 tcp 80->8080"]


def test_comware_named_group_and_plain_outbound() -> None:
    text = ("interface GigabitEthernet1/0/1\n port link-mode route\n ip address 198.51.100.2 255.255.255.0\n"
            " nat outbound 3000 address-group 2 no-pat\n nat outbound\n"
            " nat server global 198.51.100.9 inside 10.0.0.9 vpn-instance RED\n"
            "#\nnat address-group 2 name WAN\n address 198.51.100.10 198.51.100.20\n#\n")
    device = parse(text, "comware")
    assert device.unparsed == []
    assert device.nat_pools["WAN"].prefix_len == 24  # taken from the interface the group sits in
    pat, plain, server = device.nat_rules
    assert (pat.acl, pat.pool, pat.overload) == ("3000", "WAN", False)
    assert (plain.acl, plain.pool, plain.overload) == ("", "", True)
    assert (server.local, server.translated, server.vrf, server.interface) == (
        "10.0.0.9", "198.51.100.9", "RED", "Ethernet1/0/1")
    # IOS needs an ACL for the sources
    out, report = convert(text, "comware", "ios")
    assert "ip nat inside source list ACL-3000 pool WAN\n" in out
    assert "the rule translates every source" in report.to_text()


def test_comware_writer() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "comware")
    assert "nat address-group 1\n address 10.99.0.100 10.99.0.110" in out
    assert " nat static outbound 10.10.0.6 10.99.0.7" in out
    for line in ("nat outbound name MGMT-ONLY", "nat outbound name ACL-101 address-group 1 no-pat",
                 "nat static enable", "nat server protocol tcp global 10.99.0.20 8080 inside 10.10.0.5 80"):
        assert f" {line}\n" in out
    assert "written as address group 1" in report.to_text()


def test_unknown_pool_mask_is_flagged() -> None:
    _, report = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "the source gives no mask for the pool" in report.to_text()


def test_ios_from_eos_marks_outside_and_flags_inside() -> None:
    out, report = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert "ip nat inside source list NAT-SRC interface GigabitEthernet1/0/3 overload" in out
    assert "ip nat outside" in out
    assert "add 'ip nat inside' to them" in report.to_text()


def test_eos_skips_port_forwarding() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "ip nat source dynamic access-list ACL-101 pool PUBLIC" in out
    assert "8080" not in out
    assert "static port forwarding is not written for EOS" in report.to_text()


def test_aos_switches_report_every_rule() -> None:
    for target, name in (("aoscx", "AOS-CX"), ("aoss", "AOS-S")):
        out, report = convert(sample("ios_access.cfg"), "ios", target)
        assert "nat " not in out.lower().replace("native", "")
        assert report.to_text().count(f"{name} switches do not do NAT") == 4

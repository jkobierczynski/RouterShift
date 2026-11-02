"""Junos RIP, IS-IS, MPLS with LDP and tunnel interfaces, written and read back; NAT and IPsec reported."""

from helpers import sample

from routershift.convert import convert, parse


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def _isis_ports(d):
    return sorted((i.isis_passive, i.isis_metric, i.isis_network) for i in d.interfaces.values() if i.isis)


def test_ios_rip_isis_mpls() -> None:
    first, out, report, back = _back(sample("ios_access.cfg"), "ios")
    a, b = first.rip, back.rip
    assert a is not None and b is not None
    assert (b.version, b.networks, b.redistribute, b.default_originate) == \
        (a.version, a.networks, a.redistribute, a.default_originate)
    assert "route-filter 10.0.0.0/8 orlonger;" in out and "neighbor irb.99;" in out
    assert "RIP-EXPORT" not in back.route_maps
    i, j = first.isis, back.isis
    assert i is not None and j is not None
    assert (j.nets, j.level, j.wide_metrics, j.redistribute, j.redistribute_maps) == \
        (i.nets, i.level, i.wide_metrics, i.redistribute, i.redistribute_maps)
    assert _isis_ports(back) == _isis_ports(first)
    assert back.mpls.ldp and [n for n, x in back.interfaces.items() if x.mpls] == ["Vlan99"]
    assert report.items[("isis", "isis CORE")].status == "approximated"  # the process tag


def test_comware_rip_passive() -> None:
    first, out, report, back = _back(sample("comware_access.cfg"), "comware")
    a, b = first.rip, back.rip
    assert a is not None and b is not None
    assert b.passive_default and len(b.active_interfaces) == len(a.active_interfaces)
    assert "send none;" in out


def test_gre_tunnel() -> None:
    text = """\
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
!
interface Tunnel5
 ip address 172.16.5.1 255.255.255.252
 tunnel source Loopback0
 tunnel destination 192.0.2.9
!
"""
    first, out, report, back = _back(text, "ios")
    assert "gr-0/0/0 {" in out and "source 10.0.0.1;" in out
    t = back.interfaces["Tunnel5"]
    assert (t.tunnel_source, t.tunnel_destination, t.ipv4) == ("10.0.0.1", "192.0.2.9", ["172.16.5.1/30"])
    assert report.items[("interface", "Tunnel5 -> gr-0/0/0.5")].status == "approximated"


def test_nat_and_ipsec_reported() -> None:
    first, out, report, back = _back(sample("ios_access.cfg"), "ios")
    text = report.to_text()
    assert "Junos switches do not translate addresses" in text and "Junos switches do not terminate IPsec" in text
    assert "not written for Junos yet" not in text
    assert back.interfaces["Tunnel10"].ipv4 == first.interfaces["Tunnel10"].ipv4

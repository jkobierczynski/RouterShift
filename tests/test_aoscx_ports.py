"""AOS-CX port and gateway settings: anycast gateways, DHCP relay to another VRF, ICMP and proxy ARP, option 82,
the 802.1X reject VLAN and RADIUS CoA, written and read back."""

from helpers import sample

from routershift.convert import convert, parse
from routershift.names import PortMapper
from routershift.parsers.aoscx import canonical

EOS = sample("eos_border_leaf.cfg")


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "aoscx")
    back = parse(out, "aoscx")
    assert back.unparsed == []
    return first, out, report, back


def _name(first, name: str) -> str:
    return canonical(PortMapper(first, "aoscx")(name))[0]


def test_anycast_gateway() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "    active-gateway ip mac 00:1c:73:00:dc:01\n    active-gateway ip 10.1.100.1\n" in out
    for name, iface in first.interfaces.items():
        if iface.virtual_ipv4:
            got = back.interfaces[_name(first, name)]
            assert (got.virtual_ipv4, got.virtual_ipv6, got.ipv4) == \
                (iface.virtual_ipv4, iface.virtual_ipv6, iface.ipv4), name
    assert back.anycast_mac == first.anycast_mac


def test_relay_icmp_and_port_access() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "ip helper-address 10.100.0.67 vrf mgmt" in out
    assert back.interfaces["Vlan100"].helper_vrf == "mgmt"  # the management VRF's AOS-CX name
    assert "no ip icmp redirect" in out and "no ip icmp unreachable" in out
    edge = [n for n, i in first.interfaces.items() if i.ip_redirects is False]
    assert edge and all(back.interfaces[_name(first, n)].ip_redirects is False for n in edge)
    fail = {n: i.dot1x_fail_vlan for n, i in first.interfaces.items() if i.dot1x_fail_vlan}
    assert fail and {n: back.interfaces[_name(first, n)].dot1x_fail_vlan for n in fail} == fail
    assert back.aaa.coa == first.aaa.coa and back.dhcp_option82 == first.dhcp_option82
    text = report.to_text()
    assert "AOS-CX has no unicast RPF check" in text and "not written for AOS-CX yet" not in \
        text.split("Vlan100 ->")[1].split("\n  ")[0]

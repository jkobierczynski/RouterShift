"""AOS-CX multicast routing: rendezvous points with their groups, PIM in VRFs, MSDP and anycast RP, written and read
back; the IGMP querier is reported."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_rendezvous_points_and_vrfs() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "aoscx")
    assert "router pim\n    enable\n    rp-address 10.255.0.1 239.1.0.0/16\n" in out
    assert "router pim vrf PROD\n    enable\n    rp-address 10.1.255.1 239.10.0.0/16\n" in out
    back = parse(out, "aoscx")
    assert back.unparsed == []
    assert back.pim_rp_groups == first.pim_rp_groups
    assert back.multicast_vrfs["PROD"].rp_groups == first.multicast_vrfs["PROD"].rp_groups
    assert back.multicast_vrfs["PROD"].routing
    # the anycast RP's peers become MSDP peers
    assert "router msdp\n    enable\n    ip msdp peer 10.255.0.11\n        enable\n" in out
    assert set(back.msdp_peers) == {"10.255.0.11", "10.255.0.12"}
    assert any("10.255.0.1" in m for m in _findings(report, "anycast-rp"))
    assert any("10.1.100.2" in m for m in _findings(report, "igmp-querier"))
    assert not any("rendezvous" in m or "MSDP" in m for m in _findings(report, "not-written"))


def test_msdp_from_ios() -> None:
    ios = ("hostname r\nip multicast-routing\ninterface Loopback0\n ip address 10.0.0.1 255.255.255.255\n"
           "ip msdp peer 10.0.0.2 connect-source Loopback0\n")
    out, report = convert(ios, "ios", "aoscx")
    assert "    ip msdp peer 10.0.0.2\n        connect-source loopback 0\n        enable\n" in out
    back = parse(out, "aoscx")
    assert back.unparsed == [] and back.msdp_peers == {"10.0.0.2": "Loopback0"}

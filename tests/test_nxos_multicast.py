"""NX-OS multicast: IGMP snooping and its querier, PIM rendezvous points (also in VRFs), anycast RP, MSDP."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")
NXOS = """\
feature pim
feature msdp
vlan 10,20
vlan configuration 20
  no ip igmp snooping
vlan configuration 10
  ip igmp snooping querier 10.0.10.2
ip pim rp-address 10.255.0.1 group-list 239.0.0.0/8
ip pim anycast-rp 10.255.0.1 10.255.0.11
ip msdp peer 10.255.0.12 connect-source loopback0
vrf context PROD
  ip pim rp-address 10.1.255.1
interface loopback0
  ip address 10.255.0.11/32
interface Vlan10
  ip address 10.0.10.1/24
  ip pim sparse-mode
  ip igmp version 3
"""


def test_reads_nxos_multicast() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    assert d.multicast_routing and d.pim_rps == ["10.255.0.1"] and d.pim_rp_groups == {"10.255.0.1": "239.0.0.0/8"}
    assert d.pim_anycast == {"10.255.0.1": ["10.255.0.11"]} and d.msdp_peers == {"10.255.0.12": "Loopback0"}
    assert d.multicast_vrfs["PROD"].rps == ["10.1.255.1"] and d.multicast_vrfs["PROD"].routing
    assert d.vlans[20].igmp_snooping is False and d.vlans[10].igmp_querier_address == "10.0.10.2"
    assert (d.interfaces["Vlan10"].pim, d.interfaces["Vlan10"].igmp_version) == ("sparse", 3)


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, _ = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    for attr in ("multicast_routing", "pim_rps", "pim_rp_groups", "pim_anycast", "msdp_peers", "multicast_vrfs"):
        assert getattr(back, attr) == getattr(first, attr), attr
    def igmp(d):
        return {v: (x.igmp_snooping, x.igmp_querier, x.igmp_querier_address) for v, x in d.vlans.items()}
    assert igmp(back) == igmp(first)


def test_from_eos() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "feature pim\n" in out and "ip pim anycast-rp 10.255.0.1 10.255.0.11\n" in out
    assert back.pim_rps == first.pim_rps and back.pim_rp_groups == first.pim_rp_groups
    assert back.pim_anycast == first.pim_anycast
    assert {n: m.rps for n, m in back.multicast_vrfs.items()} == {n: m.rps for n, m in first.multicast_vrfs.items()}
    for vid, vlan in first.vlans.items():
        if vlan.igmp_querier_address:
            assert back.vlans[vid].igmp_querier_address == vlan.igmp_querier_address
    text = report.to_text()
    assert "IGMP snooping and PIM are not written" not in text and "anycast RP" not in text.split("not written")[0][-80:]

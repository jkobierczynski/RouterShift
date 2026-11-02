"""Junos multicast: PIM and IGMP on routed interfaces, rendezvous points in the main and VRF instances, anycast RP,
MSDP, and IGMP snooping with its querier."""

from helpers import sample

from routershift.convert import convert, parse
from routershift.emitters import junos
from routershift.names import PortMapper
from routershift.report import Report

EOS = sample("eos_border_leaf.cfg")


def test_border_leaf_multicast() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    assert back.multicast_routing and back.pim_rps == first.pim_rps and back.pim_rp_groups == first.pim_rp_groups
    assert back.multicast_vrfs == first.multicast_vrfs
    assert back.interfaces["Vlan100"].pim == "sparse" and back.interfaces["Vlan100"].vrf == "PROD"
    assert "interface irb.100 {" in out and "mode sparse;" in out
    # the border leaf owns none of the anycast RP addresses: Junos writes the RP set on the RPs only
    assert back.pim_anycast == {} and report.items[("system", "multicast routing")].status == "needs-review"
    assert back.igmp_snooping and back.vlans[100].igmp_querier and back.vlans[100].igmp_querier_address == "10.1.100.2"
    assert report.items[("vlan", "IGMP snooping")].status == "approximated"  # the querier version


def test_anycast_rp_and_msdp_on_an_rp() -> None:
    text = """\
hostname rp1
interface Loopback0
 ip address 10.0.0.11 255.255.255.255
interface Loopback1
 ip address 10.0.0.1 255.255.255.255
 ip pim sparse-mode
interface Vlan10
 ip address 10.1.10.1 255.255.255.0
 ip pim sparse-mode
 ip igmp version 3
ip multicast-routing
ip pim rp-address 10.0.0.1
ip msdp peer 10.0.0.12 connect-source Loopback0
"""
    first = parse(text, "ios")
    first.pim_anycast = {"10.0.0.1": ["10.0.0.11", "10.0.0.12"]}
    out = junos.emit(first, PortMapper(first, "junos"), Report("ios", "junos"))
    assert "local {" in out and "address 10.0.0.12;" in out and "local-address 10.0.0.11;" in out
    assert "local-address 10.0.0.11;" in out.split("msdp {")[1]
    back = parse(out, "junos")
    assert back.unparsed == []
    assert back.pim_anycast == first.pim_anycast and back.pim_rps == ["10.0.0.1"]
    assert back.msdp_peers == {"10.0.0.12": "Loopback0"}
    assert back.interfaces["Vlan10"].igmp_version == 3


def test_reads_native_junos_multicast() -> None:
    text = """\
set interfaces irb unit 20 family inet address 10.2.0.1/24
set vlans V20 vlan-id 20
set vlans V20 l3-interface irb.20
set routing-instances T instance-type vrf
set routing-instances T interface irb.20
set routing-instances T protocols pim rp static address 10.9.9.9 group-ranges 239.0.0.0/8
set routing-instances T protocols pim interface irb.20 mode sparse
set protocols igmp-snooping vlan V20
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    assert d.multicast_vrfs["T"].routing and d.multicast_vrfs["T"].rp_groups == {"10.9.9.9": "239.0.0.0/8"}
    assert d.interfaces["Vlan20"].pim == "sparse" and d.vlans[20].igmp_snooping

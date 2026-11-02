"""Rendezvous points with their groups and in VRFs, anycast RP (MSDP on IOS), and the IGMP querier's address and
version, both ways between EOS and IOS."""

from routershift.convert import convert, parse

EOS = """\
hostname bl1
vlan 100
vrf instance PROD
router multicast
   ipv4
      routing
      software-forwarding sfe
   vrf PROD
      ipv4
         routing
router pim sparse-mode
   ipv4
      rp address 10.255.0.1 239.1.0.0/16
      anycast-rp 10.255.0.1 10.255.0.11
      anycast-rp 10.255.0.1 10.255.0.12
   vrf PROD
      ipv4
         rp address 10.1.255.1 239.10.0.0/16
ip igmp snooping vlan 100 querier
ip igmp snooping vlan 100 querier address 10.1.100.2
ip igmp snooping vlan 100 querier version 3
"""

IOS = """\
hostname core
vlan 100
vrf definition PROD
 address-family ipv4
ip multicast-routing
ip multicast-routing vrf PROD
ip access-list standard RP-GROUPS
 permit 239.20.0.0 0.0.255.255
ip pim rp-address 10.0.0.1 RP-GROUPS override
ip pim vrf PROD rp-address 10.1.255.1
ip msdp peer 10.0.0.2 connect-source Loopback0 remote-as 65000
ip igmp snooping querier
ip igmp snooping querier address 10.1.100.2
ip igmp snooping querier version 2
interface Loopback0
 ip address 10.0.0.9 255.255.255.255
"""


def test_eos_reads_rps_vrfs_and_querier() -> None:
    d = parse(EOS, "eos")
    assert d.multicast_routing and d.multicast_vrfs["PROD"].routing
    assert d.pim_rps == ["10.255.0.1"] and d.pim_rp_groups == {"10.255.0.1": "239.1.0.0/16"}
    assert d.pim_anycast == {"10.255.0.1": ["10.255.0.11", "10.255.0.12"]}
    assert d.multicast_vrfs["PROD"].rp_groups == {"10.1.255.1": "239.10.0.0/16"}
    assert d.vlans[100].igmp_querier_address == "10.1.100.2" and d.vlans[100].igmp_querier_version == 3
    assert [u.text for u in d.unparsed] == ["software-forwarding sfe"]
    out, _ = convert(EOS, "eos", "eos")
    assert "router multicast\n   ipv4\n      routing\n   vrf PROD\n      ipv4\n         routing\n" in out
    assert "router pim sparse-mode\n   ipv4\n      rp address 10.255.0.1 239.1.0.0/16\n" \
        "      anycast-rp 10.255.0.1 10.255.0.11\n" in out
    assert "   vrf PROD\n      ipv4\n         rp address 10.1.255.1 239.10.0.0/16\n" in out
    assert "ip igmp snooping vlan 100 querier address 10.1.100.2\n" in out


def test_eos_to_ios_and_back() -> None:
    out, report = convert(EOS, "eos", "ios")
    assert "ip multicast-routing\nip multicast-routing vrf PROD\n" in out
    assert "ip access-list standard RS-PIM-RP-10-255-0-1\n permit 239.1.0.0 0.0.255.255\n" \
        "ip pim rp-address 10.255.0.1 RS-PIM-RP-10-255-0-1\n" in out
    assert "ip pim vrf PROD rp-address 10.1.255.1 RS-PIM-RP-10-1-255-1-PROD\n" in out
    assert "ip msdp peer 10.255.0.11\nip msdp peer 10.255.0.12\n" in out
    assert "ip igmp snooping querier address 10.1.100.2\nip igmp snooping querier version 3\n" in out
    text = report.to_text()
    assert "IOS shares an anycast RP through MSDP" in text
    back = parse(out, "ios")
    assert back.pim_rp_groups == {"10.255.0.1": "239.1.0.0/16"} and "RS-PIM-RP-10-255-0-1" not in back.acls
    assert back.multicast_vrfs["PROD"].rp_groups == {"10.1.255.1": "239.10.0.0/16"}
    assert back.unparsed == []


def test_ios_to_eos() -> None:
    d = parse(IOS, "ios")
    assert d.pim_rp_groups == {"10.0.0.1": "acl RP-GROUPS"} and d.multicast_vrfs["PROD"].rps == ["10.1.255.1"]
    assert d.msdp_peers == {"10.0.0.2": "Loopback0"} and d.igmp_querier_version == 2
    assert d.unparsed == []
    out, _ = convert(IOS, "ios", "eos")
    assert "      rp address 10.0.0.1 access-list RP-GROUPS\n" in out
    assert "   vrf PROD\n      ipv4\n         rp address 10.1.255.1\n" in out
    assert "router msdp\n   peer 10.0.0.2\n      local-interface Loopback0\n" in out
    assert "ip igmp snooping vlan 100 querier address 10.1.100.2\nip igmp snooping vlan 100 querier version 2\n" \
        in out
    assert parse(out, "eos").unparsed == []

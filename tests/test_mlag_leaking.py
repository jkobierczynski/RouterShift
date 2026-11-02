"""MLAG (StackWise Virtual on IOS, the nearest Catalyst feature), EOS trunk groups, and routes leaked between VRFs
without route targets (EOS router general, IOS XE route-replicate), both ways."""

from routershift.convert import convert, parse

EOS = """\
hostname bl1
vlan 100
vlan 4094
   trunk group MLAG
vrf instance PROD
vrf instance INET
interface Ethernet29/1
   channel-group 1000 mode active
interface Ethernet9/1
   channel-group 10 mode active
interface Port-Channel1000
   switchport mode trunk
   switchport trunk group MLAG
interface Port-Channel10
   switchport mode trunk
   switchport trunk allowed vlan 100
   mlag 10
interface Vlan4094
   no autostate
   ip address 10.255.252.0/31
mlag configuration
   domain-id DC1_BL_PAIR
   local-interface Vlan4094
   peer-address 10.255.252.1
   peer-address heartbeat 10.100.10.22 vrf MGMT
   peer-link Port-Channel1000
   dual-primary detection delay 5 action errdisable all-interfaces
   reload-delay mlag 300
   reload-delay non-mlag 330
router general
   router-id ipv4 10.255.0.21
   vrf PROD
      leak routes source-vrf INET subscribe-policy RM-LEAK
route-map RM-LEAK permit 10
"""

IOS_SVL = """\
hostname core
stackwise-virtual
 domain 7
interface TenGigabitEthernet1/0/47
 stackwise-virtual link 1
interface TenGigabitEthernet2/0/47
 stackwise-virtual link 1
interface GigabitEthernet1/0/1
 stackwise-virtual dual-active-detection
interface GigabitEthernet1/0/10
 channel-group 5 mode active
interface GigabitEthernet2/0/10
 channel-group 5 mode active
interface Port-channel5
 switchport mode trunk
vrf definition PROD
 address-family ipv4
  route-replicate from vrf INET unicast all route-map RM-LEAK
vrf definition INET
 address-family ipv4
"""


def test_eos_reads_mlag_options_trunk_groups_and_leaks() -> None:
    d = parse(EOS, "eos")
    m = d.mlag
    assert m is not None and m.heartbeat == "10.100.10.22" and m.heartbeat_vrf == "MGMT"
    assert m.dual_primary_delay == 5 and m.dual_primary_action == "errdisable all-interfaces"
    assert (m.reload_delay, m.reload_delay_non_mlag) == (300, 330)
    assert d.vlans[4094].trunk_groups == ["MLAG"] and d.interfaces["Port-channel1000"].trunk_groups == ["MLAG"]
    assert d.vrf_info["PROD"].leaks == {"INET": "RM-LEAK"} and d.system.router_id == "10.255.0.21"
    assert d.unparsed == []
    out, _ = convert(EOS, "eos", "eos")
    for line in ("   peer-address heartbeat 10.100.10.22 vrf MGMT\n",
                 "   dual-primary detection delay 5 action errdisable all-interfaces\n",
                 "   reload-delay mlag 300\n", "   reload-delay non-mlag 330\n", "   trunk group MLAG\n",
                 "   switchport trunk group MLAG\n", "router general\n   router-id ipv4 10.255.0.21\n   vrf PROD\n"
                 "      leak routes source-vrf INET subscribe-policy RM-LEAK\n"):
        assert line in out
    assert parse(out, "eos").unparsed == []


def test_eos_mlag_to_ios_stackwise_virtual() -> None:
    out, report = convert(EOS, "eos", "ios")
    assert "stackwise-virtual\n domain 1\n" in out
    # the peer link's port is the StackWise Virtual link instead of a member of Port-channel1000
    assert " stackwise-virtual link 1\n" in out and "channel-group 1000" not in out
    assert "  route-replicate from vrf INET unicast all route-map RM-LEAK\n" in out
    text = report.to_text()
    assert "written as StackWise Virtual, the nearest Catalyst feature" in text
    assert "the heartbeat 10.100.10.22" in text and "On NX-OS the same pair would be a vPC domain" in text
    assert "trunk group MLAG left out: IOS has no trunk groups" in text
    assert "routes of VRF INET leaked into it with route-replicate through route map RM-LEAK" in text
    back = parse(out, "ios")
    assert back.vrf_info["PROD"].leaks == {"INET": "RM-LEAK"}
    assert back.mlag is not None and back.mlag.stack
    assert [u.text for u in back.unparsed] == []


def test_ios_stackwise_virtual_to_eos_mlag() -> None:
    d = parse(IOS_SVL, "ios")
    assert d.mlag is not None and d.mlag.stack and d.mlag.domain == "7"
    assert d.interfaces["Ethernet1/0/47"].svl_link == 1 and d.interfaces["Ethernet1/0/1"].svl_dad
    assert d.unparsed == []
    out, report = convert(IOS_SVL, "ios", "eos")
    assert "mlag configuration\n   domain-id SVL7\n" in out
    # a port-channel with members on both switches becomes an MLAG
    assert "interface Port-Channel5\n" in out and "   mlag 5\n" in out.split("interface Port-Channel5\n", 1)[1]
    assert "router general\n   vrf PROD\n      leak routes source-vrf INET subscribe-policy RM-LEAK\n" in out
    text = report.to_text()
    assert "StackWise Virtual makes one switch of two; EOS pairs two switches with MLAG instead" in text
    out, _ = convert(IOS_SVL, "ios", "ios")
    assert "stackwise-virtual\n domain 7\n" in out and " stackwise-virtual dual-active-detection\n" in out

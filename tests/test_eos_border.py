"""An EOS border leaf converted to IOS: every item is either written correctly or reported, never called exact while
part of it was dropped."""

from typing import Dict

import pytest

from routershift.convert import convert, parse
from routershift.report import Report

EOS = """\
hostname bl1
ip name-server vrf MGMT 10.100.0.53
vrf instance MGMT
vrf instance PROD
vrf instance INET
ip virtual-router mac-address 00:1c:73:00:dc:01
!
management ssh
   idle-timeout 30
   ip access-group ACL-MGMT-IN vrf MGMT in
   vrf MGMT
      no shutdown
   shutdown
!
aaa authentication login default local
aaa authentication login console local
!
ntp local-interface vrf MGMT Management1
ntp server vrf MGMT 10.100.0.123
logging host 10.100.0.50 514 protocol udp
logging vrf MGMT host 10.100.0.50 514 protocol udp
logging vrf MGMT host 10.100.1.50 6514 protocol tls
logging vrf MGMT source-interface Management1
snmp-server enable traps bgp
snmp-server enable traps snmp link-down
!
ip access-list ACL-MGMT-IN
   10 permit tcp 10.100.0.0/23 any eq ssh
ip access-list ACL-VOICE
   10 permit udp any any range 16384 32767
!
class-map type qos match-any CM-VOICE
   match ip access-group ACL-VOICE
policy-map type quality-of-service PM-IN
   class CM-VOICE
      police rate 50 mbps burst-size 1 mbytes
!
interface Management1
   vrf MGMT
   ip address 10.100.10.21/24
!
interface Ethernet1/1-2/1
   description UNUSED
   shutdown
!
interface Ethernet3/1
   no switchport
   vrf INET
   ip address 198.51.100.1/31
   ipv6 address 2001:db8:ffff:a::1/127
   ip verify unicast source reachable-via rx
   no ip proxy-arp
   no ip redirects
   no ip unreachables
!
interface Ethernet4/1
   no switchport
   vrf PROD
   ip address 172.20.255.1/30
   ip ospf authentication message-digest
   ip ospf message-digest-key 1 sha256 7 AAAA
   ip ospf area 0.0.0.0
!
interface Port-Channel30
   switchport access vlan 300
   storm-control all level 2
!
interface Loopback100
   vrf PROD
   ip address 10.255.100.21/32
!
interface Vlan100
   vrf PROD
   ip address virtual 10.1.100.1/24
   ipv6 address virtual 2001:db8:1:100::1/64
   ip helper-address 10.100.0.67 vrf MGMT source-interface Loopback100
!
ip prefix-list PL-LOOPBACKS
   seq 10 permit 10.255.0.0/24 eq 32
ip prefix-list PL-DEFAULT
   seq 10 permit 0.0.0.0/0
!
ip community-list CL-BLACKHOLE permit 65535:666
ip as-path access-list AS-LONG permit ^([0-9]+ ){50,}[0-9]+$ any
!
route-map RM-IN deny 5
   match origin-as validity invalid
!
route-map RM-IN deny 30
   match as-path AS-LONG
!
route-map RM-IN permit 100
   set local-preference 200
!
route-map RM-OUT permit 20
   match community CL-BLACKHOLE
   set community 64496:666
!
route-map RM-OUT deny 50
   match large-community LC-ANY
!
route-map RM-EXPORT permit 10
   match ip address prefix-list PL-DEFAULT
   set extcommunity rt 65021:400 additive
!
route-map RM-TO-OSPF permit 10
   set metric-type type-1
!
router ospf 100 vrf PROD
   distribute-list route-map RM-IN in
   redistribute bgp route-map RM-TO-OSPF
   timers spf delay initial 50 200 5000
   timers lsa rx min interval 100
   max-lsa 12000 75 ignore-time 5 ignore-count 5 reset-time 5
   graceful-restart
!
router bgp 65021
   router-id 10.255.0.21
   maximum-paths 4 ecmp 4
   graceful-restart restart-time 300
   graceful-restart
   timers bgp 5 15
   distance bgp 20 200 200
   bgp bestpath as-path multipath-relax
   neighbor MLAG peer group
   neighbor MLAG remote-as 65021
   neighbor MLAG next-hop-self
   neighbor MLAG maximum-routes 12000
   !
   vrf PROD
      rd 10.255.0.21:50001
      route-target import evpn 50001:50001
      route-target export evpn 50001:50001
      route-target export evpn route-map RM-EXPORT
      router-id 10.255.0.21
      neighbor 10.255.251.1 peer group MLAG
      redistribute connected
      !
      address-family ipv6
         redistribute connected
   !
   vrf INET
      rd 10.255.0.21:50004
      neighbor ISP-A peer group
      neighbor ISP-A remote-as 64496
      neighbor ISP-A local-as 65021 no-prepend replace-as
      neighbor ISP-A ttl maximum-hops 1
      neighbor ISP-A route-map RM-IN in
      neighbor ISP-A route-map RM-OUT out
      neighbor ISP-A maximum-routes 1100000 warning-limit 90 percent
      neighbor ISP-A remove-private-as all replace-as
      neighbor 198.51.100.0 peer group ISP-A
      neighbor 2001:db8:ffff:a:: peer group ISP-A
      network 203.0.113.0/24
      aggregate-address 203.0.113.0/24 summary-only
      !
      address-family ipv4
         neighbor 198.51.100.0 activate
      !
      address-family ipv6
         neighbor 2001:db8:ffff:a:: activate
         network 2001:db8:203::/48
!
ip route vrf INET 203.0.113.80/28 Null0 tag 666 name RTBH
"""


@pytest.fixture(scope="module")
def ios() -> str:
    out, _ = convert(EOS, "eos", "ios")
    return out


@pytest.fixture(scope="module")
def report() -> Report:
    _, rep = convert(EOS, "eos", "ios")
    return rep


def _status(report: Report) -> Dict[str, str]:
    return {name: item.status for (_, name), item in report.items.items()}


def test_anycast_gateway_and_relay(ios: str, report: Report) -> None:
    assert ("interface Vlan100\n vrf forwarding PROD\n ip address 10.1.100.1 255.255.255.0\n"
            " ipv6 address 2001:db8:1:100::1/64\n mac-address 001c.7300.dc01\n"
            " ip helper-address vrf Mgmt-vrf 10.100.0.67\n ip dhcp relay source-interface Loopback100\n") in ios
    assert _status(report)["Vlan100 -> Vlan100"] == "approximated"
    eos = parse(EOS, "eos")
    assert convert(EOS, "eos", "eos")[0].count("ip address virtual 10.1.100.1/24") == 1
    assert eos.interfaces["Vlan100"].helper_addresses == ["10.100.0.67"]


def test_ranges_become_ports(ios: str) -> None:
    assert "Ethernet1/1-2/1" not in ios
    names = set(parse(EOS, "eos").interfaces)
    assert {"Ethernet1/1", "Ethernet2/1"} <= names


def test_ssh_in_a_vrf_stays_on(ios: str, report: Report) -> None:
    assert "line vty 0 15\n transport input ssh\n access-class ACL-MGMT-IN in vrf-also\n" in ios
    assert "line con 0\n login authentication console\n" in ios
    assert _status(report)["authentication login console"] == "exact"


def test_services(ios: str, report: Report) -> None:
    assert "ntp source GigabitEthernet0/0\n" in ios
    assert "logging host 10.100.0.50 vrf Mgmt-vrf\nlogging host 10.100.1.50 vrf Mgmt-vrf transport tls port 6514\n" \
        in ios
    assert "logging source-interface GigabitEthernet0/0 vrf Mgmt-vrf\n" in ios
    assert _status(report)["syslog servers"] == "needs-review"  # TLS needs a profile
    assert _status(report)["snmp traps"] == "approximated"
    assert "police cir 50000000 bc 1000000 conform-action transmit exceed-action drop" in ios


def test_interface_hardening_and_storm_control(ios: str) -> None:
    assert (" ip verify unicast source reachable-via rx\n no ip redirects\n no ip unreachables\n no ip proxy-arp\n"
            in ios)
    assert " storm-control broadcast level 2\n storm-control multicast level 2\n storm-control unicast level 2\n" \
        in ios


def test_route_maps_keep_their_clauses(ios: str, report: Report) -> None:
    assert "ip prefix-list PL-LOOPBACKS seq 10 permit 10.255.0.0/24 ge 32 le 32\n" in ios
    assert "ip community-list standard CL-BLACKHOLE permit 65535:666\n" in ios
    assert "ip as-path access-list 1 permit ^([0-9]+ ){50,}[0-9]+$\n" in ios
    assert "route-map RM-IN deny 5\n match rpki invalid\n" in ios
    assert "route-map RM-IN deny 30\n match as-path 1\n" in ios
    assert "route-map RM-OUT permit 20\n match community CL-BLACKHOLE\n set community 64496:666\n" in ios
    assert "set extcommunity rt 65021:400 additive\n" in ios and "set metric-type type-1\n" in ios
    # a clause that cannot be read takes its entry out, rather than leaving a deny that matches every route
    assert "\nroute-map RM-OUT deny 50\n" not in ios
    assert "! route-map RM-OUT deny 50 left out: match large-community LC-ANY not converted" in ios
    assert _status(report)["route-map RM-OUT"] == "needs-review"
    assert _status(report)["route-map RM-IN"] == "needs-review"  # the RPKI servers are not converted


def test_ospf(ios: str, report: Report) -> None:
    for line in ("distribute-list route-map RM-IN in", "redistribute bgp 65021 subnets route-map RM-TO-OSPF",
                 "timers throttle spf 50 200 5000", "timers lsa arrival 100",
                 "max-lsa 12000 75 ignore-time 5 ignore-count 5 reset-time 5", "nsf ietf"):
        assert f"\n {line}\n" in ios, line
    assert "key chain OSPF-GigabitEthernet1-0-4\n key 1\n  key-string CHANGE-ME\n" \
           "  cryptographic-algorithm hmac-sha-256\n" in ios
    assert " ip ospf authentication key-chain OSPF-GigabitEthernet1-0-4\n" in ios
    assert _status(report)["ospf 100 vrf PROD"] == "exact"


def test_bgp(ios: str, report: Report) -> None:
    for line in ("timers bgp 5 15", "bgp graceful-restart", "bgp graceful-restart restart-time 300",
                 "bgp bestpath as-path multipath-relax"):
        assert f"\n {line}\n" in ios, line
    assert "  distance bgp 20 200 200\n" in ios and "  maximum-paths 4\n" in ios
    inet4 = ios.split(" address-family ipv4 vrf INET\n")[1].split(" exit-address-family")[0]
    for line in ("network 203.0.113.0 mask 255.255.255.0", "aggregate-address 203.0.113.0 255.255.255.0 summary-only",
                 "neighbor 198.51.100.0 remote-as 64496", "neighbor 198.51.100.0 local-as 65021 no-prepend replace-as",
                 "neighbor 198.51.100.0 ttl-security hops 1", "neighbor 198.51.100.0 maximum-prefix 1100000 90",
                 "neighbor 198.51.100.0 remove-private-as all replace-as", "neighbor 198.51.100.0 route-map RM-IN in",
                 "neighbor 198.51.100.0 route-map RM-OUT out"):
        assert f"  {line}\n" in inet4, line
    assert "2001:db8" not in inet4
    inet6 = ios.split(" address-family ipv6 vrf INET\n")[1].split(" exit-address-family")[0]
    assert "  network 2001:db8:203::/48\n  neighbor 2001:db8:ffff:a:: remote-as 64496\n" in inet6
    assert "  neighbor 2001:db8:ffff:a:: activate\n" in inet6
    prod = ios.split(" address-family ipv4 vrf PROD\n")[1].split(" exit-address-family")[0]
    assert "  neighbor 10.255.251.1 remote-as 65021\n" in prod and "maximum-prefix 12000" in prod
    assert " address-family ipv6 vrf PROD\n  redistribute connected\n" in ios
    assert "vrf definition PROD\n rd 10.255.0.21:50001\n address-family ipv4\n" \
           "  route-target both 50001:50001 stitching\n  export map RM-EXPORT\n exit-address-family\n" \
           " address-family ipv6\n" in ios
    assert _status(report)["bgp vrf INET"] == "exact"
    assert "ip route vrf INET 203.0.113.80 255.255.255.240 Null0 tag 666 name RTBH" in ios


def test_nothing_partly_converted_is_exact() -> None:
    text = EOS + "interface Vlan200\n   vrf PROD\n   ip address 10.2.0.1/24\n   frobnicate on\n"
    _, rep = convert(text, "eos", "ios")
    item = rep.items[("interface", "Vlan200 -> Vlan200")]
    assert item.status == "needs-review"
    assert "frobnicate on" in item.findings[-1].message


@pytest.mark.parametrize("target", ["eos", "ios"])
def test_reads_back(target: str) -> None:
    out, _ = convert(EOS, "eos", target)
    back = parse(out, target)
    left = [u.text for u in back.unparsed]
    if target == "ios":  # the anycast MAC and the OSPF key chain have no place in the model yet
        left = [t for t in left if not t.startswith(("mac-address", "key", "cryptographic", "ip ospf authentication"))]
    assert left == []
    assert back.bgp is not None and back.bgp.vrfs["INET"].aggregates[0].summary_only
    assert sorted(n.address for n in back.bgp.vrfs["INET"].neighbors) == ["198.51.100.0", "2001:db8:ffff:a::"]


@pytest.mark.parametrize("target", ["aoscx", "comware", "nxos", "junos", "aoss"])
def test_other_targets_report_what_they_leave_out(target: str) -> None:
    out, rep = convert(EOS, "eos", target)
    text = rep.to_text()
    assert "anycast gateway 10.1.100.1/24" in text
    assert "community-list CL-BLACKHOLE: skipped" in text
    for (kind, name), item in rep.items.items():
        if kind == "interface" and name.startswith("Vlan100 ->"):
            assert item.status in ("needs-review", "skipped"), target


def test_pbr_policy_before_its_numbered_class() -> None:
    text = """\
ip access-list ACL-SCRUB
   10 permit ip any 203.0.113.80/28
policy-map type pbr PBR-SCRUBBER
   10 class CM-PBR-SCRUB
      set nexthop 10.255.200.1
class-map type pbr match-any CM-PBR-SCRUB
   10 match ip access-group ACL-SCRUB
interface Vlan300
   ip address 203.0.113.2/26
   service-policy type pbr input PBR-SCRUBBER
"""
    out, rep = convert(text, "eos", "ios")
    assert "route-map PBR-SCRUBBER permit 10\n match ip address ACL-SCRUB\n set ip next-hop 10.255.200.1\n" in out
    assert " ip policy route-map PBR-SCRUBBER\n" in out
    assert rep.items[("policy", "route-map PBR-SCRUBBER")].status == "exact"

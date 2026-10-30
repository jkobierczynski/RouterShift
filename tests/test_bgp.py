import pytest
from helpers import sample

from routershift import bgp as bgp_text
from routershift.convert import PLATFORMS, convert, parse

IOS = """\
hostname r1
interface Loopback0
 ip address 10.0.0.1 255.255.255.255
router ospf 1
 network 10.0.0.1 0.0.0.0 area 0
router bgp 65001
 bgp router-id 10.0.0.1
 bgp log-neighbor-changes
 neighbor SPINES peer-group
 neighbor SPINES remote-as 65000
 neighbor SPINES send-community both
 neighbor 10.1.0.1 peer-group SPINES
 neighbor 10.1.0.1 description spine-1
 neighbor 10.2.0.1 remote-as 65001
 neighbor 10.2.0.1 update-source Loopback0
 neighbor 10.2.0.1 password 7 0822455D0A16
 neighbor 10.3.0.1 remote-as 65100
 neighbor 10.3.0.1 ebgp-multihop 2
 neighbor 10.3.0.1 shutdown
 neighbor 2001:db8::1 remote-as 65000
 !
 address-family ipv4
  network 10.10.0.0 mask 255.255.255.0
  redistribute connected
  redistribute ospf 1 route-map O2B
  neighbor 10.2.0.1 next-hop-self
  no neighbor 2001:db8::1 activate
 exit-address-family
 !
 address-family ipv6
  network 2001:db8:10::/48
  neighbor 2001:db8::1 activate
 exit-address-family
"""


def test_ios_reader() -> None:
    device = parse(IOS, "ios")
    bgp = device.bgp
    assert bgp is not None
    assert (bgp.local_as, bgp.router_id, list(bgp.peer_groups)) == ("65001", "10.0.0.1", ["SPINES"])
    spines = bgp.peer_groups["SPINES"]
    assert (spines.remote_as, spines.send_community) == ("65000", True)
    peers = {n.address: n for n in bgp.neighbors}
    assert (peers["10.1.0.1"].peer_group, peers["10.1.0.1"].description) == ("SPINES", "spine-1")
    assert (peers["10.2.0.1"].update_source, peers["10.2.0.1"].next_hop_self) == ("Loopback0", True)
    assert (peers["10.3.0.1"].ebgp_multihop, peers["10.3.0.1"].shutdown) == (2, True)
    assert [n.families for n in bgp.neighbors] == [["ipv4"], ["ipv4"], ["ipv4"], ["ipv6"]]
    assert (bgp.networks, bgp.redistribute) == (["10.10.0.0/24", "2001:db8:10::/48"], ["connected"])
    assert [u.text for u in device.unparsed] == ["neighbor 10.2.0.1 password 7 0822455D0A16",
                                                 "redistribute ospf 1 route-map O2B"]


def test_password_is_masked() -> None:
    for target in sorted(PLATFORMS):
        _, report = convert(IOS, "ios", target)
        assert "0822455D0A16" not in report.to_text(), target


def test_eos_reader() -> None:
    bgp = parse(sample("eos_leaf.cfg"), "eos").bgp
    assert bgp is not None
    flat = {n.address: n for n in bgp_text.flat(bgp)}
    assert (flat["10.255.0.0"].remote_as, flat["10.255.0.0"].send_community) == ("65000", True)
    assert flat["10.255.255.9"].update_source == "Loopback0"


def test_default_ipv4_off() -> None:
    text = ("router bgp 1\n no bgp default ipv4-unicast\n neighbor 10.0.0.2 remote-as 2\n"
            " neighbor 10.0.0.3 remote-as 3\n address-family ipv4\n  neighbor 10.0.0.3 activate\n")
    bgp = parse(text, "ios").bgp
    assert bgp is not None and [n.families for n in bgp.neighbors] == [[], ["ipv4"]]


def test_aoscx_reader_and_writer() -> None:
    bgp = parse(sample("aoscx_access.cfg"), "aoscx").bgp
    assert bgp is not None
    [peer] = bgp.neighbors
    assert (peer.address, peer.remote_as, peer.families, bgp.networks) == (
        "10.99.0.1", "65000", ["ipv4"], ["10.10.0.0/24"])
    out, report = convert(IOS, "ios", "aoscx")
    assert "    neighbor 10.1.0.1 remote-as 65000\n" in out  # from its peer group
    assert "    neighbor 10.2.0.1 update-source loopback 0\n" in out
    assert "    address-family ipv6 unicast\n        neighbor 2001:db8::1 activate\n" in out
    assert "peer groups SPINES written out on each member" in report.to_text()


def test_comware_reader_and_writer() -> None:
    bgp = parse(sample("comware_access.cfg"), "comware").bgp
    assert bgp is not None
    [peer] = bgp.neighbors
    assert (peer.remote_as, peer.ebgp_multihop, peer.families, bgp.redistribute) == (
        "65000", 2, ["ipv4"], ["static"])
    text = ("bgp 65001\n group IBGP internal\n peer 10.0.0.2 group IBGP\n peer 10.0.0.2 connect-interface LoopBack0\n"
            " address-family ipv4 unicast\n  peer IBGP next-hop-local\n  peer 10.0.0.2 enable\n#\n")
    device = parse(text, "comware")
    assert device.bgp is not None and device.unparsed == []
    [peer] = bgp_text.flat(device.bgp)
    assert (peer.remote_as, peer.update_source, peer.next_hop_self) == ("65001", "Loopback0", True)
    out, _ = convert(IOS, "ios", "comware")
    assert " group SPINES external\n peer SPINES as-number 65000\n" in out
    assert " peer 10.2.0.1 connect-interface LoopBack0\n" in out
    assert "  network 10.10.0.0 255.255.255.0\n" in out and "  network 2001:db8:10:: 48\n" in out


def test_aoss_leaves_bgp_to_a_person() -> None:
    out, report = convert(IOS, "ios", "aoss")
    assert "bgp" not in out
    assert "bgp 65001: skipped" in report.to_text()


@pytest.mark.parametrize("target", sorted(set(PLATFORMS) - {"aoss"}))
def test_every_writer_round_trips(target: str) -> None:
    first = parse(IOS, "ios")
    out, _ = convert(IOS, "ios", target)
    back = parse(out, target)
    assert first.bgp is not None and back.bgp is not None
    assert bgp_text.flat(back.bgp) == bgp_text.flat(first.bgp), target
    assert (back.bgp.networks, back.bgp.redistribute) == (first.bgp.networks, first.bgp.redistribute)
    assert [u.text for u in back.unparsed] == [], target

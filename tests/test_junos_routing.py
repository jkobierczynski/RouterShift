"""Junos routing tuning: BFD timers per session, the ECMP hash, OSPF authentication and options, static route tags
and policy-based routing as filter-based forwarding, written and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def _timers(d):
    return sorted((i.bfd_interval, i.bfd_min_rx, i.bfd_multiplier) for i in d.interfaces.values() if i.bfd_interval)


def test_border_leaf_bfd() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert _timers(back) == _timers(first)  # each port's timers ride on the OSPF and BGP sessions over it
    assert back.bfd_multihop == first.bfd_multihop
    assert "minimum-interval 100;" in out and "multiplier 3;" in out
    assert back.ospf[0].bfd_all and first.ospf[0].bfd_all
    assert "no BFD slow timer (2000 ms)" in report.to_text()


def test_border_leaf_ecmp_and_tag() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert back.ecmp_hash == first.ecmp_hash
    assert "enhanced-hash-key {" in out and "no-incoming-port;" in out
    assert [(r.prefix, r.tag) for r in back.static_routes if r.tag] == \
        [(r.prefix, r.tag) for r in first.static_routes if r.tag]
    assert report.items[("route", "DMZ 203.0.113.80/28")].status == "approximated"  # only the route's name


def test_border_leaf_ospf() -> None:
    first, out, report, back = _back(EOS, "eos")
    p, q = first.ospf[0], back.ospf[0]
    assert (q.distribute_list_in, q.max_lsa, q.graceful_restart) == (p.distribute_list_in, p.max_lsa,
                                                                     p.graceful_restart)
    assert q.spf_timers is not None and p.spf_timers is not None
    assert (q.spf_timers[0], q.spf_timers[2]) == (p.spf_timers[0], p.spf_timers[2])
    assert "ignore-time 300;" in out and "import RM-OSPF-LEGACY-IN;" in out
    auth = [(i.ospf_auth, list(i.ospf_keys)) for i in back.interfaces.values() if i.ospf_auth]
    assert auth == [(i.ospf_auth, list(i.ospf_keys)) for i in first.interfaces.values() if i.ospf_auth]
    assert 'md5 1 key "CHANGE-ME";' in out or "md5 1 key CHANGE-ME;" in out
    text = report.to_text()
    assert "the sha256 keys are written as MD5 keys" in text and "no separate hold time (200 ms)" in text


def test_pbr_as_filter_based_forwarding() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "routing-instance PBR-SCRUBBER-10;" in out and "instance-type forwarding;" in out
    assert "import-rib [ DMZ.inet.0 PBR-SCRUBBER-10.inet.0 ];" in out
    a, b = first.route_maps["PBR-SCRUBBER"].entries[0], back.route_maps["PBR-SCRUBBER"].entries[0]
    assert (b.match_acls, b.sets) == (a.match_acls, a.sets)
    assert back.interfaces["Vlan300"].pbr == "PBR-SCRUBBER" and not back.interfaces["Vlan300"].acl_in
    assert "PBR-SCRUBBER-10" not in back.vrfs


def test_graceful_restart_per_protocol() -> None:
    text = """\
router ospf 1
 graceful-restart
 network 10.0.0.0 0.0.0.255 area 0
!
router bgp 65000
 neighbor 10.0.0.2 remote-as 65001
!
interface GigabitEthernet0/1
 no switchport
 ip address 10.0.0.1 255.255.255.0
!
"""
    first, out, report, back = _back(text, "ios")
    assert "disable;" in out
    assert back.ospf[0].graceful_restart and back.bgp is not None and not back.bgp.graceful_restart

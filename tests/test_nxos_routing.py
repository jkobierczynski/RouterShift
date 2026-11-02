"""NX-OS routing tuning: OSPF authentication and options, BFD, the ECMP hash, RIP, IS-IS, MPLS, GRE, PBR."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")
IOS = sample("ios_access.cfg")
NXOS = """\
feature ospf
feature bfd
feature rip
feature isis
feature pbr
feature tunnel
install feature-set mpls
feature-set mpls
feature mpls ldp
ip load-sharing address source-destination port source-destination
bfd multihop interval 300 min_rx 300 multiplier 3
bfd slow-timer 2000
key chain OSPF-Ethernet1-2
  key 1
    key-string 0 CHANGE-ME
    cryptographic-algorithm HMAC-SHA-256
ip access-list SCRUB
  10 permit ip 10.9.0.0/16 any
route-map PBR-SCRUB permit 10
  match ip address SCRUB
  set ip next-hop 10.255.200.1
route-map RS-PERMIT-ALL permit 10
mpls ldp configuration
  router-id loopback0 force
router ospf 1
  router-id 10.255.0.1
  bfd
  table-map FILTER-IN filter
  timers throttle spf 50 100 5000
  timers lsa-arrival 80
  max-lsa 8000
  graceful-restart
  log-adjacency-changes detail
route-map FILTER-IN permit 10
router rip RIP
  address-family ipv4 unicast
    redistribute static route-map RS-PERMIT-ALL
    default-metric 3
    default-information originate
router isis CORE
  net 49.0001.0000.0000.0001.00
  is-type level-2
  address-family ipv4 unicast
    redistribute direct route-map RS-PERMIT-ALL
interface loopback0
  ip address 10.255.0.1/32
  ip router ospf 1 area 0.0.0.0
  ip router isis CORE
  isis passive-interface level-1-2
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/30
  ip router ospf 1 area 0.0.0.0
  ip ospf authentication message-digest
  ip ospf message-digest-key 1 md5 0 CHANGE-ME
  ip ospf bfd
  bfd interval 250 min_rx 250 multiplier 3
  ip router isis CORE
  isis metric 20 level-2
  isis network point-to-point
  mpls ip
interface Ethernet1/2
  no switchport
  ip address 10.0.1.1/30
  ip router ospf 1 area 0.0.0.0
  ip ospf authentication key-chain OSPF-Ethernet1-2
interface Ethernet1/3
  no switchport
  ip address 192.168.10.1/24
  ip router rip RIP
  ip rip passive-interface
  ip policy route-map PBR-SCRUB
interface Tunnel1
  ip address 172.16.0.1/30
  tunnel source loopback0
  tunnel destination 198.51.100.9
  tunnel mode gre ip
"""


def _findings(report, code):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_reads_nxos_routing() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    p = d.ospf[0]
    assert (p.bfd_all, p.distribute_list_in, p.spf_timers, p.lsa_arrival, p.max_lsa, p.graceful_restart,
            p.log_adjacency) == (True, "FILTER-IN", (50, 100, 5000), 80, "8000", True, "detail")
    e1, e2 = d.interfaces["Ethernet1/1"], d.interfaces["Ethernet1/2"]
    assert (e1.ospf_auth, e1.ospf_keys, e1.ospf_bfd) == ("message-digest", {1: "md5"}, True)
    assert (e1.bfd_interval, e1.bfd_min_rx, e1.bfd_multiplier) == (250, 250, 3)
    assert (e2.ospf_auth, e2.ospf_keys) == ("message-digest", {1: "sha256"})
    assert d.bfd_multihop == (300, 300, 3) and d.bfd_slow_timer == 2000
    assert d.ecmp_hash == ["source-ip", "destination-ip", "source-port", "destination-port"]
    rip = d.rip
    assert rip.networks == ["192.168.10.0/24"] and rip.passive_interfaces == ["Ethernet1/3"]
    assert (rip.redistribute, rip.redistribute_maps, rip.default_metric, rip.default_originate) == \
        (["static"], {}, 3, True)
    isis = d.isis
    assert (isis.tag, isis.nets, isis.level, isis.redistribute) == \
        ("CORE", ["49.0001.0000.0000.0001.00"], "level-2", ["connected"])
    assert d.interfaces["Loopback0"].isis_passive and (e1.isis, e1.isis_metric, e1.isis_network) == \
        (True, 20, "point-to-point")
    assert d.mpls.ldp and d.mpls.router_id_interface == "Loopback0" and e1.mpls
    assert d.interfaces["Ethernet1/3"].pbr == "PBR-SCRUB"
    t = d.interfaces["Tunnel1"]
    assert (t.tunnel_source, t.tunnel_destination, t.tunnel_mode) == ("Loopback0", "198.51.100.9", "gre")


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, report = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []

    def plain(v):
        return {k: x for k, x in vars(v).items() if k != "origin"}
    assert [plain(p) for p in back.ospf] == [plain(p) for p in first.ospf]
    assert plain(back.rip) == plain(first.rip) and plain(back.isis) == plain(first.isis)
    assert plain(back.mpls) == plain(first.mpls)
    assert (back.bfd_multihop, back.bfd_slow_timer, back.ecmp_hash) == \
        (first.bfd_multihop, first.bfd_slow_timer, first.ecmp_hash)
    for name, a in first.interfaces.items():
        b = back.interfaces[name]
        assert {k: v for k, v in plain(a).items() if k != "source_name"} == \
            {k: v for k, v in plain(b).items() if k != "source_name"}, name
    assert "not written for NX-OS yet" not in report.to_text()


def test_from_eos() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "feature bfd\n" in out and "ip load-sharing address source-destination port source-destination\n" in out
    assert back.bfd_multihop == first.bfd_multihop and back.ecmp_hash == first.ecmp_hash
    a, b = first.ospf[0], back.ospf[0]
    assert (b.distribute_list_in, b.spf_timers, b.lsa_arrival, b.max_lsa, b.graceful_restart) == \
        (a.distribute_list_in, a.spf_timers, a.lsa_arrival, a.max_lsa, a.graceful_restart)
    assert sorted(i.ospf_auth for i in back.interfaces.values() if i.ospf_auth) == \
        sorted(i.ospf_auth for i in first.interfaces.values() if i.ospf_auth)
    assert _findings(report, "ecmp-platform")


def test_from_ios_rip_mpls_tunnel() -> None:
    first = parse(IOS, "ios")
    out, report = convert(IOS, "ios", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert out.startswith("install feature-set mpls\nfeature-set mpls\n")
    assert "router rip RIP\n" in out and back.rip is not None and back.rip.networks
    assert [n for n, i in back.interfaces.items() if i.mpls] == [n for n, i in first.interfaces.items() if i.mpls]
    assert _findings(report, "rip-networks") and _findings(report, "vpn-unsupported")
    assert "not written for NX-OS yet" not in report.to_text()

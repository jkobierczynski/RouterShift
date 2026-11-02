"""AOS-CX routing tuning: OSPF authentication and timers, GRE tunnels and policy-based routing, written and read
back; BFD and ECMP globals, RIP, IS-IS and IPsec tunnels are reported."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "aoscx")
    back = parse(out, "aoscx")
    assert [u.text for u in back.unparsed] == []
    return first, out, report, back


def test_ospf_authentication_and_timers() -> None:
    first, out, report, back = _back(EOS, "eos")
    authed = {n: i for n, i in first.interfaces.items() if i.ospf_auth}
    assert authed and "ip ospf authentication message-digest\n" in out
    assert "ip ospf message-digest-key 1 md5 plaintext CHANGE-ME" in out
    got = [i for i in back.interfaces.values() if i.ospf_auth]
    assert sorted(i.ospf_auth for i in got) == sorted(i.ospf_auth for i in authed.values())
    assert _findings(report, "secret-placeholder")
    ios = ("hostname r\nrouter ospf 1\n timers throttle spf 50 200 5000\n timers lsa arrival 100\n nsf ietf\n"
           " network 10.0.0.0 0.0.0.255 area 0\ninterface Vlan10\n ip address 10.0.0.1 255.255.255.0\n"
           " ip ospf authentication\n")
    first, out, report, back = _back(ios, "ios")
    assert "timers throttle spf start-time 50 hold-time 200 max-wait-time 5000\n" in out
    p, q = first.ospf[0], back.ospf[0]
    assert (q.spf_timers, q.lsa_arrival, q.graceful_restart) == (p.spf_timers, p.lsa_arrival, p.graceful_restart)
    assert back.interfaces["Vlan10"].ospf_auth == "simple"


def test_gre_tunnel() -> None:
    ios = ("hostname r\ninterface Loopback0\n ip address 10.255.0.1 255.255.255.255\ninterface Tunnel5\n"
           " ip address 172.16.5.1 255.255.255.252\n tunnel source Loopback0\n tunnel destination 198.51.100.7\n")
    first, out, report, back = _back(ios, "ios")
    assert "interface tunnel 5\n    tunnel mode gre ipv4\n    source ip 10.255.0.1\n" \
           "    destination ip 198.51.100.7\n" in out
    t = back.interfaces["Tunnel5"]
    assert (t.tunnel_mode, t.tunnel_source, t.tunnel_destination, t.ipv4) == \
        ("gre", "10.255.0.1", "198.51.100.7", ["172.16.5.1/30"])
    assert _findings(report, "tunnel-source")


def test_ipsec_tunnel_left_out() -> None:
    out, report = convert(sample("ios_vpn.cfg"), "ios", "aoscx")
    assert "interface tunnel" not in out
    assert any("IPsec tunnel interface" in m for m in _findings(report, "tunnel"))


def test_policy_based_routing() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "pbr-action-list PBR-SCRUBBER-10\n    10 nexthop 10.255.200.1\n" in out
    assert "policy PBR-SCRUBBER\n    10 class ip PBR-SCRUBBER-10 action pbr PBR-SCRUBBER-10\n" in out
    assert "    apply policy PBR-SCRUBBER routed-in\n" in out
    assert back.interfaces["Vlan300"].pbr == "PBR-SCRUBBER"
    rm, got = first.route_maps["PBR-SCRUBBER"], back.route_maps["PBR-SCRUBBER"]
    assert [(e.seq, e.match_acls, e.sets) for e in got.entries] == \
        [(e.seq, e.match_acls, e.sets) for e in rm.entries if e.action.value == "permit"]
    assert "PBR-SCRUBBER-10" not in back.qos_classes and "PBR-SCRUBBER" not in back.qos_policies


def test_reported_limits() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert _findings(report, "bfd-global") and _findings(report, "ecmp-hash")
    out, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert any("AOS-CX has no RIP" in m for m in _findings(report, "rip-unsupported"))
    assert any("AOS-CX has no IS-IS" in m for m in _findings(report, "isis-unsupported"))

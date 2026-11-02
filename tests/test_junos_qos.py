"""Junos class of service: the DSCP maps, queuing profiles and a port's own queue settings, port trust, and QoS
policies as filters with policers, written and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def test_border_leaf_maps_and_profiles() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert back.qos_dscp_tc == first.qos_dscp_tc and back.qos_tc_dscp == first.qos_tc_dscp
    assert "code-points [ 100010 100100 100110 ];" in out and "dscp RS-DSCP-REWRITE {" in out
    assert set(back.qos_profiles) == set(first.qos_profiles)
    for name, profile in first.qos_profiles.items():
        got = back.qos_profiles[name]
        assert (got.trust, got.queues, got.shape_kbps) == (profile.trust, profile.queues, profile.shape_kbps), name
    ports = lambda d: sorted(repr((i.qos_profile, i.qos_trust, i.queues)) for i in d.interfaces.values()  # noqa: E731
                             if i.qos_profile or i.qos_trust or i.queues)
    for i in first.interfaces.values():
        for q in i.queues.values():
            q.ecn = (0, 0, 0) if q.ecn else None  # Junos takes the thresholds from its drop profile
    assert ports(back) == ports(first)
    assert "scheduler-map QP-FABRIC-P1;" in out  # the uplinks' own ECN setting on top of QP-FABRIC
    assert "forwarding-class TC0;" in out  # the peer link trusts nothing
    text = report.to_text()
    assert "thresholds (500-1500 kbytes, 20%) are left to" in text


def test_border_leaf_policy() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert back.qos_policies["PM-ACCESS-IN"].actions == first.qos_policies["PM-ACCESS-IN"].actions
    assert back.qos_classes["CM-VOICE"].acl == "ACL-QOS-VOICE"  # the filter's terms match that ACL's entries
    assert "family ethernet-switching {" in out and "ip-protocol udp;" in out
    assert "if-exceeding {" in out and "bandwidth-limit 50m;" in out and "burst-size-limit 1000000;" in out
    assert back.interfaces["Port-channel20"].qos_policy_in == "PM-ACCESS-IN"
    assert report.items[("qos", "class CM-SCRUB")].status == "approximated"  # used by no policy
    assert report.items[("qos", "policy PM-ACCESS-IN")].status == "approximated"  # marking in a filter


def test_access_switch_policy() -> None:
    first, out, report, back = _back(sample("ios_access.cfg"), "ios")
    policy = first.qos_policies["EDGE-IN"]
    assert [(a.qos_class, a.set_dscp, a.police_kbps) for a in back.qos_policies["EDGE-IN"].actions] == \
        [(a.qos_class, a.set_dscp, a.police_kbps) for a in policy.actions]
    assert back.qos_classes["VOICE"].dscp == first.qos_classes["VOICE"].dscp
    assert "dscp [ ef cs5 ];" in out
    assert report.items[("qos", "policy EDGE-IN")].status == "approximated"  # the policer's burst is made up


def test_reads_native_junos_cos() -> None:
    text = """\
set class-of-service forwarding-classes class expedited-forwarding queue-num 5
set class-of-service forwarding-classes class best-effort queue-num 0
set class-of-service classifiers dscp CL forwarding-class expedited-forwarding loss-priority low code-points ef
set class-of-service schedulers S-EF priority strict-high
set class-of-service schedulers S-EF shaping-rate 100m
set class-of-service schedulers S-BE transmit-rate percent 60
set class-of-service scheduler-maps SM forwarding-class expedited-forwarding scheduler S-EF
set class-of-service scheduler-maps SM forwarding-class best-effort scheduler S-BE
set class-of-service interfaces ge-0/0/1 scheduler-map SM
set class-of-service interfaces ge-0/0/1 unit 0 classifiers dscp CL
set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/30
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    assert d.qos_dscp_tc == {46: 5}
    sm = d.qos_profiles["SM"]
    assert sm.trust == "dscp" and sm.queues[5].priority and sm.queues[5].shape_kbps == 100000
    assert sm.queues[0].bandwidth_percent == 60
    assert d.interfaces["Ethernet0/0/1"].qos_profile == "SM"

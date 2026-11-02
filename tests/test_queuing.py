"""QoS queuing: the DSCP to traffic-class map, EOS qos profiles with their tx-queues (priority, bandwidth, shaping,
ECN), and IOS output queuing policies (priority level, bandwidth remaining, a parent shaper), both ways."""

from routershift.convert import convert, parse

EOS = """\
hostname bl1
qos map dscp 46 to traffic-class 5
qos map dscp 34 36 38 to traffic-class 4
qos map traffic-class 5 to dscp 46
qos profile QP-FABRIC
   qos trust dscp
   tx-queue 5
      priority strict
      shape rate 20 percent
   tx-queue 4
      no priority
      bandwidth percent 30
   tx-queue 0
      no priority
      bandwidth percent 10
interface Ethernet1/1
   no switchport
   ip address 10.0.1.1/31
   service-profile QP-FABRIC
interface Ethernet1/1
   tx-queue 4
      random-detect ecn minimum-threshold 500 kbytes maximum-threshold 1500 kbytes max-mark-probability 20
"""

IOS = """\
hostname wan
class-map match-any CM-VOICE
 match dscp ef
class-map match-any CM-VIDEO
 match dscp af41
class-map match-any CM-BULK
 match dscp af11
policy-map PM-CHILD
 class CM-VOICE
  priority level 1 percent 15
 class CM-VIDEO
  priority level 2 percent 20
 class CM-BULK
  bandwidth remaining percent 10
  random-detect dscp-based
 class class-default
  bandwidth remaining percent 50
  fair-queue
policy-map PM-SHAPER
 class class-default
  shape average 500000000
   service-policy PM-CHILD
interface GigabitEthernet0/0/1
 ip address 192.0.2.1 255.255.255.252
 service-policy output PM-SHAPER
"""


def test_eos_reads_map_profiles_and_port_queues() -> None:
    d = parse(EOS, "eos")
    assert d.qos_dscp_tc == {46: 5, 34: 4, 36: 4, 38: 4} and d.qos_tc_dscp == {5: 46}
    p = d.qos_profiles["QP-FABRIC"]
    assert p.trust == "dscp" and p.queues[5].priority and p.queues[5].shape_percent == 20
    assert p.queues[4].bandwidth_percent == 30 and not p.queues[4].priority
    port = d.interfaces["Ethernet1/1"]
    assert port.qos_profile == "QP-FABRIC" and port.queues[4].ecn == (500, 1500, 20)
    assert d.unparsed == []
    out, _ = convert(EOS, "eos", "eos")
    assert "qos map dscp 34 36 38 to traffic-class 4\n" in out and "qos map traffic-class 5 to dscp 46\n" in out
    assert "qos profile QP-FABRIC\n   qos trust dscp\n   tx-queue 5\n      priority strict\n" \
        "      shape rate 20 percent\n" in out
    assert "   service-profile QP-FABRIC\n" in out
    assert "   tx-queue 4\n      random-detect ecn minimum-threshold 500 kbytes maximum-threshold 1500 kbytes " \
        "max-mark-probability 20\n" in out
    assert parse(out, "eos").unparsed == []


def test_eos_to_ios_and_back() -> None:
    out, report = convert(EOS, "eos", "ios")
    assert "class-map match-any RS-TC5\n match dscp ef\n" in out
    assert "class-map match-any RS-TC4\n match dscp af41 af42 af43\n" in out
    assert "policy-map QP-FABRIC\n class RS-TC5\n  priority level 1\n  police rate percent 20\n" \
        " class RS-TC4\n  bandwidth remaining percent 30\n class class-default\n  bandwidth remaining percent 10\n" in out
    assert " service-policy output QP-FABRIC\n" in out
    text = report.to_text()
    assert "IOS has no DSCP to traffic-class map" in text and "the rewrite of traffic classes to DSCP" in text
    assert "queue settings of this port on top of its profile (traffic class 4 ECN) are not written" in text
    back = parse(out, "ios")
    assert back.unparsed == []
    assert back.interfaces["Ethernet1/0/1"].qos_profile == "QP-FABRIC"
    q = back.qos_profiles["QP-FABRIC"].queues
    assert q[5].priority and q[5].shape_percent == 20 and q[4].bandwidth_remaining == 30
    assert back.qos_dscp_tc[46] == 5


def test_ios_queuing_policy_to_eos() -> None:
    d = parse(IOS, "ios")
    assert d.unparsed == []
    p = d.qos_profiles["PM-SHAPER"]
    assert "PM-CHILD" not in d.qos_profiles and p.shape_kbps == 500000
    assert d.interfaces["Ethernet0/0/1"].qos_profile == "PM-SHAPER"
    assert p.queues[7].priority and p.queues[7].priority_percent == 15 and p.queues[6].priority_level == 2
    assert p.queues[5].bandwidth_remaining == 10 and p.queues[5].wred and p.queues[0].fair_queue
    assert d.qos_dscp_tc == {46: 7, 34: 6, 10: 5}
    out, report = convert(IOS, "ios", "eos")
    assert "qos map dscp 46 to traffic-class 7\n" in out
    assert "qos profile PM-SHAPER\n   shape rate 500000 kbps\n   tx-queue 7\n      priority strict\n" \
        "      shape rate 15 percent\n" in out
    assert "   service-profile PM-SHAPER\n" in out
    text = report.to_text()
    assert "WRED without thresholds is not written" in text and "fair-queue left out" in text
    out, _ = convert(IOS, "ios", "ios")
    assert "policy-map PM-SHAPER-CHILD\n" in out and " service-policy output PM-SHAPER\n" in out
    assert parse(out, "ios").qos_profiles["PM-SHAPER"].shape_kbps == 500000

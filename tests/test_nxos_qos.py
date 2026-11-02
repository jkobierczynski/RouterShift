"""NX-OS QoS: classification and policing, the DSCP map, queuing policies (also per port), CoPP."""

from helpers import sample

from routershift.convert import convert, parse
from routershift.names import PortMapper

EOS = sample("eos_border_leaf.cfg")
NXOS = """\
ip access-list VOICE-ACL
  10 permit udp any any range 16384 32767
class-map type qos match-any VOICE
  match dscp 46
  match access-group name VOICE-ACL
class-map type qos match-any VIDEO
  match dscp 34,36
policy-map type qos MARK-IN
  class VOICE
    set dscp 46
    police cir 2000 kbps bc 25000 bytes conform transmit violate drop
  class class-default
    set dscp 0
class-map type qos match-any RS-TC5
  match dscp 46
class-map type qos match-any RS-TC3
  match dscp 26,34
policy-map type qos RS-DSCP-MAP
  class RS-TC5
    set qos-group 5
  class RS-TC3
    set qos-group 3
policy-map type queuing QP-FABRIC
  class type queuing c-out-8q-q7
    priority level 1
  class type queuing c-out-8q-q5
    bandwidth remaining percent 40
    random-detect minimum-threshold 150 kbytes maximum-threshold 3000 kbytes drop-probability 7 weight 0 ecn
  class type queuing c-out-8q-q-default
    bandwidth remaining percent 60
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/31
  service-policy type qos input RS-DSCP-MAP
  service-policy type queuing output QP-FABRIC
interface Ethernet1/2
  service-policy type qos input MARK-IN
"""


def _findings(report, code):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_reads_nxos_qos() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    assert d.qos_classes["VIDEO"].dscp == [34, 36] and d.qos_classes["VOICE"].acl == "VOICE-ACL"
    assert "RS-TC5" not in d.qos_classes and "RS-DSCP-MAP" not in d.qos_policies
    assert d.qos_dscp_tc == {26: 3, 34: 3, 46: 5}
    voice = d.qos_policies["MARK-IN"].actions[0]
    assert (voice.set_dscp, voice.police_kbps, voice.burst_bytes) == (46, 2000, 25000)
    q = d.qos_profiles["QP-FABRIC"].queues
    assert q[7].priority and q[5].bandwidth_remaining == 40 and q[5].ecn == (150, 3000, 7)
    assert q[0].bandwidth_remaining == 60
    e1 = d.interfaces["Ethernet1/1"]
    assert e1.qos_profile == "QP-FABRIC" and e1.qos_policy_in == ""
    assert d.interfaces["Ethernet1/2"].qos_policy_in == "MARK-IN"


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, _ = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert back.qos_dscp_tc == first.qos_dscp_tc
    for attr in ("qos_classes", "qos_policies", "qos_profiles"):
        def plain(d):
            return {k: {f: x for f, x in vars(v).items() if f != "origin"} for k, v in getattr(d, attr).items()}
        assert plain(back) == plain(first), attr
    for name in ("Ethernet1/1", "Ethernet1/2"):
        a, b = first.interfaces[name], back.interfaces[name]
        assert (a.qos_profile, a.qos_policy_in, a.queues) == (b.qos_profile, b.qos_policy_in, b.queues), name


def test_from_eos() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "policy-map type queuing QP-FABRIC\n" in out and "  class type queuing c-out-8q-q7\n    priority level 1\n" in out
    assert "policy-map type queuing QP-FABRIC-P1\n" in out and "copp profile strict\n" in out
    assert "    police cir 50000 kbps bc 1000000 bytes conform transmit violate drop\n" in out
    assert back.qos_dscp_tc == first.qos_dscp_tc
    assert set(back.qos_profiles) == set(first.qos_profiles)
    ports = PortMapper(first, "nxos")
    by_name = {n.lower(): i for n, i in back.interfaces.items()}
    for name, iface in first.interfaces.items():
        if iface.qos_profile:
            assert by_name[ports(name).lower()].qos_profile == iface.qos_profile, name
    ports = [i for i in back.interfaces.values() if i.queues]
    assert ports and all(i.queues[3].ecn for i in ports)
    assert back.qos_policies["PM-ACCESS-IN"].actions[0].police_kbps == 50000
    assert _findings(report, "qos-map") and _findings(report, "copp")
    text = report.to_text()
    assert "QoS is not written" not in text and "queuing profiles not written" not in text

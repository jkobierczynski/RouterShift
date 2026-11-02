"""AOS-CX egress queuing: the DSCP map, schedule profiles and the ports that apply them, written and read back."""

from helpers import sample

from routershift.convert import convert, parse
from routershift.names import PortMapper
from routershift.parsers.aoscx import canonical

EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_map_and_profiles() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "aoscx")
    assert "qos dscp-map 46 local-priority 5\n" in out
    assert "qos schedule-profile QP-EDGE\n    strict queue 5\n    dwrr queue 0 weight 50\n" in out
    back = parse(out, "aoscx")
    assert back.unparsed == []
    assert back.qos_dscp_tc == first.qos_dscp_tc
    for name, p in first.qos_profiles.items():
        got = back.qos_profiles[name]
        assert got.trust == p.trust, name
        assert {tc: (q.priority, q.bandwidth_percent) for tc, q in got.queues.items()} == \
            {tc: (q.priority, q.bandwidth_percent) for tc, q in p.queues.items()}, name
    ports = PortMapper(first, "aoscx")
    for name, iface in first.interfaces.items():
        if iface.qos_profile:
            assert back.interfaces[canonical(ports(name))[0]].qos_profile == iface.qos_profile, name
    assert any("shaping to 20 percent" in m for m in _findings(report, "qos-queue-options"))
    assert any("queues 1" in m for m in _findings(report, "qos-queues"))
    assert any("ecn" in m for m in _findings(report, "qos-port-queues"))
    assert _findings(report, "qos-rewrite")
    assert not any("queuing profile" in m for m in _findings(report, "not-written"))


def test_port_queues_of_their_own() -> None:
    eos = ("hostname s\nqos profile QP\n   qos trust dscp\n   tx-queue 5\n      priority strict\n   tx-queue 0\n"
           "      no priority\n      bandwidth percent 50\n!\ninterface Ethernet1\n   service-profile QP\n   tx-queue 0\n"
           "      bandwidth percent 70\n!\ninterface Ethernet2\n   service-profile QP\n!\n")
    first = parse(eos, "eos")
    out, report = convert(eos, "eos", "aoscx")
    assert "qos schedule-profile QP-P1\n    strict queue 5\n    dwrr queue 0 weight 70\n" in out
    assert "    apply qos schedule-profile QP-P1\n    qos trust dscp\n" in out
    back = parse(out, "aoscx")
    assert back.unparsed == [] and set(back.qos_profiles) == {"QP"}
    ports = PortMapper(first, "aoscx")
    e1 = back.interfaces[canonical(ports("Ethernet1"))[0]]
    assert e1.qos_profile == "QP" and e1.queues[0].bandwidth_percent == 70
    assert back.qos_profiles["QP"].trust == "dscp"

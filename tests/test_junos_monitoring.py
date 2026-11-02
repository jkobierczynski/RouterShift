"""Junos monitoring: sFlow, inline J-Flow, analyzers, LLDP timers, the TWAMP reflector, RPM probes and VRRP interface
tracking, written and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")
IOS = sample("ios_access.cfg")


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def test_border_leaf_monitoring() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert first.sflow is not None and back.sflow is not None
    assert (back.sflow.sample_rate, back.sflow.polling_interval) == (first.sflow.sample_rate,
                                                                     first.sflow.polling_interval)
    assert back.sflow.source_interface == "Management0"  # me0, the management port
    assert [c.address for c in back.sflow.collectors] == ["10.100.0.70"]
    assert sum(i.sflow for i in back.interfaces.values()) == sum(i.sflow for i in first.interfaces.values())
    assert "sample-rate {" in out and "ingress 16384;" in out
    session = back.mirror_sessions[0]
    assert (session.name, list(session.sources.values()), session.acl) == ("SPAN-DMZ", ["rx"], "")
    assert report.items[("monitor", "mirror session SPAN-DMZ")].status == "needs-review"  # its ACL
    m, src = back.management, first.management
    assert (m.lldp_timer, m.lldp_holdtime, m.lldp_mgmt_interface) == (src.lldp_timer, src.lldp_holdtime,
                                                                      "Management0")
    assert "hold-multiplier 4;" in out
    assert (back.twamp_port, back.twamp_mode) == (862, "light")


def test_access_switch_flows_and_probes() -> None:
    first, out, report, back = _back(IOS, "ios")
    assert first.netflow is not None and back.netflow is not None
    assert [(c.address, c.port) for c in back.netflow.collectors] == [(c.address, c.port)
                                                                      for c in first.netflow.collectors]
    assert back.netflow.version == 9 and back.netflow.source_interface == first.netflow.source_interface
    assert sorted(i.flow for i in back.interfaces.values() if i.flow) == \
        sorted(i.flow for i in first.interfaces.values() if i.flow)
    assert "sampling-instance RS-SAMPLING;" in out
    assert report.items[("monitor", "netflow")].status != "exact"  # J-Flow, not NetFlow on a switch
    sla, src = back.ip_slas["10"], first.ip_slas["10"]
    assert (sla.target, sla.frequency, sla.source_interface) == (src.target, src.frequency, src.source_interface)
    # the tracked interface lives on in the VRRP group; the probe's track is reported
    vrrp = next(g for i in back.interfaces.values() for g in i.fhrp)
    assert list(vrrp.tracks.values()) == [10] and list(back.tracks.values())[0].interface
    assert report.items[("track", "track 1")].status == "needs-review"


def test_reads_native_junos_monitoring() -> None:
    text = """\
set interfaces ge-0/0/1 unit 0 family inet address 192.0.2.1/30
set interfaces ge-0/0/2 unit 0 family ethernet-switching
set protocols sflow sample-rate ingress 2048
set protocols sflow collector 198.51.100.5 udp-port 6400
set protocols sflow interfaces ge-0/0/1
set forwarding-options analyzer A1 input ingress interface ge-0/0/1.0
set forwarding-options analyzer A1 input egress interface ge-0/0/1.0
set forwarding-options analyzer A1 output interface ge-0/0/2.0
set protocols lldp advertisement-interval 10
set protocols lldp hold-multiplier 3
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    assert d.sflow is not None and d.sflow.sample_rate == 2048 and d.sflow.collectors[0].port == 6400
    assert d.interfaces["Ethernet0/0/1"].sflow
    assert d.mirror_sessions[0].sources == {"Ethernet0/0/1": "both"}
    assert (d.management.lldp_timer, d.management.lldp_holdtime) == (10, 30)

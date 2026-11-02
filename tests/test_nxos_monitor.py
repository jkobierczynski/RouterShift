"""NX-OS monitoring: SPAN, sFlow, NetFlow, IP SLA probes and tracked objects (routes, HSRP), LLDP timers."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")
COMWARE = sample("comware_access.cfg")
NXOS = """\
feature sflow
feature netflow
feature sla sender
lldp timer 15
lldp holdtime 60
sflow sampling-rate 4096
sflow counter-poll-interval 20
sflow collector-ip 10.100.1.60 vrf management
sflow collector-port 6343
sflow agent-ip 10.255.0.11
sflow data-source interface Ethernet1/1
sflow data-source interface Ethernet1/2
flow exporter RS-EXPORT-1
  destination 10.100.1.61 use-vrf management
  transport udp 2055
  source mgmt0
  version 9
flow monitor RS-MONITOR
  record netflow ipv4 original-input
  exporter RS-EXPORT-1
sampler RS-SAMPLER
  mode 1 out-of 1000
ip sla 10
  icmp-echo 192.0.2.1 source-interface loopback0
    vrf PROD
    frequency 10
    timeout 2000
ip sla schedule 10 life forever start-time now
track 1 ip sla 10 reachability
  delay up 5 down 10
track 2 interface Ethernet1/1 line-protocol
vrf context PROD
  ip route 0.0.0.0/0 10.0.0.2 track 1
monitor session 1
  source interface Ethernet1/1 rx
  source interface Ethernet1/2 both
  destination interface Ethernet1/3
  filter access-group MIRROR-ACL
  no shut
ip access-list MIRROR-ACL
  10 permit ip any any
interface loopback0
  ip address 10.255.0.11/32
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/30
  ip flow monitor RS-MONITOR input sampler RS-SAMPLER
interface Ethernet1/2
interface Ethernet1/3
  switchport monitor
interface Vlan10
  ip address 10.0.10.2/24
  hsrp 10
    priority 110
    ip 10.0.10.1
    track 2 decrement 20
"""


def _findings(report, code):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_reads_nxos_monitoring() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    sf = d.sflow
    assert (sf.sample_rate, sf.polling_interval, sf.agent) == (4096, 20, "10.255.0.11")
    assert [(c.address, c.port, c.vrf) for c in sf.collectors] == [("10.100.1.60", 6343, "management")]
    assert [i.name for i in d.interfaces.values() if i.sflow] == ["Ethernet1/1", "Ethernet1/2"]
    nf = d.netflow
    assert [(c.address, c.port, c.vrf) for c in nf.collectors] == [("10.100.1.61", 2055, "management")]
    assert (nf.version, nf.sample_rate, nf.source_interface) == (9, 1000, "Management0")
    assert d.interfaces["Ethernet1/1"].flow == "input"
    s = d.mirror_sessions[0]
    assert (s.name, s.sources, s.destination, s.acl) == \
        ("1", {"Ethernet1/1": "rx", "Ethernet1/2": "both"}, "Ethernet1/3", "MIRROR-ACL")
    sla = d.ip_slas["10"]
    assert (sla.target, sla.source_interface, sla.vrf, sla.frequency, sla.timeout_ms) == \
        ("192.0.2.1", "Loopback0", "PROD", 10, 2000)
    assert (d.tracks["1"].sla, d.tracks["1"].delay_up, d.tracks["1"].delay_down) == ("10", 5, 10)
    assert d.tracks["2"].interface == "Ethernet1/1"
    assert d.static_routes[0].track == "1" and d.interfaces["Vlan10"].fhrp[0].tracks == {"2": 20}
    assert (d.management.lldp_timer, d.management.lldp_holdtime) == (15, 60)


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, report = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "  switchport monitor\n" in out and "    track 2 decrement 20\n" in out
    for attr in ("sflow", "netflow", "mirror_sessions", "ip_slas", "tracks", "static_routes"):
        def plain(v):
            if isinstance(v, dict):
                return {k: plain(x) for k, x in v.items()}
            if isinstance(v, list):
                return [plain(x) for x in v]
            return {f: x for f, x in vars(v).items() if f != "origin"} if hasattr(v, "__dataclass_fields__") else v
        assert plain(getattr(back, attr)) == plain(getattr(first, attr)), attr
    assert [(i.name, i.sflow, i.flow) for i in back.interfaces.values()] == \
        [(i.name, i.sflow, i.flow) for i in first.interfaces.values()]
    assert back.interfaces["Vlan10"].fhrp[0].tracks == {"2": 20}
    assert "not written for NX-OS yet" not in report.to_text()


def test_from_eos() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "feature sflow\n" in out and "monitor session 1\n" in out
    assert back.sflow.sample_rate == first.sflow.sample_rate
    assert [c.address for c in back.sflow.collectors] == [c.address for c in first.sflow.collectors]
    assert len(back.mirror_sessions) == len(first.mirror_sessions)
    assert back.mirror_sessions[0].acl == first.mirror_sessions[0].acl
    tracked = [r for r in first.static_routes if r.track]
    assert tracked and all(r.track for r in back.static_routes if r.prefix in {t.prefix for t in tracked})
    assert _findings(report, "sflow-options") and _findings(report, "mirror-number")
    assert _findings(report, "track-number")
    assert "sFlow is not written" not in report.to_text() and "port mirroring is not written" not in report.to_text()


def test_from_comware_probes() -> None:
    first = parse(COMWARE, "comware")
    out, report = convert(COMWARE, "comware", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "feature sla sender\n" in out and "ip sla schedule 1 life forever start-time now\n" in out
    assert len(back.ip_slas) == len(first.ip_slas) and len(back.tracks) == len(first.tracks)
    assert back.netflow is not None and back.netflow.collectors
    assert "probes are not written" not in report.to_text()

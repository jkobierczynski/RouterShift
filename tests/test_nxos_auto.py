"""NX-OS PTP and EEM applets."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")
IOS = sample("ios_access.cfg")
NXOS = """\
feature ptp
ptp source 10.255.0.11
ptp domain 24
ptp priority1 100
ptp priority2 20
track 1 interface Ethernet1/1 line-protocol
event manager applet UPLINK
  description "Uplink watch"
  event syslog pattern "Interface Ethernet1/1 is (up|down)"
  action 1.0 syslog priority warnings msg "uplink changed"
  action 2.0 cli show interface ethernet 1/1
event manager applet SAVE
  event cli match "copy running-config startup-config"
  action 1.0 syslog priority notifications msg "config saved"
event manager applet TRACKED
  event track 1 state down
  action 1.0 syslog priority errors msg "track 1 down"
interface Ethernet1/1
  no switchport
  ip address 10.0.0.1/30
  ptp
  ptp announce interval 1
  ptp sync interval -2
  ptp delay-request minimum interval 0
"""


def _findings(report, code):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_reads_nxos_ptp_and_eem() -> None:
    d = parse(NXOS, "nxos")
    assert [u.text for u in d.unparsed] == []
    p = d.ptp
    assert (p.mode, p.source_ip, p.domain, p.priority1, p.priority2) == ("boundary", "10.255.0.11", 24, 100, 20)
    e = d.interfaces["Ethernet1/1"]
    assert (e.ptp, e.ptp_announce_interval, e.ptp_sync_interval, e.ptp_delay_req_interval) == (True, 1, -2, 0)
    up = d.event_handlers["UPLINK"]
    assert (up.trigger, up.interface, up.description) == ("interface", "Ethernet1/1", "Uplink watch")
    assert [(a.kind, a.text) for a in up.actions] == [("syslog", "uplink changed"),
                                                      ("cli", "show interface ethernet 1/1")]
    assert d.event_handlers["SAVE"].trigger == "startup-config"
    assert (d.event_handlers["TRACKED"].trigger, d.event_handlers["TRACKED"].track) == ("track", "1")


def test_nxos_round_trip() -> None:
    first = parse(NXOS, "nxos")
    out, report = convert(NXOS, "nxos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert vars(back.ptp) | {"origin": None} == vars(first.ptp) | {"origin": None}

    def plain(d):
        return {n: {k: v for k, v in vars(h).items() if k not in ("origin", "actions")} |
                {"actions": [vars(a) for a in h.actions]} for n, h in d.event_handlers.items()}
    assert plain(back) == plain(first)
    a, b = first.interfaces["Ethernet1/1"], back.interfaces["Ethernet1/1"]
    assert (a.ptp, a.ptp_announce_interval, a.ptp_sync_interval, a.ptp_delay_req_interval) == \
        (b.ptp, b.ptp_announce_interval, b.ptp_sync_interval, b.ptp_delay_req_interval)
    assert "not written for NX-OS yet" not in report.to_text()


def test_from_eos() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert "feature ptp\n" in out and "ptp source 10.255.0.21\n" in out
    assert (back.ptp.domain, back.ptp.priority1, back.ptp.priority2) == \
        (first.ptp.domain, first.ptp.priority1, first.ptp.priority2)
    assert len([i for i in back.interfaces.values() if i.ptp]) == len([i for i in first.interfaces.values() if i.ptp])
    assert "event manager applet HIGH-CPU\n" in out and back.event_handlers["HIGH-CPU"].trigger == "cpu"
    assert back.event_handlers["ISP-A-DOWN"].trigger == "interface"
    assert _findings(report, "event-delay") and _findings(report, "ptp-options")
    assert "PTP: not written" not in report.to_text() and "EEM applets: not written" not in report.to_text()

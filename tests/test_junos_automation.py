"""Junos PTP and event policies, written and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def test_border_leaf_ptp() -> None:
    first, out, report, back = _back(EOS, "eos")
    p, q = first.ptp, back.ptp
    assert p is not None and q is not None
    assert (q.mode, q.domain, q.priority1, q.priority2) == (p.mode, p.domain, p.priority1, p.priority2)
    assert "clock-mode boundary;" in out and "sync-interval -3;" in out
    ports = lambda d: sorted((i.ptp_announce_interval, i.ptp_sync_interval, i.ptp_transport)  # noqa: E731
                             for i in d.interfaces.values() if i.ptp)
    assert ports(back) == ports(first)
    items = report.items[("system", "PTP")]
    assert items.status == "needs-review"
    assert "make the port facing the grandmaster a slave interface" in report.to_text()


def test_border_leaf_event_policies() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "events ui_commit_completed;" in out and "attributes-match snmp_trap_link_down.interface-name" in out
    for name in ("BACKUP-ON-SAVE", "ISP-A-DOWN"):
        a, b = first.event_handlers[name], back.event_handlers[name]
        assert (b.trigger, b.actions) == (a.trigger, a.actions), name
    assert "HIGH-CPU" not in back.event_handlers
    assert report.items[("system", "event handler HIGH-CPU")].status == "skipped"
    text = report.to_text()
    assert "the 30 second delay is left out" in text and "runs after every commit" in text


def test_ios_timer_and_cli() -> None:
    text = """\
event manager applet SAVE-HOURLY
 event timer watchdog time 3600
 action 1.0 cli command "enable"
 action 2.0 cli command "show version"
!
"""
    out, report = convert(text, "ios", "junos")
    assert "generate-event save-hourly {" in out and "time-interval 3600;" in out
    back = parse(out, "junos")
    assert back.unparsed == []
    h = back.event_handlers["SAVE-HOURLY"]
    assert (h.trigger, h.pattern, [(a.kind, a.text) for a in h.actions]) == \
        ("timer", "watchdog time 3600", [("cli", "show version")])


def test_reads_native_junos_ptp() -> None:
    text = """\
set protocols ptp e2e-transparent
set protocols ptp domain 0
set protocols ptp master interface xe-0/0/1.0 multicast-mode transport ieee-802.3
set interfaces xe-0/0/1 unit 0 family ethernet-switching
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    assert d.ptp is not None and d.ptp.mode == "e2etransparent" and d.ptp.domain == 0
    port = next(i for i in d.interfaces.values() if i.ptp)
    assert port.ptp_transport == "layer2"

"""AOS-CX PTP (the 1588v2 profile and PTP ports), written and read back; event handlers are reported."""

from helpers import sample

from routershift.convert import convert, parse
from routershift.names import PortMapper
from routershift.parsers.aoscx import canonical

EOS = sample("eos_border_leaf.cfg")


def _findings(report, code: str):
    return [f.message for item in report.items.values() for f in item.findings if f.code == code]


def test_ptp() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "aoscx")
    assert "ptp profile 1588v2\n    mode boundary\n" in out
    back = parse(out, "aoscx")
    assert back.unparsed == []
    p, q = first.ptp, back.ptp
    assert p is not None and q is not None
    assert (q.mode, q.domain, q.priority1, q.priority2) == (p.mode, p.domain, p.priority1, p.priority2)
    ports = PortMapper(first, "aoscx")
    for name, iface in first.interfaces.items():
        if iface.ptp:
            got = back.interfaces[canonical(ports(name))[0]]
            assert (got.ptp, got.ptp_announce_interval, got.ptp_sync_interval) == \
                (True, iface.ptp_announce_interval, iface.ptp_sync_interval), name
    assert _findings(report, "ptp-platform")


def test_event_handlers_reported() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "aoscx")
    assert len(_findings(report, "event-handler")) == len(first.event_handlers)
    assert all("NAE agents" in m for m in _findings(report, "event-handler"))
    assert not any("event handlers" in m for m in _findings(report, "not-written"))

"""AOS-CX monitoring: LLDP options, tracked objects in VRRP groups, the sFlow VRF, and the reported mirror ACL and
TWAMP reflector."""

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


def test_lldp() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "lldp timer 15\nlldp holdtime-multiplier 4\nlldp management-ipv4-address " in out
    m, f = back.management, first.management
    assert (m.lldp_timer, m.lldp_holdtime) == (f.lldp_timer, f.lldp_holdtime)
    assert m.lldp_mgmt_interface == "Management1"
    assert _findings(report, "lldp-mgmt")


def test_tracked_objects() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "track 1 interface 1/1/" in out
    assert "        track 1\n" in out
    [t] = back.tracks.values()
    assert t.interface
    groups = [g for i in back.interfaces.values() for g in i.fhrp if g.tracks]
    assert [list(g.tracks) for g in groups] == [["1"]]
    assert any("by 30" in m for m in _findings(report, "fhrp-track"))
    assert not any("tracked objects are not written" in m for m in _findings(report, "track-unsupported"))


def test_sflow_mirror_and_twamp() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "sflow collector 10.100.0.70 port 6343 vrf mgmt\n" in out
    assert _findings(report, "sflow-extensions")
    assert any("ACL-PBR-SCRUBBER" in m for m in _findings(report, "mirror-acl"))
    assert _findings(report, "twamp")
    assert not any("TWAMP" in m or "LLDP" in m for m in _findings(report, "not-written"))

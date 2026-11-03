"""AOS-S at the depth of the other targets: the EOS border leaf converts with nothing left as not written yet, the
settings AOS-S has a form for are written and read back, and the rest is reported with what AOS-S has instead."""

from typing import Tuple

from helpers import sample

from routershift.convert import convert, parse

BORDER = sample("eos_border_leaf.cfg")


def _convert() -> Tuple[str, str]:
    out, report = convert(BORDER, "eos", "aoss")
    return out, report.to_text()


def test_nothing_left_as_not_written_yet() -> None:
    _, text = _convert()
    assert "not written for AOS-S yet" not in text and "AOS-S: community lists are not written yet" not in text


def test_written() -> None:
    out, _ = _convert()
    assert "logging 10.100.1.50 tls 6514\n" in out
    assert "lldp refresh-interval 15\nlldp holdtime-multiplier 4\n" in out
    assert "aaa port-access authenticator 10 unauth-vid 900\n" in out
    assert "ip router-id 10.255.0.21\n" in out


def test_reported_with_what_aoss_has() -> None:
    _, text = _convert()
    assert "AOS-S has no MAC access lists" in text
    assert "distributed trunking" in text and "qos dscp-map" in text
    assert "the anycast gateway (AOS-S has no distributed gateway; use VRRP)" in text
    assert "radius-server dyn-authorization" in text


def test_reads_back() -> None:
    out, _ = _convert()
    back = parse(out, "aoss")
    assert [u.text for u in back.unparsed] == []
    assert back.system.syslog_transport == {"10.100.1.50": ("tls", 6514)}
    assert (back.management.lldp_timer, back.management.lldp_holdtime) == (15, 60)
    assert back.ospf[0].router_id == "10.255.0.21"
    assert any(i.dot1x_fail_vlan == 900 for i in back.interfaces.values())


def test_router_id_and_exec_banner_without_ospf() -> None:
    device = parse('hostname "sw1"\nip router-id 10.0.0.1\nbanner exec "Hello"\n', "aoss")
    assert device.unparsed == [] and device.system.router_id == "10.0.0.1" and device.system.banner_exec == "Hello"
    out, _ = convert('hostname "sw1"\nip router-id 10.0.0.1\nbanner exec "Hello"\n', "aoss", "aoss")
    assert "ip router-id 10.0.0.1\n" in out and 'banner exec "Hello"\n' in out

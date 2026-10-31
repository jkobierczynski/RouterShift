from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    sla = ios.ip_slas["10"]
    assert (sla.target, sla.source_interface, sla.frequency, sla.timeout_ms) == ("10.99.0.1", "Vlan99", 10, 1000)
    assert (ios.tracks["1"].sla, ios.tracks["1"].delay_up, ios.tracks["1"].delay_down) == ("10", 5, 10)
    assert ios.tracks["2"].interface == "Ethernet1/1/1"
    assert [r.track for r in ios.static_routes if r.track] == ["1"]
    assert ios.interfaces["Vlan99"].fhrp[0].tracks == {"1": 20, "2": 10}
    comware = parse(sample("comware_access.cfg"), "comware")
    gw = comware.ip_slas["gw"]
    assert (gw.target, gw.source_address, gw.frequency) == ("10.99.0.1", "10.99.0.4", 5)
    assert (comware.tracks["5"].sla, comware.tracks["6"].delay_down) == ("gw", 3)
    assert comware.interfaces["Vlan10"].fhrp[0].tracks == {"5": 30}
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert eos.tracks["UPLINK"].interface == "Ethernet49/1"
    text = ("interface Vlan10\n vrrp 1 ipv4 10.0.0.1\n vrrp 1 tracked-object UPLINK decrement 25\n"
            "track UPLINK interface Ethernet1 line-protocol\ninterface Ethernet1\n")
    dev = parse(text, "eos")
    assert dev.interfaces["Vlan10"].fhrp[0].tracks == {"UPLINK": 25} and not dev.unparsed


def test_writers() -> None:
    out, report = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "ip sla 1\n icmp-echo 10.99.0.1 source-ip 10.99.0.4\n  frequency 5\n" in out
    assert "track 5 ip sla 1 reachability\n" in out and "track 6 interface TenGigabitEthernet1/0/49 line-protocol\n" \
        " delay down 3\n" in out
    assert "ip route 0.0.0.0 0.0.0.0 10.99.0.1 track 5\n" in out and "  track 5 decrement 30\n  exit-vrrp\n" in out
    assert "written as 1" in report.to_text()
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert "track 1 interface Ten-GigabitEthernet" in out or "track 1 interface GigabitEthernet" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert "track 1 nqa entry admin 10 reaction 1 delay positive 5 negative 10\n" in out
    assert " vrrp vrid 99 track 1 priority reduced 20\n" in out


def test_reports() -> None:
    _, report = convert(sample("ios_access.cfg"), "ios", "eos")
    text = report.to_text()
    assert "EOS has no IP SLA probes" in text and "follows ip sla 10, which EOS cannot write" in text
    assert "static route 0.0.0.0/0 is written without it" in text
    _, report = convert(sample("comware_access.cfg"), "comware", "aoscx")
    text = report.to_text()
    assert "AOS-CX: tracked objects are not written" in text and "AOS-CX has no IP SLA probes" in text
    assert "VRRP group 10 on Vlan10 is written without it" in text

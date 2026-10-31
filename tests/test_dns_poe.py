from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios").system
    assert (ios.dns_lookup, ios.dns_search, ios.dns_source) == (False, ["corp.example.net"], "Vlan99")
    assert ios.dns_hosts == {"tftp-01": "10.0.5.69"}
    comware = parse(sample("comware_access.cfg"), "comware")
    assert (comware.system.domain_name, comware.system.dns_search) == ("example.net", ["corp.example.net"])
    port = comware.interfaces["Ethernet1/0/1"]
    assert (port.poe, port.poe_priority, port.poe_max_mw) == (True, "high", 30000)
    eos = parse(sample("eos_leaf.cfg"), "eos").interfaces["Ethernet1"]
    assert (eos.poe_priority, eos.poe_max_mw) == ("critical", 30000)
    aoss = parse(sample("aoss_edge.cfg"), "aoss")
    assert (aoss.interfaces["Ethernet1"].poe_priority, aoss.interfaces["Ethernet2"].poe) == ("critical", False)
    ios_ports = parse(sample("ios_access.cfg"), "ios").interfaces
    assert (ios_ports["Ethernet1/0/1"].poe_max_mw, ios_ports["Ethernet1/0/2"].poe) == (15400, False)


def test_writers() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "ip domain-list corp.example.net\nip domain lookup source-interface Vlan99\nip host tftp-01 10.0.5.69\n" in out
    assert "   poe priority high\n   poe limit 15.4 watts\n" in out and "   poe disabled\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert " power inline auto max 30000\n power inline port priority high\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert " dns domain corp.example.net\n dns source-interface Vlan-interface99\n ip host tftp-01 10.0.5.69\n" in out
    assert " poe enable\n poe priority high\n poe max-power 15400\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "aoscx")
    assert "ip dns domain-list corp.example.net\nip dns host nms-01 10.0.5.20\n" in out
    assert "    power-over-ethernet priority high\n" in out


def test_reports() -> None:
    _, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    text = report.to_text()
    assert "AOS-S has no setting for switching name lookup off; the search domains corp.example.net; the source " \
        "interface Vlan99; the static hosts tftp-01; left out" in text
    assert "AOS-S: the PoE limit of 15.4 W is not written" in text
    _, report = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert "PoE priority critical written as high, the nearest IOS has" in report.to_text()

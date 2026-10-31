from helpers import sample

from routershift.convert import convert, parse


def test_rip_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    rip = ios.rip
    assert rip is not None
    assert (rip.version, rip.networks, rip.passive_default, rip.active_interfaces) == (
        2, ["10.0.0.0/8"], True, ["Vlan99"])
    assert (rip.redistribute, rip.default_originate, rip.auto_summary) == (["static"], True, False)
    comware = parse(sample("comware_access.cfg"), "comware")
    rip = comware.rip
    assert rip is not None
    assert (rip.version, rip.auto_summary, rip.passive_default, rip.active_interfaces, rip.redistribute) == (
        2, False, True, ["Vlan99"], ["connected"])
    device = parse("rip 1\n network 10.1.0.0 0.0.255.255\n default cost 3\n#\n", "comware")
    assert device.rip is not None and (device.rip.networks, device.rip.default_metric) == (["10.1.0.0/16"], 3)


def test_isis_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    isis = ios.isis
    assert isis is not None
    assert (isis.tag, isis.nets, isis.level, isis.wide_metrics) == (
        "CORE", ["49.0001.0100.9900.0011.00"], "level-2", True)
    assert isis.redistribute_maps == {"connected": "STATIC-TO-OSPF"}
    assert (ios.interfaces["Vlan99"].isis, ios.interfaces["Vlan99"].isis_metric) == (True, 20)
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert eos.isis is not None and (eos.isis.tag, eos.isis.level, eos.isis.wide_metrics) == ("UNDERLAY", "level-2", True)
    port = eos.interfaces["Ethernet49/1"]
    assert (port.isis, port.isis_metric, port.isis_network) == (True, 10, "point-to-point")
    assert eos.interfaces["Loopback0"].isis_passive
    comware = parse(sample("comware_access.cfg"), "comware")
    assert comware.isis is not None and (comware.isis.tag, comware.isis.redistribute) == ("10", ["static"])
    assert comware.interfaces["Loopback0"].isis_passive and comware.interfaces["Vlan99"].isis_metric == 30


def test_writers() -> None:
    out, _ = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "router rip\n version 2\n network 10.0.0.0\n passive-interface default\n no passive-interface Vlan99\n" \
           " redistribute connected\n no auto-summary\n!\n" in out
    assert "router isis 10\n net 49.0001.0102.5525.5004.00\n is-type level-2-only\n metric-style wide\n" \
           " passive-interface Loopback0\n redistribute static ip route-map TO-CORE\n!\n" in out
    assert " ip router isis 10\n isis metric 30\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert "rip 1\n undo summary\n version 2\n network 10.0.0.0\n silent-interface all\n" \
           " undo silent-interface Vlan-interface99\n import-route static\n default-route originate\n#\n" in out
    assert "isis 1\n is-level level-2\n cost-style wide\n network-entity 49.0001.0100.9900.0011.00\n" in out
    assert " isis enable 1\n isis cost 20\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert " isis enable 1\n isis cost 10\n isis circuit-type p2p\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "eos")
    assert "router rip\n   network 10.0.0.0/8\n   redistribute connected\n   no shutdown\n!\n" in out
    assert "router isis 10\n   net 49.0001.0102.5525.5004.00\n   is-type level-2\n" in out
    assert "   isis enable 10\n   isis passive\n" in out


def test_reported_limits() -> None:
    _, report = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "passive interfaces are not written for EOS RIP" in report.to_text()
    _, report = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert "IS-IS process UNDERLAY written as process 1" in report.to_text()
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert "router rip" not in out and "AOS-S: RIP is not written" in report.to_text()
    assert "AOS-S has no IS-IS" in report.to_text()
    text = "router rip\n version 1\n network 10.1.0.0/16\n!\n"
    out, report = convert(text, "eos", "ios")
    assert " network 10.0.0.0\n" in out and "written as classful 10.0.0.0/8" in report.to_text()
    _, report = convert("router rip\n version 1\n network 10.0.0.0\n!\n", "ios", "eos")
    assert "EOS runs RIP version 2 only" in report.to_text()
    _, report = convert("router isis X\n net 49.0001.0000.0000.0001.00\n!\n", "ios", "eos")
    assert "EOS sends wide metrics" in report.to_text()

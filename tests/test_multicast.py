from helpers import sample

from routershift import multicast as multicast_text
from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert (ios.igmp_snooping, ios.igmp_querier, ios.vlans[20].igmp_snooping) == (True, True, False)
    assert multicast_text.snooped(ios) == [10, 99]
    assert (ios.multicast_routing, ios.pim_rps) == (True, ["10.99.0.1"])
    assert (ios.interfaces["Vlan99"].pim, ios.interfaces["Vlan99"].igmp_version) == ("sparse", 3)
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert multicast_text.snooped(eos) == [100, 4094] and multicast_text.queriers(eos) == [100]
    assert (eos.multicast_routing, eos.pim_rps, eos.interfaces["Vlan100"].pim) == (True, ["10.255.255.100"], "sparse")
    cx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert multicast_text.snooped(cx) == [10] and cx.pim_rps == ["10.99.0.1"]
    assert (cx.interfaces["Vlan99"].pim, cx.interfaces["Vlan99"].igmp_version) == ("sparse", 3)
    aoss = parse(sample("aoss_edge.cfg"), "aoss")
    assert (multicast_text.snooped(aoss), multicast_text.queriers(aoss)) == ([10, 20], [10])
    comware = parse(sample("comware_access.cfg"), "comware")
    assert (multicast_text.snooped(comware), multicast_text.queriers(comware)) == ([10], [10])
    assert (comware.multicast_routing, comware.interfaces["Vlan99"].pim) == (True, "sparse")


def test_writers() -> None:
    out, _ = convert(sample("comware_access.cfg"), "comware", "eos")
    assert "no ip igmp snooping vlan 20\n" in out and "ip igmp snooping vlan 10 querier\n" in out
    assert "router multicast\n   ipv4\n      routing\n!\nrouter pim sparse-mode\n   ipv4\n      rp address 10.99.0.1\n" in out
    assert "   pim ipv4 sparse-mode\n   ip igmp version 3\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert "igmp-snooping\n#\nmulticast routing\n#\npim\n static-rp 10.255.255.100\n#\n" in out
    assert " igmp-snooping enable\n igmp-snooping querier\n#\nvlan 200\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "router pim\n    enable\n    rp-address 10.99.0.1\n" in out
    assert "    ip igmp enable\n    ip pim-sparse enable\n    ip igmp version 3\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert '   name "VOICE"\n' in out and "ip igmp\n" in out
    out, _ = convert(sample("aoss_edge.cfg"), "aoss", "ios")
    assert "no ip igmp snooping vlan 1\nno ip igmp snooping vlan 99\nip igmp snooping querier\n" in out


def test_reported_limits() -> None:
    _, report = convert(sample("aoss_edge.cfg"), "aoss", "ios")
    assert "IOS sets the querier for every snooping VLAN" in report.to_text()
    _, report = convert(sample("comware_access.cfg"), "comware", "aoscx")
    assert "AOS-CX: the IGMP querier is set on the VLAN interface" in report.to_text()
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert "pim" not in out and "AOS-S: multicast routing" in report.to_text()
    text = "interface Vlan10\n ip address 10.0.0.1 255.255.255.0\n ip pim sparse-dense-mode\n"
    out, report = convert(text, "ios", "eos")
    assert "   pim ipv4 sparse-mode\n" in out and "PIM sparse-dense mode written as sparse mode" in report.to_text()
    out, _ = convert("no ip igmp snooping\n", "ios", "eos")
    assert "no ip igmp snooping\n" in out
    assert "igmp" not in convert("hostname a\n", "ios", "comware")[0]

from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert (ios.mpls.ldp, ios.mpls.router_id_interface) == (True, "Vlan99")
    assert [i.name for i in ios.interfaces.values() if i.mpls] == ["Vlan99"]
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert (eos.mpls.ldp, eos.mpls.router_id_interface) == (True, "Loopback0")
    assert [i.name for i in eos.interfaces.values() if i.mpls] == ["Ethernet49/1"]
    comware = parse(sample("comware_access.cfg"), "comware")
    assert (comware.mpls.ldp, comware.mpls.router_id) == (True, "10.255.255.4")
    assert [i.name for i in comware.interfaces.values() if i.mpls] == ["Ethernet1/0/48"]


def test_router_id_as_address_or_interface() -> None:
    out, _ = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "mpls label protocol ldp\nmpls ldp router-id Loopback0 force\n" in out  # the interface with the address
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert " mpls lsr-id 10.99.0.11\n#\nmpls ldp\n" in out  # the address of the interface
    assert " mpls enable\n mpls ldp enable\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "mpls ip\n!\nmpls ldp\n   router-id interface Vlan99\n   interface disabled default\n   no shutdown\n" in out
    assert "   mpls ldp interface\n" in out


def test_router_id_without_a_match_is_reported() -> None:
    text = "hostname pe\nmpls lsr-id 10.9.9.9\nmpls ldp\ninterface GigabitEthernet1/0/1\n port link-mode route\n" \
           " ip address 10.0.0.1 255.255.255.252\n mpls enable\n mpls ldp enable\n"
    out, report = convert(text, "comware", "ios")
    assert "router-id" not in out and "router ID 10.9.9.9 has no matching interface" in report.to_text()


def test_aos_switches_report_it() -> None:
    for target, name in (("aoscx", "AOS-CX"), ("aoss", "AOS-S")):
        out, report = convert(sample("eos_leaf.cfg"), "eos", target)
        assert "mpls" not in out
        assert f"{name} has no MPLS; LDP on Ethernet49/1 is left out" in report.to_text()

from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert eos.mlag is not None
    assert (eos.mlag.domain, eos.mlag.local_interface, eos.mlag.peer_address, eos.mlag.peer_link) == \
        ("LEAF-PAIR", "Vlan4094", "10.255.1.2", "Port-channel10")
    assert [(i.name, i.mlag_id) for i in eos.interfaces.values() if i.mlag_id] == [("Port-channel20", 20)]
    assert (eos.vrf_info["PROD"].rd, eos.vrf_info["PROD"].rt_import, eos.vrf_info["PROD"].rt_export) == \
        ("65001:10", ["65000:10"], ["65001:10"])
    cx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert cx.mlag is not None
    assert (cx.mlag.peer_link, cx.mlag.role, cx.mlag.peer_address, cx.mlag.local_interface) == \
        ("Port-channel256", "primary", "192.168.255.13", "Management1")
    assert [i.name for i in cx.interfaces.values() if i.mlag_id] == ["Port-channel1"]
    assert (cx.vrf_info["PROD"].rd, cx.vrf_info["PROD"].rt_import) == ("65010:10", ["65000:10"])
    ios = parse(sample("ios_access.cfg"), "ios")
    assert (ios.vrf_info["Mgmt-vrf"].rt_import, ios.vrf_info["Mgmt-vrf"].rt_export) == (["65000:99"], ["65000:99"])
    comware = parse(sample("comware_access.cfg"), "comware")
    assert (comware.vrf_info["PROD"].rt_import, comware.vrf_info["PROD"].rt_export) == \
        (["65000:1", "65100:1"], ["65000:1"])
    assert not [u for u in comware.unparsed if "vpn-target" in u.text]


def test_route_targets_per_platform() -> None:
    out, _ = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "vrf definition PROD\n rd 65000:1\n address-family ipv4\n  route-target both 65000:1\n" \
           "  route-target import 65100:1\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "eos")
    assert "   vrf PROD\n      rd 65000:1\n      route-target import vpn-ipv4 65000:1\n" \
           "      route-target export vpn-ipv4 65000:1\n      route-target import vpn-ipv4 65100:1\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "aoscx")
    assert "vrf PROD\n    rd 65000:1\n    address-family ipv4 unicast\n        route-target both 65000:1\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert " route-distinguisher 65001:10\n vpn-target 65000:10 import-extcommunity\n" \
           " vpn-target 65001:10 export-extcommunity\n" in out


def test_leaking_where_it_cannot_be_written() -> None:
    _, report = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "the source has no BGP" in report.to_text()
    _, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "management VRF, which takes no route distinguisher" in report.to_text()
    _, report = convert(sample("comware_access.cfg"), "comware", "aoss")
    assert "AOS-S has no VRFs; route distinguisher and route targets left out" in report.to_text()


def test_mlag_to_vsx_and_back() -> None:
    out, report = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "interface lag 20 multi-chassis\n" in out
    assert "vsx\n    inter-switch-link lag 10\n    role primary\n    keepalive peer 10.255.1.2 source 10.255.1.1\n" in out
    text = report.to_text()
    assert "VSX has no domain name (was LEAF-PAIR)" in text and "make the peer secondary" in text
    out, report = convert(sample("aoscx_access.cfg"), "aoscx", "eos")
    assert "mlag configuration\n   domain-id MLAG\n   local-interface Management1\n   peer-address 192.168.255.13\n" \
           "   peer-link Port-Channel256\n!\n" in out
    assert "interface Port-Channel1\n" in out and "   mlag 1\n" in out
    assert "EOS elects the primary itself (was primary)" in report.to_text()


def test_mlag_where_the_target_has_none() -> None:
    for target, words in (("ios", "StackWise Virtual"), ("aoss", "distributed trunking"), ("comware", "IRF or DRNI")):
        out, report = convert(sample("eos_leaf.cfg"), "eos", target)
        text = report.to_text()
        assert words in text and "peer link Port-channel10, shared LAGs Port-channel20" in text
        assert "mlag" not in out.lower().replace("mlag-peer", "")

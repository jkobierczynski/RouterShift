from helpers import sample

from routershift.convert import convert, parse
from routershift.model import AclAction, PrefixEntry


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert ios.prefix_lists["LOOPBACKS"].entries == [
        PrefixEntry(5, AclAction.PERMIT, "10.255.255.0/24", 32, None),
        PrefixEntry(10, AclAction.DENY, "0.0.0.0/0", None, 32)]
    assert ios.prefix_lists["V6-NETS"].family == "ipv6"
    first, second = ios.route_maps["STATIC-TO-OSPF"].entries
    assert (first.description, first.match_prefix_lists, first.sets) == (
        "static routes into OSPF", ["LOOPBACKS"], {"metric": "20", "tag": "100"})
    assert (second.seq, second.action) == (20, AclAction.DENY)
    assert ios.ospf[0].redistribute_maps == {"static": "STATIC-TO-OSPF"}
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert len(eos.prefix_lists["SPINE-IN"].entries) == 2
    [e] = eos.route_maps["FROM-SPINE"].entries
    assert (e.sets, e.community_additive) == ({"local-preference": "200", "community": "65001:100"}, True)
    assert eos.route_maps["TO-SPINE"].entries[0].match_acls == ["SERVERS-IN"]
    assert eos.bgp is not None
    spine = eos.bgp.peer_groups["SPINE"]
    assert (spine.route_map_in, spine.route_map_out) == ("FROM-SPINE", "TO-SPINE")
    assert eos.bgp.redistribute_maps == {"connected": "CONNECTED"}
    cx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert cx.route_maps["CORE-IN"].entries[0].sets == {"weight": "100", "next-hop": "10.99.0.1"}
    assert cx.bgp is not None
    assert (cx.bgp.neighbors[0].route_map_in, cx.bgp.neighbors[0].prefix_list_out) == ("CORE-IN", "CORE-OUT")
    comware = parse(sample("comware_access.cfg"), "comware")
    assert comware.prefix_lists["LOCAL"].entries == [PrefixEntry(10, AclAction.PERMIT, "10.10.0.0/16", 24, 28)]
    assert comware.route_maps["TO-CORE"].entries[0].sets == {"metric": "50", "weight": "10"}
    assert comware.bgp is not None
    peer = comware.bgp.neighbors[0]
    assert (peer.route_map_out, peer.prefix_list_in) == ("TO-CORE", "DEFAULT")
    assert comware.bgp.redistribute_maps == {"static": "TO-CORE"}


def test_writers() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert "ip prefix-list SPINE-IN seq 10 permit 10.0.0.0/8 le 24\n" in out
    assert "route-map FROM-SPINE permit 10\n match ip address prefix-list SPINE-IN\n set local-preference 200\n" \
           " set community 65001:100 additive\n!\n" in out
    assert "  neighbor SPINE route-map FROM-SPINE in\n  neighbor SPINE route-map TO-SPINE out\n" in out
    assert "  redistribute connected route-map CONNECTED\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "ip prefix-list LOOPBACKS\n   seq 5 permit 10.255.255.0/24 ge 32\n   seq 10 deny 0.0.0.0/0 le 32\n!\n" in out
    assert "   redistribute static route-map STATIC-TO-OSPF\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "aoscx")
    assert "ip prefix-list LOCAL seq 10 permit 10.10.0.0/16 ge 24 le 28\n" in out
    assert "route-map TO-CORE permit seq 10\n    match ip address prefix-list LOCAL\n    set metric 50\n" in out
    assert "        neighbor 10.99.0.1 route-map TO-CORE out\n        neighbor 10.99.0.1 prefix-list DEFAULT in\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert "ip prefix-list SPINE-IN index 10 permit 10.0.0.0 8 less-equal 24\n" in out
    assert "route-policy TO-SPINE permit node 10\n if-match ip address acl name SERVERS-IN\n" \
           " apply as-path 65001 65001 additive\n#\n" in out
    assert "  import-route direct route-policy CONNECTED\n" in out
    assert "  peer SPINE route-policy FROM-SPINE import\n" in out
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "comware")
    assert " apply preferred-value 100\n apply ip-address next-hop 10.99.0.1\n" in out


def test_reported_limits() -> None:
    out, report = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "route-map TO-SPINE permit seq 10\n    set as-path prepend 65001 65001\n" in out
    assert "AOS-CX route maps match prefix lists" in report.to_text()
    out, report = convert(sample("eos_leaf.cfg"), "eos", "aoss")
    assert "route-map" not in out and "prefix-list" not in out
    assert "AOS-S: route maps are not written" in report.to_text()
    text = "route-map RM permit 10\n match ip address prefix-list A B\n match tag 1 2\n!\n"
    out, report = convert(text, "ios", "eos")
    assert "   match ip address prefix-list A\n   match tag 1\n" in out
    assert "merge the others into it" in report.to_text()
    out, report = convert(text, "ios", "ios")
    assert " match ip address prefix-list A B\n match tag 1 2\n" in out


def test_unknown_lines_are_kept() -> None:
    device = parse("route-map RM permit 10\n continue 20\n set metric 5\n!\n", "ios")
    assert [u.text for u in device.unparsed] == ["continue 20"]
    assert device.route_maps["RM"].entries[0].sets == {"metric": "5"}
    device = parse("route-policy RP permit node 10\n apply mpls-label\n#\n", "comware")
    assert [u.text for u in device.unparsed] == ["apply mpls-label"]

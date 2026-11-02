"""Junos routing policy and firewall filters: the border leaf's prefix lists, route maps, community and AS-path lists,
redistribution and ACLs go to Junos and read back."""

from helpers import sample

from routershift.convert import convert, parse
from routershift.junospolicy import as_path_regex
from routershift.model import AclAction

EOS = sample("eos_border_leaf.cfg")


def _round_trip():
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "junos")
    return first, out, report, parse(out, "junos")


def test_prefix_lists_and_route_maps() -> None:
    first, out, report, back = _round_trip()
    assert "route-filter-list PL-BOGONS {" in out and "10.0.0.0/8 orlonger;" in out
    assert "0.0.0.0/0 prefix-length-range /25-/32;" in out and "172.20.0.0/16 upto /24;" in out
    for name, pl in first.prefix_lists.items():
        assert [(e.prefix, e.ge, e.le) for e in back.prefix_lists[name].entries] == \
            [(e.prefix, e.ge, e.le) for e in pl.entries], name
        assert back.prefix_lists[name].family == pl.family
    for name, rm in first.route_maps.items():
        if name == "PBR-SCRUBBER":  # matches an ACL: written as filter-based forwarding, not a routing policy
            assert report.items[("policy", f"route-map {name}")].status == "approximated"
            continue
        got = back.route_maps[name]
        assert [(e.seq, e.action, e.match_prefix_lists, e.match_as_paths, e.match_communities, e.match_rpki, e.sets,
                 e.community_additive, e.extcommunity_additive) for e in got.entries] == \
            [(e.seq, e.action, e.match_prefix_lists, e.match_as_paths, e.match_communities, e.match_rpki, e.sets,
              e.community_additive, e.extcommunity_additive) for e in rm.entries], name
    assert set(back.community_lists) == set(first.community_lists)
    assert "term implicit-deny {" in out  # IOS denies what no entry matches


def test_redistribution_and_neighbor_policies() -> None:
    first, out, report, back = _round_trip()
    assert back.bgp is not None and first.bgp is not None
    assert back.bgp.redistribute == ["connected"] and back.bgp.redistribute_maps == {"connected": "RM-CONN-TO-BGP"}
    group = back.bgp.peer_groups["MLAG-IPv4-UNDERLAY-PEER"]
    assert group.route_map_in == "RM-MLAG-PEER-IN"
    prod = next(p for p in back.ospf if p.vrf == "PROD")
    assert prod.redistribute == ["bgp"] and prod.redistribute_maps == {"bgp": "RM-BGP-TO-OSPF"}
    assert "export PROD-OSPF-EXPORT;" in out and "export BGP-EXPORT;" in out
    assert back.bgp.multipath_relax and "load-balance per-packet;" in out
    assert report.items[("bgp", "bgp 65021")].status != "exact"  # multipath has no path limit on Junos


def test_acls_are_filters() -> None:
    first, out, report, back = _round_trip()
    for name, acl in first.acls.items():
        rules = lambda a: [(e.action, e.protocol, e.source, e.destination, e.src_ports, e.dst_ports,  # noqa: E731
                            e.icmp_type, e.log) for a_ in [a] for e in a_.entries if e.action != AclAction.REMARK]
        assert rules(back.acls[name]) == rules(acl), name
    assert report.items[("acl", "ACL-DMZ-IN")].status == "approximated"  # its remarks
    assert any(i.acl_in == "ACL-INET-EDGE-IN" for i in back.interfaces.values())
    assert "destination-port [ 22 443 6030 ];" in out


def test_as_path_expressions() -> None:
    assert as_path_regex("^64496( 64496)*$") == "64496 (64496)*"
    assert as_path_regex("_65000_") == "65000"
    assert as_path_regex("^$") == "()"


def test_reads_native_junos_policy() -> None:
    text = """\
policy-options {
    prefix-list MGMT { 10.0.0.0/8; }
    community TAG members 65000:100;
    policy-statement IMPORT {
        term a {
            from { route-filter 192.0.2.0/24 orlonger; community TAG; }
            then { local-preference 300; accept; }
        }
        term b { from prefix-list MGMT; then reject; }
        then accept;
    }
}
firewall {
    family inet {
        filter PROTECT {
            term ssh {
                from { source-address { 10.1.0.0/16; 10.2.0.0/16; } protocol tcp; destination-port ssh; }
                then { count ssh; accept; }
            }
            term rest { then discard; }
        }
    }
}
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    rm = d.route_maps["IMPORT"]
    assert [(e.seq, e.action.value) for e in rm.entries] == [(10, "permit"), (20, "deny"), (30, "permit")]
    assert rm.entries[0].match_prefix_lists == ["IMPORT-a"] and rm.entries[0].sets == {"local-preference": "300"}
    assert d.prefix_lists["IMPORT-a"].entries[0].le == 32
    acl = d.acls["PROTECT"]
    assert [(e.source, e.dst_ports) for e in acl.entries] == [("10.1.0.0/16", "22"), ("10.2.0.0/16", "22"),
                                                              ("any", "")]

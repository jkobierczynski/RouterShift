"""AOS-CX routing policy: community and AS-path lists, the route-map clauses that use them, and static route
tags, written and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _findings(report):
    return [f for item in report.items.values() for f in item.findings]


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "aoscx")
    back = parse(out, "aoscx")
    assert back.unparsed == []
    return first, out, report, back


def test_lists_written_and_read_back() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "ip community-list standard CL-BLACKHOLE seq 10 permit 65535:666\n" in out
    assert "ip aspath-list AS-LONG seq 10 permit ^([0-9]+ ){50,}[0-9]+$\n" in out
    assert {n: (c.expanded, c.entries) for n, c in back.community_lists.items()} == \
        {n: (c.expanded, c.entries) for n, c in first.community_lists.items()}
    assert {n: a.entries for n, a in back.as_path_lists.items()} == \
        {n: a.entries for n, a in first.as_path_lists.items()}
    assert not any(f.code == "policy-unsupported" for f in _findings(report))


def test_route_map_clauses() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert "    match aspath-list AS-LONG\n" in out
    assert "    set metric-type type-1\n" in out
    assert "    set extcommunity rt 65021:400 additive\n" in out
    for name, rm in first.route_maps.items():
        if name not in back.route_maps:
            continue  # a PBR-only map
        got = {e.seq: e for e in back.route_maps[name].entries}
        for e in rm.entries:
            if e.match_rpki:
                continue
            g = got[e.seq]
            assert (g.match_as_paths, g.match_communities, g.sets) == \
                (e.match_as_paths, e.match_communities, e.sets), (name, e.seq)


def test_expanded_lists_from_ios() -> None:
    ios = ("hostname r1\nip community-list expanded CX permit _65000:1[0-9]_\n"
           "ip as-path access-list 10 permit ^65001_\n"
           "route-map RM permit 10\n match community CX\n match as-path 10\n set local-preference 200\n")
    first, out, report, back = _back(ios, "ios")
    assert "ip community-list expanded CX seq 10 permit _65000:1[0-9]_\n" in out
    assert "ip aspath-list 10 seq 10 permit ^65001_\n" in out
    assert "    match community-list CX\n" in out
    e = back.route_maps["RM"].entries[0]
    assert (e.match_communities, e.match_as_paths) == (["CX"], ["10"])
    assert back.community_lists["CX"].expanded


def test_rpki_still_flagged() -> None:
    first, out, report, back = _back(EOS, "eos")
    rpki = [rm for rm in first.route_maps.values() if any(e.match_rpki for e in rm.entries)]
    if rpki:
        assert any(f.code == "rm-match-unconverted" and "RPKI" in f.message for f in _findings(report))


def test_static_route_tag() -> None:
    first, out, report, back = _back(EOS, "eos")
    tagged = [r for r in first.static_routes if r.tag is not None]
    assert tagged
    assert "tag 666" in out
    assert sorted((r.prefix, r.tag) for r in back.static_routes if r.tag is not None) == \
        sorted((r.prefix, r.tag) for r in tagged)
    assert not any(f.code == "not-written" and "route tag" in f.message for f in _findings(report))

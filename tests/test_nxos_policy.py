"""NX-OS community and AS-path lists, route-map matches on them, and static route tags."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def test_lists_round_trip() -> None:
    first = parse(EOS, "eos")
    out, report = convert(EOS, "eos", "nxos")
    back = parse(out, "nxos")
    assert [u.text for u in back.unparsed] == []
    assert 'ip as-path access-list AS-ISP-A seq 10 permit "^64496( 64496)*$"\n' in out
    assert {n: (c.expanded, c.entries) for n, c in back.community_lists.items()} == \
        {n: (c.expanded, c.entries) for n, c in first.community_lists.items()}
    assert {n: a.entries for n, a in back.as_path_lists.items()} == \
        {n: a.entries for n, a in first.as_path_lists.items()}
    for name, rm in first.route_maps.items():
        written = {e.seq: e for e in back.route_maps[name].entries}
        for a in rm.entries:
            b = written.get(a.seq)
            if b is None:
                assert a.match_rpki  # NX-OS: RPKI matches are left out with a note
                continue
            assert (a.match_as_paths, a.match_communities) == (b.match_as_paths, b.match_communities)
    tagged = [(r.vrf, r.prefix, r.tag) for r in first.static_routes if r.tag is not None]
    assert tagged and tagged == [(r.vrf, r.prefix, r.tag) for r in back.static_routes if r.tag is not None]
    assert "community-list CL-BLACKHOLE: skipped" not in report.to_text()

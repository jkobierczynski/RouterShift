import pytest
from helpers import DATA

from routershift import ospf as ospf_text
from routershift.acl import safe_name
from routershift.convert import PLATFORMS, convert, parse
from routershift.model import AclAction

SAMPLES = {"ios": "ios_access.cfg", "eos": "eos_leaf.cfg", "aoscx": "aoscx_access.cfg", "aoss": "aoss_edge.cfg",
           "comware": "comware_access.cfg"}


def test_every_platform_has_a_sample() -> None:
    assert set(SAMPLES) == set(PLATFORMS)


@pytest.mark.parametrize("source", sorted(SAMPLES))
@pytest.mark.parametrize("target", sorted(PLATFORMS))
def test_converts_and_reads_back(source: str, target: str) -> None:
    text = (DATA / SAMPLES[source]).read_text(encoding="utf-8")
    first = parse(text, source)
    out, report = convert(text, source, target)
    back = parse(out, target)
    # the writer's own output holds nothing its reader does not understand
    assert [u.text for u in back.unparsed if not u.section.startswith("a trunk without")] == []
    # VLANs and layer 3 addresses survive every conversion
    assert set(first.vlans) <= set(back.vlans)
    addresses = lambda dev: sorted(a for i in dev.interfaces.values() for a in i.ipv4)  # noqa: E731
    assert addresses(first) == addresses(back)
    # every ACL arrives, with at least its convertible entries (more where a platform needs one port per entry),
    # and stays applied in the same direction
    for name, acl in first.acls.items():
        other = back.acls[safe_name(name)]
        rules = lambda a: [e for e in a.entries if e.action != AclAction.REMARK and not e.unsupported]  # noqa: E731
        assert len(rules(other)) >= len(rules(acl)), name
    bound = lambda dev: sorted((d, safe_name(getattr(i, d))) for i in dev.interfaces.values()  # noqa: E731
                               for d in ("acl_in", "acl_out", "acl6_in", "acl6_out") if getattr(i, d))
    assert bound(first) == bound(back)
    # every gateway redundancy address arrives
    virtual = lambda dev: sorted(a for i in dev.interfaces.values() for g in i.fhrp  # noqa: E731
                                 for a in [g.address] + g.secondary)
    assert virtual(first) == virtual(back)
    assert all(g.address for i in back.interfaces.values() for g in i.fhrp)
    # OSPF runs on the same number of interfaces, in the same areas, as passive or not, with the same router ID
    for p in first.ospf:
        other = next(o for o in back.ospf if o.router_id == p.router_id)
        areas = lambda dev, q: sorted((a, q.passive(i)) for i, a in ospf_text.interfaces(dev, q).items())  # noqa: E731
        assert areas(first, p) == areas(back, other)
        assert other.redistribute == p.redistribute and other.area_types == p.area_types
    costs = lambda dev: sorted(i.ospf_cost for i in dev.interfaces.values() if i.ospf_cost)  # noqa: E731
    assert costs(first) == costs(back)
    assert report.counts()

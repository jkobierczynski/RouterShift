import pytest
from helpers import DATA

from routershift.convert import PLATFORMS, convert, parse

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
    assert report.counts()

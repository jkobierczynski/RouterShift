"""The full EOS border leaf converts to every target, and no target leaves anything as not written yet: what a target
has no form for is reported with what to do instead."""

import pytest
from helpers import sample

from routershift.convert import PLATFORMS, convert


@pytest.mark.parametrize("target", sorted(PLATFORMS))
def test_converts(target: str) -> None:
    out, report = convert(sample("eos_border_leaf.cfg"), "eos", target)
    assert out.strip()
    text = report.to_text()
    assert not [line for line in text.splitlines() if "not written" in line and " yet" in line], target

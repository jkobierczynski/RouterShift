"""The full EOS border leaf converts to every target, and the other targets report the settings only the IOS and
EOS writer writes instead of dropping them."""

import pytest
from helpers import sample

from routershift.convert import PLATFORMS, convert


@pytest.mark.parametrize("target", sorted(PLATFORMS))
def test_converts(target: str) -> None:
    out, report = convert(sample("eos_border_leaf.cfg"), "eos", target)
    assert out.strip()
    if target not in ("ios", "eos"):
        assert "not written for" in report.to_text()

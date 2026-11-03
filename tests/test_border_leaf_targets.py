"""The full EOS border leaf converts to every target; the targets not written at full depth report the settings they
do not write instead of dropping them, and the full-depth ones leave nothing as not written yet."""

import pytest
from helpers import sample

from routershift.convert import PLATFORMS, convert

FULL_DEPTH = {"nxos": "NX-OS", "iosxr": "IOS-XR", "comware": "Comware"}


@pytest.mark.parametrize("target", sorted(PLATFORMS))
def test_converts(target: str) -> None:
    out, report = convert(sample("eos_border_leaf.cfg"), "eos", target)
    assert out.strip()
    if target in FULL_DEPTH:
        assert f"not written for {FULL_DEPTH[target]} yet" not in report.to_text()
    elif target not in ("ios", "eos"):
        assert "not written for" in report.to_text()

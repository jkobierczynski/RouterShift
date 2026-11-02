import json
import re
from pathlib import Path

import pytest

import routershift
from routershift.cli import main
from routershift.report import Report

ROOT = Path(__file__).parent.parent


def test_version_is_semantic() -> None:
    assert re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", routershift.__version__)


def test_changelog_has_the_version() -> None:
    headings = re.findall(r"^## (\S+)", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    assert headings[0] == "Unreleased"
    # the newest release in the changelog is the version in the code
    assert headings[1] == routershift.__version__


def test_cli_prints_the_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert capsys.readouterr().out.strip() == f"routershift {routershift.__version__}"


def test_report_names_the_version() -> None:
    report = Report("eos", "ios")
    assert report.to_text().startswith(f"RouterShift {routershift.__version__} report: eos -> ios")
    assert json.loads(report.to_json())["version"] == routershift.__version__

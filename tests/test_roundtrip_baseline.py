"""Every sample converted to every other platform and back, against the losses known today.

tests/data/roundtrip_baseline.json lists, for each sample and platform it goes through, the settings that do not
come back as they were and the lines that are not read back. A conversion that starts losing a setting fails here,
so a feature cannot disappear without anyone noticing. When a change makes more come back, or a loss is
deliberate, write the baseline again and let the diff of the file show what changed:

    python tests/test_roundtrip_baseline.py
"""

import json
import sys
from pathlib import Path
from typing import Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from helpers import DATA  # noqa: E402

from routershift.convert import PLATFORMS  # noqa: E402
from routershift.report import redact  # noqa: E402
from routershift.roundtrip import round_trip  # noqa: E402

BASELINE = DATA / "roundtrip_baseline.json"
SAMPLES = sorted(p.name for p in DATA.glob("*.cfg"))
CASES = [(name, via) for name in SAMPLES for via in PLATFORMS if via != name.split("_")[0]]


def observed(name: str, via: str) -> Dict[str, List[str]]:
    trip = round_trip((DATA / name).read_text(encoding="utf-8"), name.split("_")[0], via)
    return {"lost": [c.path for c in trip.lost], "changed": [c.path for c in trip.changed],
            "unread": [redact(t) for t in trip.unread_via + trip.unread_back]}


def _key(name: str, via: str) -> str:
    return f"{name} via {via}"


@pytest.fixture(scope="module")
def baseline() -> Dict[str, Dict[str, List[str]]]:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def test_every_case_is_in_the_baseline(baseline: Dict[str, Dict[str, List[str]]]) -> None:
    assert sorted(baseline) == sorted(_key(n, v) for n, v in CASES), "run: python tests/test_roundtrip_baseline.py"


@pytest.mark.parametrize("name,via", CASES)
def test_round_trip_loses_nothing_new(name: str, via: str, baseline: Dict[str, Dict[str, List[str]]]) -> None:
    known = baseline.get(_key(name, via), {})
    now = observed(name, via)
    for kind in ("lost", "changed", "unread"):
        new = sorted(set(now[kind]) - set(known.get(kind, [])))
        assert not new, (f"{_key(name, via)}: {kind} now, not before: {new}. If that is intended, "
                         f"run: python tests/test_roundtrip_baseline.py")
        gone = sorted(set(known.get(kind, [])) - set(now[kind]))
        assert not gone, (f"{_key(name, via)}: no longer {kind}: {gone}. Write the better baseline: "
                          f"python tests/test_roundtrip_baseline.py")


if __name__ == "__main__":
    data = {_key(n, v): observed(n, v) for n, v in CASES}
    BASELINE.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {BASELINE} ({len(data)} round trips)")

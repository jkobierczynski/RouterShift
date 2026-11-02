import json

from helpers import sample

from routershift.cli import main
from routershift.roundtrip import compare, round_trip, settings
from routershift.convert import parse


def test_a_sample_comes_back_with_its_ports_under_their_own_names() -> None:
    trip = round_trip(sample("eos_leaf.cfg"), "eos", "ios")
    # IOS numbers the ports 1/0/x; on the way back they are Ethernet1, Ethernet49/1 again, not Ethernet1..n
    whole = [c.path for c in trip.lost if c.path.count(".") == 1 and c.path.startswith("interfaces.")]
    assert whole == []
    assert not any(c.path.startswith("interfaces.Ethernet3.") for c in trip.added)


def test_what_does_not_come_back_is_listed() -> None:
    trip = round_trip(sample("eos_leaf.cfg"), "eos", "ios")
    lost = {c.path: c for c in trip.lost}
    changed = {c.path: c for c in trip.changed}
    assert "users[0]" in lost  # a SHA-512 hash IOS cannot take
    assert changed["interfaces.Ethernet49/1.mtu"].before == 9214
    assert changed["system.service_vrf"].after == "Mgmt-vrf"
    assert trip.compared == trip.unchanged + sum(c.count for c in trip.lost + trip.changed)
    assert not trip.clean


def test_a_round_trip_through_the_same_kind_of_writer_keeps_everything() -> None:
    trip = round_trip(sample("junos_core.cfg"), "junos", "eos")
    assert len(trip.lost) == 0 and trip.unread_via == [] and trip.unread_back == []


def test_settings_that_are_not_set_do_not_count() -> None:
    device = parse("hostname sw1\n", "eos")
    flat = settings(device)
    assert flat == {"system.hostname": "sw1"}


def test_records_are_matched_wherever_they_are_in_the_list() -> None:
    before = {"entries": [{"action": "permit", "port": "22"}, {"action": "deny", "port": ""}]}
    after = {"entries": [{"action": "deny", "port": None}, {"action": "permit", "port": "22"}]}
    assert compare(before, after) == ([], [], [])
    # a record split in two: the first part matches, the rest is added rather than every record after it changed
    after = {"entries": [{"action": "permit", "port": "22"}, {"action": "permit", "port": "443"},
                         {"action": "deny"}]}
    before = {"entries": [{"action": "permit", "port": "22"}, {"action": "deny"}]}
    lost, changed, added = compare(before, after)
    assert (lost, changed) == ([], [])
    assert [c.path for c in added] == ["entries[+1]"]


def test_secrets_are_not_shown() -> None:
    trip = round_trip(sample("eos_leaf.cfg"), "eos", "ios")
    text, data = trip.to_text(), trip.to_json()
    assert "$6$salt" not in text and "$6$salt" not in data
    assert "password_hash: <removed>" in text


def test_command_line(tmp_path, capsys) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "leaf.cfg"
    path.write_text(sample("eos_leaf.cfg"), encoding="utf-8")
    assert main(["roundtrip", str(path), "--from", "eos", "--via", "ios"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("RouterShift ") and "eos -> ios -> eos" in out and "Lost:" in out
    assert main(["roundtrip", str(path), "--from", "eos", "--via", "ios", "--strict"]) == 3
    capsys.readouterr()
    assert main(["roundtrip", str(path), "--from", "eos", "--via", "all", "--report-format", "json"]) == 0
    trips = json.loads(capsys.readouterr().out)
    assert sorted(t["via"] for t in trips) == ["aoscx", "aoss", "comware", "ios", "junos", "nxos"]
    assert main(["roundtrip", str(path), "--from", "eos", "--via", "all"]) == 0
    assert capsys.readouterr().out.startswith("Round trips:\n  eos -> ios -> eos:")

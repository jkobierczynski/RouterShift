# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Round trip: convert a configuration to another platform and back, and compare the two models.

A setting that the outward conversion drops or approximates without saying so shows up here: it is in the model
read from the original configuration but missing, or different, in the model read from the configuration that
comes back. The comparison is on the vendor-neutral model, so formatting, order of commands and the platform's
own spelling do not count; only what the configuration means does.

The way back uses the reverse of the port names chosen on the way out, so every port comes home under its own
name and is compared with itself.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .convert import PLATFORMS, convert, parse
from .errors import RoutershiftError
from .aaa import PLACEHOLDER  # the stand-in every writer puts where the source holds a secret encrypted
from .names import PortMapper
from .report import redact

# Parts of the model that say where a setting came from, not what it is
_IGNORED = {"origin", "source_name", "platform", "unparsed"}
# Settings whose value is a secret: the round trip report shows "<removed>" instead
_SECRETS = {"key", "auth_key", "priv_key", "password", "password_hash", "enable_secret", "secret", "psk", "cak"}
_REMOVED = "<removed>"
# Values that mean "not set": a platform that spells out a default as empty, or not at all, is not a change
_UNSET: Tuple[Any, ...] = (None, "", False)


def _unset(value: Any) -> bool:
    if isinstance(value, (list, tuple, dict)):
        return not value
    return any(value is u or (value == u and type(value) is type(u)) for u in _UNSET)


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_plain(v) for v in value]
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def _flatten(value: Any, path: str, out: Dict[str, Any]) -> None:
    """Every setting below ``value`` as path -> value, leaving out the ones that are not set."""
    if isinstance(value, dict):
        for key, item in value.items():
            if key not in _IGNORED:
                _flatten(item, f"{path}.{key}" if path else str(key), out)
    elif _records(value):
        for n, item in enumerate(value):
            _flatten(item, f"{path}[{n}]", out)
    elif not _unset(value):
        out[path] = _plain(value)


def _records(value: Any) -> bool:
    return isinstance(value, (list, tuple)) and bool(value) and all(isinstance(v, dict) for v in value)


def settings(device: Any) -> Dict[str, Any]:
    """The settings of a model, by path (``interfaces.Ethernet1.vlan``, ``aaa.servers[0].address``)."""
    out: Dict[str, Any] = {}
    _flatten(device.to_dict(), "", out)
    return out


def _secret(path: str) -> bool:
    leaf = path.rsplit(".", 1)[-1]
    return leaf in _SECRETS or (path.startswith("snmp.communities[") and leaf == "name")


def _show(path: str, value: Any) -> Any:
    """A value as the round trip report shows it, without secrets."""
    if isinstance(value, dict):
        return {k: _show(f"{path}.{k}", v) for k, v in value.items()}
    if value is not None and value != PLACEHOLDER and _secret(path):
        return _REMOVED
    return value


def _text(value: Any) -> str:
    if isinstance(value, dict):
        return "{" + ", ".join(f"{k}: {_text(v)}" for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_text(v) for v in value) + "]"
    return str(value)


def _parent(path: str) -> str:
    """The path one level up: interfaces.Ethernet1.mtu -> interfaces.Ethernet1, vlans.10 -> vlans."""
    cut = max(path.rfind("."), path.rfind("["))
    return path[:cut] if cut > 0 else path


# Changes under one parent beyond this many are summed up in the text report (a range of 4000 VLANs, say)
_LISTED = 10


@dataclass
class Change:
    path: str
    before: Any  # None when the setting was added
    after: Any  # None when the setting was lost
    count: int = 1  # settings this change covers (a whole record lost or added covers all of its settings)

    def line(self) -> str:
        if self.after is None:
            return f"{self.path} = {_text(_show(self.path, self.before))}"
        if self.before is None:
            return f"{self.path} = {_text(_show(self.path, self.after))}"
        return f"{self.path}: {_text(_show(self.path, self.before))} -> {_text(_show(self.path, self.after))}"


def _count(changes: List[Change]) -> int:
    return sum(c.count for c in changes)


@dataclass
class RoundTrip:
    """What came back from source -> via -> source."""

    source: str
    via: str
    compared: int = 0  # settings in the original model
    lost: List[Change] = field(default_factory=list)
    changed: List[Change] = field(default_factory=list)
    added: List[Change] = field(default_factory=list)
    unread_via: List[str] = field(default_factory=list)  # lines of the outward conversion the via reader did not read
    unread_back: List[str] = field(default_factory=list)  # lines of the way back the source reader did not read

    @property
    def unchanged(self) -> int:
        return self.compared - _count(self.lost) - _count(self.changed)

    @property
    def clean(self) -> bool:
        """Nothing lost or changed, and every line read on both ways."""
        return not (self.lost or self.changed or self.unread_via or self.unread_back)

    def to_dict(self) -> Dict[str, Any]:
        def rows(changes: List[Change]) -> List[Dict[str, Any]]:
            return [{"path": c.path, "before": _show(c.path, c.before), "after": _show(c.path, c.after),
                     "settings": c.count} for c in changes]
        return {"version": __version__, "source": self.source, "via": self.via, "compared": self.compared,
                "unchanged": self.unchanged, "lost": rows(self.lost), "changed": rows(self.changed),
                "added": rows(self.added), "unread_via": [redact(t) for t in self.unread_via],
                "unread_back": [redact(t) for t in self.unread_back]}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False, default=str) + "\n"

    def summary(self) -> str:
        return (f"{self.source} -> {self.via} -> {self.source}: {self.compared} settings, {self.unchanged} came back "
                f"unchanged, {_count(self.lost)} lost, {_count(self.changed)} changed, {_count(self.added)} added")

    def to_text(self) -> str:
        lines = [f"RouterShift {__version__} round trip", self.summary(), ""]
        for title, unread in ((f"Lines the {self.via} reader did not read in the outward conversion", self.unread_via),
                              (f"Lines the {self.source} reader did not read on the way back", self.unread_back)):
            if unread:
                lines.append(f"{title} ({len(unread)}):")
                lines += [f"  {redact(text)}" for text in unread]
                lines.append("")
        for title, changes in (("Lost: in the original, gone after the round trip", self.lost),
                               ("Changed: back with another value", self.changed),
                               ("Added: not in the original (often a default spelled out)", self.added)):
            if not changes:
                continue
            lines.append(f"{title} ({_count(changes)}):")
            groups: Dict[str, List[Change]] = {}
            for c in changes:
                groups.setdefault(_parent(c.path), []).append(c)
            for parent, group in groups.items():
                lines += [f"  {c.line()}" for c in group[:_LISTED]]
                if len(group) > _LISTED:
                    lines.append(f"  ... and {len(group) - _LISTED} more under {parent}")
            lines.append("")
        if self.clean and not self.added:
            lines += ["Everything came back as it was.", ""]
        return "\n".join(lines)


class _Diff:
    def __init__(self) -> None:
        self.lost: List[Change] = []
        self.changed: List[Change] = []
        self.added: List[Change] = []

    def walk(self, before: Any, after: Any, path: str) -> None:
        if isinstance(before, dict) and isinstance(after, dict):
            for key in list(before) + [k for k in after if k not in before]:
                if key not in _IGNORED:
                    self.walk(before.get(key), after.get(key), f"{path}.{key}" if path else str(key))
        elif _records(before) or _records(after):
            self.records(before or [], after or [], path)
        else:
            self.leaf(before, after, path)

    def leaf(self, before: Any, after: Any, path: str) -> None:
        old: Dict[str, Any] = {}
        new: Dict[str, Any] = {}
        _flatten(before, path, old)
        _flatten(after, path, new)
        if old == new:
            return
        if old and not new:
            self.lost.append(Change(path, _collapse(old, path), None, len(old)))
        elif new and not old:
            self.added.append(Change(path, None, _collapse(new, path), len(new)))
        elif path in old and path in new:
            self.changed.append(Change(path, old[path], new[path], 1))
        else:
            self.walk(before, after, path)

    def records(self, before: List[Any], after: List[Any], path: str) -> None:
        """Lists of records (ACL entries, servers, routes): a record that comes back whole, anywhere in the list,
        is unchanged; the others are paired with the record that shares most settings with them."""
        def flat(record: Any) -> Dict[str, Any]:
            out: Dict[str, Any] = {}
            _flatten(record, "", out)
            return out
        old = [flat(r) for r in before]
        new = [flat(r) for r in after]
        free = list(range(len(new)))
        unmatched: List[int] = []
        for n, record in enumerate(old):
            same = next((m for m in free if new[m] == record), None)
            if same is None:
                unmatched.append(n)
            else:
                free.remove(same)
        for n in unmatched:
            shared = [(sum(1 for k, v in old[n].items() if new[m].get(k) == v), m) for m in free]
            best = max(shared, default=(0, -1))
            if best[0]:
                free.remove(best[1])
                self.walk(before[n], after[best[1]], f"{path}[{n}]")
            else:
                self.walk(before[n], None, f"{path}[{n}]")
        for m in free:
            self.walk(None, after[m], f"{path}[+{m}]")


def _collapse(flat: Dict[str, Any], path: str) -> Any:
    """One value for a setting, or the settings of a whole record that was lost or added."""
    if list(flat) == [path]:
        return flat[path]
    return {key[len(path):].lstrip("."): value for key, value in flat.items()}


def compare(before: Dict[str, Any], after: Dict[str, Any]) -> Tuple[List[Change], List[Change], List[Change]]:
    """Lost, changed and added settings between two models (as ``Device.to_dict`` gives them)."""
    diff = _Diff()
    diff.walk(before, after, "")
    return diff.lost, diff.changed, diff.added


def round_trip(text: str, source: str, via: str, port_map: Optional[Dict[str, str]] = None) -> RoundTrip:
    """Convert ``text`` from ``source`` to ``via`` and back, and say what did not come back as it was."""
    if via not in PLATFORMS:
        raise RoutershiftError(f"cannot convert to '{via}'; choose one of {', '.join(sorted(PLATFORMS))}")
    original = parse(text, source)
    outward = PortMapper(original, via, port_map)
    home = PortMapper(original, source)
    # the way back names every port as the original did
    back_map = {outward(name): home(name) for name in original.interfaces}
    middle_text, _ = convert(text, source, via, port_map)
    middle = parse(middle_text, via)
    back_text, _ = convert(middle_text, via, source, back_map)
    returned = parse(back_text, source)
    result = RoundTrip(source, via)
    result.compared = len(settings(original))
    result.lost, result.changed, result.added = compare(original.to_dict(), returned.to_dict())
    result.unread_via = [u.text for u in middle.unparsed]
    result.unread_back = [u.text for u in returned.unparsed]
    return result

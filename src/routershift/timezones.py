# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fixed time zone offsets, the one form of a time zone every platform can take."""

from __future__ import annotations

import re
from typing import Optional, Tuple

_UTC = re.compile(r"^UTC([+-])(\d{1,2}):(\d{2})$")


def offset_minutes(tz: str) -> Optional[int]:
    """Offset from UTC of a time zone written as IOS writes it (``CET 1 0``) or as ``UTC+01:00``; None for a zone
    of the tz database, whose offset depends on the date."""
    m = _UTC.match(tz)
    if m:
        minutes = int(m.group(2)) * 60 + int(m.group(3))
        return -minutes if m.group(1) == "-" else minutes
    words = tz.split()
    if len(words) in (2, 3) and words[1].lstrip("-").isdigit() and (len(words) == 2 or words[2].isdigit()):
        hours = int(words[1])
        minutes = int(words[2]) if len(words) == 3 else 0
        return hours * 60 - minutes if hours < 0 else hours * 60 + minutes
    return None


def utc(minutes: int) -> str:
    sign = "-" if minutes < 0 else "+"
    return f"UTC{sign}{abs(minutes) // 60:02d}:{abs(minutes) % 60:02d}"


# Zones of the tz database as a fixed offset with summer-time rules (NX-OS clock timezone / clock summer-time) -------

_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
           "November", "December"]
_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
_REGIONS = ["Europe", "America", "Asia", "Australia", "Pacific", "Africa", "Atlantic", "Indian", "Antarctica"]
YEAR = 2026  # the year whose rules are written


def _zone(name: str):  # type: ignore[no-untyped-def]
    try:
        import zoneinfo
        for candidate in (name, "/".join("_".join(p[:1].upper() + p[1:] for p in part.split("_"))
                                         for part in name.split("/"))):
            try:
                return zoneinfo.ZoneInfo(candidate)
            except (zoneinfo.ZoneInfoNotFoundError, ValueError):
                continue
    except ImportError:
        pass
    return None


def _letters(name: Optional[str], default: str) -> str:
    """A zone abbreviation NX-OS takes (letters only); numeric ones (-04, +1245) become the default."""
    return re.sub(r"[^A-Za-z]", "", name or "")[:8] or default


def _when(local, before_offset) -> str:  # type: ignore[no-untyped-def]
    """week day month hh:mm of a transition, in the local time that held before it (week 5 = the last)."""
    import datetime
    wall = (local.astimezone(datetime.timezone.utc) + before_offset).replace(tzinfo=None)
    days = (datetime.date(wall.year + wall.month // 12, wall.month % 12 + 1, 1) - datetime.timedelta(days=1)).day
    week = 5 if wall.day + 7 > days else (wall.day - 1) // 7 + 1
    return f"{week} {_DAYS[wall.weekday()]} {_MONTHS[wall.month - 1]} {wall:%H:%M}"


def standard_and_summer(tz: str) -> Optional[Tuple[str, int, Optional[Tuple[str, str, str, int]]]]:
    """A tz database zone as (standard abbreviation, standard offset in minutes, summer time or None), the summer
    time being (abbreviation, start, end, minutes added) with start and end in the NX-OS week day month hh:mm form;
    None when the zone is unknown."""
    import datetime
    zone = _zone(tz)
    if zone is None:
        return None
    hours = [datetime.datetime(YEAR, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(hours=h)
             for h in range(0, 366 * 24, 1)]
    changes = []
    for a, b in zip(hours, hours[1:]):
        if a.astimezone(zone).utcoffset() != b.astimezone(zone).utcoffset():
            changes.append((a, b))
    first = hours[0].astimezone(zone)
    if not changes:
        off = first.utcoffset() or datetime.timedelta()
        return _letters(first.tzname(), "UTC"), int(off.total_seconds() // 60), None
    offsets = {int((h.astimezone(zone).utcoffset() or datetime.timedelta()).total_seconds() // 60) for _, h in changes}
    offsets.add(int((first.utcoffset() or datetime.timedelta()).total_seconds() // 60))
    if len(changes) != 2 or len(offsets) != 2:
        return None
    std = min(offsets)
    to_summer = [(a, b) for a, b in changes if int((b.astimezone(zone).utcoffset() or datetime.timedelta())
                                                   .total_seconds() // 60) != std][0]
    to_standard = [(a, b) for a, b in changes if (a, b) != to_summer][0]
    summer_name = _letters(to_summer[1].astimezone(zone).tzname(), "DST")
    std_name = _letters(to_standard[1].astimezone(zone).tzname(), "STD")
    start = _when(to_summer[1], datetime.timedelta(minutes=std))
    end = _when(to_standard[1], datetime.timedelta(minutes=max(offsets)))
    return std_name, std, (summer_name, start, end, max(offsets) - std)


def zone_for(std_name: str, minutes: int, summer: Optional[Tuple[str, str, str, int]]) -> str:
    """A tz database zone with that standard time and summer time ("" if none), preferring the larger regions."""
    try:
        import zoneinfo
        names = zoneinfo.available_timezones()
    except ImportError:
        return ""
    import datetime
    region = {r: n for n, r in enumerate(_REGIONS)}
    want = {minutes, minutes + (summer[3] if summer else 0)}
    for name in sorted(names, key=lambda z: (region.get(z.split("/")[0], 99), z)):
        if "/" not in name or name.split("/")[0] not in region:
            continue
        zone = _zone(name)
        quick = {int((datetime.datetime(YEAR, m, 15, tzinfo=datetime.timezone.utc).astimezone(zone).utcoffset()
                      or datetime.timedelta()).total_seconds() // 60) for m in (1, 7)}
        if quick != want:
            continue
        found = standard_and_summer(name)
        if found == (std_name, minutes, summer):
            return name
    return ""

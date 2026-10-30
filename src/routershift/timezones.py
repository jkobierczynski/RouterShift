# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Fixed time zone offsets, the one form of a time zone every platform can take."""

from __future__ import annotations

import re
from typing import Optional

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

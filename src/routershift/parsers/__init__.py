# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Readers: each turns one platform's configuration into a model.Device."""

from __future__ import annotations

from typing import Callable, Dict

from ..model import Device
from . import aoscx, aoss, comware, ioslike, junos

PARSERS: Dict[str, Callable[[str], Device]] = {
    "ios": lambda text: ioslike.parse(text, "ios"),
    "eos": lambda text: ioslike.parse(text, "eos"),
    "aoscx": aoscx.parse,
    "aoss": aoss.parse,
    "comware": comware.parse,
    "junos": junos.parse,
}

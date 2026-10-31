# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writers: each turns a model.Device into one platform's configuration."""

from __future__ import annotations

from typing import Callable, Dict

from ..model import Device
from ..names import PortMapper
from ..report import Report
from . import aoscx, aoss, comware, ioslike, junos

EMITTERS: Dict[str, Callable[[Device, PortMapper, Report], str]] = {
    "ios": lambda device, ports, report: ioslike.emit(device, "ios", ports, report),
    "eos": lambda device, ports, report: ioslike.emit(device, "eos", ports, report),
    "aoscx": aoscx.emit,
    "aoss": aoss.emit,
    "comware": comware.emit,
    "junos": junos.emit,
}

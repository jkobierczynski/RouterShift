# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""One conversion: read, map the ports, write, report."""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from .emitters import EMITTERS
from .errors import RoutershiftError
from .model import Device
from .names import PortMapper
from .parsers import PARSERS
from .report import Report

PLATFORMS = {
    "ios": "Cisco IOS and IOS XE",
    "eos": "Arista EOS",
}


def parse(text: str, source: str) -> Device:
    if source not in PARSERS:
        raise RoutershiftError(f"cannot read '{source}'; choose one of {', '.join(sorted(PARSERS))}")
    return PARSERS[source](text)


def convert(text: str, source: str, target: str,
            port_map: Optional[Dict[str, str]] = None) -> Tuple[str, Report]:
    if target not in EMITTERS:
        raise RoutershiftError(f"cannot write '{target}'; choose one of {', '.join(sorted(EMITTERS))}")
    device = parse(text, source)
    report = Report(source, target)
    ports = PortMapper(device, target, port_map)
    return EMITTERS[target](device, ports, report), report

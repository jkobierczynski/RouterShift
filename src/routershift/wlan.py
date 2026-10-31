# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""WLAN helpers that every writer shares. Only IOS XE (Catalyst 9800 and embedded controllers) and Comware (WX
controllers) carry wireless networks; the other platforms report them."""

from __future__ import annotations

from typing import Optional

from .model import Device, Wlan
from .report import Report, Severity

SUPPORTED = ("ios", "comware")
PLACEHOLDER = "CHANGE-ME"
_SECURITY = {"open": "open", "psk": "WPA2-PSK", "dot1x": "WPA2-Enterprise (802.1X)"}


def label(w: Wlan) -> str:
    return f"WLAN {w.name}" + (f" (SSID {w.ssid})" if w.ssid and w.ssid != w.name else "")


def describe(w: Wlan) -> str:
    vlan = f"VLAN {w.vlan}" if w.vlan is not None else "no VLAN"
    return f"{vlan}, {_SECURITY.get(w.security, w.security)}"


def psk(w: Wlan, report: Report) -> str:
    """The pre-shared key to write, or the placeholder when the source holds it encrypted."""
    if w.psk:
        return w.psk
    report.add("wlan", label(w), Severity.REVIEW, "secret-encrypted",
               f"the pre-shared key is stored encrypted in the source; replace {PLACEHOLDER} with it")
    return PLACEHOLDER


def unsupported(device: Device, report: Report, platform: str) -> None:
    """Report every WLAN on a target that is no wireless controller."""
    for w in device.wlans:
        report.add("wlan", label(w), Severity.REVIEW, "wlan-unsupported",
                   f"{platform} is no wireless controller; this WLAN ({describe(w)}) is left out")


def vlan_number(word: str) -> Optional[int]:
    return int(word) if word.isdigit() and 1 <= int(word) <= 4094 else None

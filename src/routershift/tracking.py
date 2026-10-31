# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IP SLA probes (Comware NQA) and tracked objects, and their use by static routes and gateway groups."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple

from .model import Device, IpSla, Track
from .report import Report, Severity

KIND = "track"
SLA_PLATFORMS = ("ios", "comware")  # IP SLA / NQA
TRACK_PLATFORMS = ("ios", "eos", "comware")
ROUTE_TRACK_PLATFORMS = ("ios", "comware")
NUMBERED = ("ios", "comware")  # the others name their tracked objects
DEFAULT_DECREMENT = 10


def sla_label(sla: IpSla) -> str:
    return f"ip sla {sla.name}"


def track_label(track: Track) -> str:
    return f"track {track.name}"


def track(device: Device, name: str, line: int = 0, text: str = "") -> Track:
    if name not in device.tracks:
        t = device.tracks[name] = Track(name)
        t.origin.line, t.origin.text = line, text
    return device.tracks[name]


@dataclass
class Plan:
    """What a target writes: the name each probe and tracked object takes there."""

    slas: Dict[str, str] = field(default_factory=dict)
    tracks: Dict[str, str] = field(default_factory=dict)

    def route_track(self, name: str) -> str:
        return self.tracks.get(name, "")

    def fhrp_tracks(self, tracks: Dict[str, int]) -> List[Tuple[str, int]]:
        return [(self.tracks[t], dec) for t, dec in tracks.items() if t in self.tracks]


def _numbers(names: Iterable[str], limit: int) -> Dict[str, str]:
    names = list(names)
    used = {n for n in names if n.isdigit() and 1 <= int(n) <= limit}
    free = (str(n) for n in range(1, limit + 1) if str(n) not in used)
    return {n: n if n in used else next(free) for n in names}


def plan(device: Device, report: Report, platform: str, label: str) -> Plan:
    """Registers every probe and tracked object in the report and decides which the target writes; ``label`` names
    the target in the messages. Static routes and gateway groups that lose their tracking are reported here too."""
    out = Plan()
    numbered = platform in NUMBERED
    sla_numbers = _numbers(device.ip_slas, 2147483647)
    for sla in device.ip_slas.values():
        report.item(KIND, sla_label(sla))
        if platform not in SLA_PLATFORMS:
            report.skip(KIND, sla_label(sla), "sla-unsupported", f"{label} has no IP SLA probes; left out")
            continue
        out.slas[sla.name] = sla_numbers[sla.name] if platform == "ios" else sla.name
        if out.slas[sla.name] != sla.name:
            report.add(KIND, sla_label(sla), Severity.APPROX, "sla-number", f"written as {out.slas[sla.name]}")
    track_numbers = _numbers(device.tracks, 1000)
    for t in device.tracks.values():
        item = track_label(t)
        report.item(KIND, item)
        if platform not in TRACK_PLATFORMS:
            report.skip(KIND, item, "track-unsupported", f"{label}: tracked objects are not written; configure them by "
                        "hand")
            continue
        if t.sla and t.sla not in out.slas:
            report.skip(KIND, item, "track-sla",
                        f"follows ip sla {t.sla}, which {label} cannot write; left out" if t.sla in device.ip_slas
                        else f"follows ip sla {t.sla}, which is not defined; left out")
            continue
        if not t.sla and not t.interface:
            report.skip(KIND, item, "track-kind", "follows nothing RouterShift converts; left out")
            continue
        out.tracks[t.name] = track_numbers[t.name] if numbered else t.name
        if out.tracks[t.name] != t.name:
            report.add(KIND, item, Severity.APPROX, "track-number", f"written as track {out.tracks[t.name]}")
        if platform == "eos" and (t.delay_up is not None or t.delay_down is not None):
            report.add(KIND, item, Severity.APPROX, "track-delay", "EOS tracks without a delay; written without it")
    for route in device.static_routes:
        if route.track and (platform not in ROUTE_TRACK_PLATFORMS or route.track not in out.tracks):
            where = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
            reason = f"{label} does not track static routes" if route.track in out.tracks else "the track is not written"
            report.add(KIND, f"track {route.track}", Severity.REVIEW, "route-track",
                       f"{reason}: static route {where} is written without it and stays when its next hop fails")
    for iface in device.interfaces.values():
        for g in iface.fhrp:
            for name in g.tracks:
                if name not in out.tracks:
                    report.add(KIND, f"track {name}", Severity.REVIEW, "fhrp-track",
                               f"{g.protocol.upper()} group {g.group} on {iface.name} is written without it: its "
                               "priority no longer drops when the object goes down")
    return out

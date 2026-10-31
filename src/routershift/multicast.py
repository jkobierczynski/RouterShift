# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""IGMP snooping and PIM helpers that every reader and writer shares."""

from __future__ import annotations

from typing import List

from .model import Device
from .report import Report, Severity

SNOOPS_BY_DEFAULT = ("ios", "eos")  # the others snoop only the VLANs they are told to
PIM_MODES = ("sparse", "dense", "sparse-dense")
LABEL = "IGMP snooping"


def stated(device: Device) -> bool:
    """Whether the source says anything about IGMP snooping."""
    return device.igmp_snooping is not None or device.igmp_querier or \
        any(v.igmp_snooping is not None or v.igmp_querier for v in device.vlans.values())


def finish(device: Device) -> None:
    """A reader's last step: on a platform that snoops by default, a VLAN statement means snooping is on."""
    if device.platform in SNOOPS_BY_DEFAULT and stated(device) and device.igmp_snooping is None:
        device.igmp_snooping = True


def snooped(device: Device) -> List[int]:
    """The VLANs that snoop IGMP."""
    if device.igmp_snooping is False:
        return []
    return sorted(v.vlan_id for v in device.vlans.values()
                  if v.igmp_snooping or v.igmp_snooping is None and device.igmp_snooping)


def queriers(device: Device) -> List[int]:
    on = snooped(device)
    return [vid for vid in on if device.igmp_querier or device.vlans[vid].igmp_querier]


def uses_pim(device: Device) -> bool:
    return device.multicast_routing or bool(device.pim_rps) or \
        any(i.pim or i.igmp_version is not None for i in device.interfaces.values())


def pim_unsupported(device: Device, report: Report, platform: str) -> None:
    if uses_pim(device):
        report.add("system", "multicast routing", Severity.REVIEW, "pim-unsupported",
                   f"{platform}: multicast routing (PIM, IGMP on routed interfaces) is not written; configure it by "
                   "hand")


def querier_unsupported(device: Device, report: Report, platform: str) -> None:
    if queriers(device):
        report.add("vlan", LABEL, Severity.REVIEW, "igmp-querier",
                   f"{platform}: the IGMP querier is set on the VLAN interface; not written")

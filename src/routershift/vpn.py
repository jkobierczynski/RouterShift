# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Site-to-site IPsec helpers that every reader and writer shares."""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Optional

from .model import Device, IkePolicy, IpsecPeer
from .report import Report, Severity

SUPPORTED = {"ios", "eos", "comware"}  # AOS-CX and AOS-S switches do not terminate IPsec tunnels
PLACEHOLDER_KEY = "CHANGE-ME"  # written where the source key is encrypted or missing

# The order of strength, to pick the nearest stronger algorithm a platform offers
ENCRYPTION = ["des", "3des", "aes-128", "aes-192", "aes-256", "aes-gcm-128", "aes-gcm-256"]
INTEGRITY = ["md5", "sha1", "sha256", "sha384", "sha512"]

# Platform words for the neutral names
IOS_ISAKMP_ENC = {"des": "des", "3des": "3des", "aes-128": "aes", "aes-192": "aes 192", "aes-256": "aes 256"}
IOS_IKEV2_ENC = {"des": "des", "3des": "3des", "aes-128": "aes-cbc-128", "aes-192": "aes-cbc-192",
                 "aes-256": "aes-cbc-256", "aes-gcm-128": "aes-gcm-128", "aes-gcm-256": "aes-gcm-256"}
IOS_HASH = {"md5": "md5", "sha1": "sha", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
IOS_IKEV2_INT = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
IOS_ESP_ENC = {"des": "esp-des", "3des": "esp-3des", "aes-128": "esp-aes", "aes-192": "esp-aes 192",
               "aes-256": "esp-aes 256", "aes-gcm-128": "esp-gcm", "aes-gcm-256": "esp-gcm 256"}
IOS_ESP_INT = {"md5": "esp-md5-hmac", "sha1": "esp-sha-hmac", "sha256": "esp-sha256-hmac",
               "sha384": "esp-sha384-hmac", "sha512": "esp-sha512-hmac"}
COMWARE_ENC = {"des": "des-cbc", "3des": "3des-cbc", "aes-128": "aes-cbc-128", "aes-192": "aes-cbc-192",
               "aes-256": "aes-cbc-256"}
COMWARE_ESP_ENC = dict(COMWARE_ENC, **{"aes-gcm-128": "aes-gcm-128", "aes-gcm-256": "aes-gcm-256"})
COMWARE_IKE_INT = {"md5": "md5", "sha1": "sha", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
COMWARE_ESP_INT = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
EOS_ENC = {"3des": "3des", "aes-128": "aes128", "aes-256": "aes256"}
EOS_ESP_ENC = dict(EOS_ENC, **{"aes-gcm-128": "aes128gcm128", "aes-gcm-256": "aes256gcm128"})
EOS_INT = {"md5": "md5", "sha1": "sha1", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}


def is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def read(table: Dict[str, str], word: str) -> str:
    """The neutral name of a platform word; ValueError when unknown, so the line is reported."""
    for neutral, platform_word in table.items():
        if platform_word == word:
            return neutral
    raise ValueError(word)


def pick(table: Dict[str, str], value: str, report: Report, label: str) -> str:
    """The platform word for a neutral name, or the nearest stronger one the platform has (reported)."""
    if value in table:
        return table[value]
    order = ENCRYPTION if value in ENCRYPTION else INTEGRITY
    stronger = [v for v in order[order.index(value) + 1:] if v in table] if value in order else []
    chosen = stronger[0] if stronger else next(iter(table))
    report.add("vpn", label, Severity.REVIEW, "vpn-algorithm",
               f"{value} is not offered; {chosen} is written, so the peer must change to it as well")
    return table[chosen]


def peer_label(p: IpsecPeer) -> str:
    if p.profile:
        return f"profile {p.name}"
    return f"crypto map {p.name} {p.seq}" + (f" -> {p.peer}" if p.peer else "")


def policy_label(policy: IkePolicy) -> str:
    return f"IKEv{policy.version} proposal {policy.name}"


def peers_of(device: Device, p: IpsecPeer) -> List[str]:
    """The remote addresses of a connection: its own, or the destinations of the tunnels using the profile."""
    if p.peer:
        return [p.peer]
    return sorted({i.tunnel_destination for i in device.interfaces.values()
                   if i.tunnel_profile == p.name and i.tunnel_destination})


def key_for(device: Device, address: str, report: Report, label: str) -> str:
    """The pre-shared key to write for a peer, or a placeholder with a note."""
    psk = device.psks.get(address) or device.psks.get("0.0.0.0")
    if psk is not None and psk.key:
        return psk.key
    why = "is stored encrypted in the source" if psk is not None else "is not in the source"
    report.add("vpn", label, Severity.REVIEW, "vpn-key",
               f"the pre-shared key for {address} {why}; replace {PLACEHOLDER_KEY} with it")
    return PLACEHOLDER_KEY


def policies_for(device: Device, p: IpsecPeer) -> List[IkePolicy]:
    """The IKE proposals a connection may use: the pinned ones, or every proposal of its IKE version."""
    if p.ike_policies:
        return [device.ike_policies[n] for n in p.ike_policies if n in device.ike_policies]
    return [policy for policy in device.ike_policies.values() if policy.version == p.ike_version]


def has_vpn(device: Device) -> bool:
    return bool(device.ipsec_peers or device.ike_policies)


def skip_all(device: Device, report: Report, platform: str) -> None:
    """For a target without IPsec: every connection goes to the report."""
    for p in device.ipsec_peers:
        report.skip("vpn", peer_label(p), "vpn-unsupported",
                    f"{platform} switches do not terminate IPsec tunnels; move this VPN to a router or firewall")


def lifetime_hours(seconds: Optional[int]) -> Optional[int]:
    return None if seconds is None else max(1, round(seconds / 3600))

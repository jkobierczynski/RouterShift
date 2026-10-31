# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer for HPE Comware 7, as lines for the system view."""

from __future__ import annotations

import ipaddress
from typing import Callable, Dict, List, Optional, Set, Tuple

from .. import aaa as aaa_text
from .. import acl as acl_text
from .. import dhcp as dhcp_text
from .. import fhrp
from .. import nat as nat_text
from .. import vpn as vpn_text
from .. import ospf as ospf_text
from .. import snmp as snmp_text
from .. import stp as stp_text
from .. import l2sec as l2sec_text
from .. import mgmt as mgmt_text
from .. import vrfs as vrfs_text
from .. import igp as igp_text
from .. import bfd as bfd_text
from .. import routemap as routemap_text
from .. import mpls as mpls_text
from .. import qos as qos_text
from .. import wlan as wlan_text
from ..model import (AaaMethod, AaaServer, AclAction, AclEntry, BgpNeighbor, Device, FhrpGroup, IpsecPeer, SnmpGroup, Interface, InterfaceKind, LacpMode, NatRule,
                     Ospf, StaticRoute, StpMode, SwitchportMode)
from ..names import PortMapper
from ..parsers.comware import COMWARE_ROLES, ranges
from ..parsers.ioslike import _vlan_ids
from ..report import Report, Severity
from ..timezones import offset_minutes

_IND = " "


def vlan_words(model_list: str) -> str:
    """The model's ``10,20,30-40`` as Comware's ``10 20 30 to 40``."""
    return " ".join(part.replace("-", " to ") for part in ranges(_vlan_ids(model_list)).split(","))


class Writer:
    def __init__(self, device: Device, ports: PortMapper, report: Report) -> None:
        self.device = device
        self.port = ports
        self.report = report
        self.out: List[str] = []
        self.is_switch = bool(device.vlans) or any(
            i.mode != SwitchportMode.ROUTED for i in device.interfaces.values())

    def emit(self) -> str:
        self.groups = {i.name: fhrp.plan(i, "comware", self.report, self.port(i.name))
                       for i in self.device.interfaces.values() if i.fhrp}
        groups = [g for gs in self.groups.values() for g in gs]
        self.vrrp_v2 = any(g.version != 3 for g in groups)
        self.system()
        self.users()
        self.aaa()
        self.port_access()
        if self.vrrp_v2:
            self.out.append(f"{_IND}vrrp version 2")  # Comware 7 runs VRRPv3 unless told otherwise
            self.block_end()
        self.vrfs()
        self.vlans()
        self.spanning_tree()
        self.acls()
        self.policies()
        self.qos()
        self.mpls()
        self.wlans()
        for p in self.device.ospf:
            self.ospf(p)
        self.rip()
        self.isis()
        self.dhcp()
        self.nat()
        self.vpn()
        order = {InterfaceKind.LAG: 0}
        for iface in sorted(self.device.interfaces.values(), key=lambda i: order.get(i.kind, 1)):
            self.interface(iface)
        self.routes()
        if self.device.bgp is not None:
            self.bgp()
        vrfs_text.mlag_unsupported(self.device, self.report, "Comware",
                                   "Comware pairs switches with IRF or DRNI; configure it by hand")
        self.out.append("return")
        self.report.unparsed(self.device.unparsed)
        return "\n".join(self.out) + "\n"

    def block_end(self) -> None:
        self.out.append("#")

    # system ----------------------------------------------------------------------------------------------------------

    def system(self) -> None:
        s = self.device.system
        rep = self.report
        if s.hostname:
            self.out.append(f"{_IND}sysname {s.hostname}")
            rep.item("system", "hostname")
        if s.timezone:
            minutes = offset_minutes(s.timezone)
            if minutes is None:
                rep.add("system", "time zone", Severity.REVIEW, "timezone",
                        f"time zone '{s.timezone}' has no fixed offset; Comware takes 'clock timezone NAME add "
                        "HH:MM:SS' and 'clock summer-time'; set it by hand")
            else:
                name = s.timezone.split()[0] if " " in s.timezone else "UTC"
                sign = "minus" if minutes < 0 else "add"
                m = abs(minutes)
                self.out.append(f"{_IND}clock timezone {name} {sign} {m // 60:02d}:{m % 60:02d}:00")
                rep.item("system", "time zone")
        vpn = f" vpn-instance {s.service_vrf}" if s.service_vrf else ""
        if s.domain_name:
            self.out.append(f"{_IND}dns domain {s.domain_name}")
            rep.item("system", "domain name")
        for server in s.dns_servers:
            self.out.append(f"{_IND}dns server {server}{vpn}")
        if s.dns_servers:
            rep.item("system", "name servers")
        if s.ntp_servers:
            self.out.append(f"{_IND}ntp-service enable")
            for key in s.ntp_keys.values():
                rep.item("system", f"ntp key {key.number}")
                mode = {"md5": "md5", "sha1": "hmac-sha-1", "sha256": "hmac-sha-256"}[key.algorithm] \
                    if key.algorithm in ("md5", "sha1", "sha256") else "hmac-sha-256"
                self.out.append(f"{_IND}ntp-service authentication-keyid {key.number} authentication-mode {mode} "
                                f"simple {snmp_text.ntp_key(key, rep)}")
                if key.trusted:
                    self.out.append(f"{_IND}ntp-service reliable authentication-keyid {key.number}")
            if s.ntp_authenticate:
                self.out.append(f"{_IND}ntp-service authentication enable")
            for server in s.ntp_servers:
                words = [f"{_IND}ntp-service unicast-server {server}{vpn}"]
                if server in s.ntp_server_keys:
                    words.append(f"authentication-keyid {s.ntp_server_keys[server]}")
                if s.ntp_source:
                    words.append(f"source {self.port(s.ntp_source)}")
                if server == s.ntp_prefer:
                    words.append("priority")
                self.out.append(" ".join(words))
            rep.item("system", "ntp servers")
        for host in s.syslog_servers:
            self.out.append(f"{_IND}info-center loghost{vpn} {host}")
        if s.syslog_servers:
            rep.item("system", "syslog servers")
        if s.logging_source:
            self.out.append(f"{_IND}info-center loghost source {self.port(s.logging_source)}")
            rep.item("system", "syslog source")
        if s.logging_level is not None:
            self.out.append(f"{_IND}info-center source default loghost level {mgmt_text.COMWARE[s.logging_level]}")
            rep.item("system", "syslog level")
        self.management()
        self.snmp()
        if s.banner_motd:
            delim = "%" if "%" not in s.banner_motd else "^"
            self.out += [f"{_IND}header motd {delim}", s.banner_motd, delim]
            rep.item("system", "banner motd")
        self.block_end()

    # users and AAA -----------------------------------------------------------------------------------------------------

    _HASHES = ("comware-hash", "comware-cipher")
    _FORMS = {"plain": "simple", "comware-hash": "hash", "comware-cipher": "cipher"}

    @staticmethod
    def role(privilege: Optional[int]) -> str:
        if privilege is None or privilege in (1, 15):
            return aaa_text.role(privilege, COMWARE_ROLES)
        return f"level-{privilege}"

    def _vty(self, scheme: bool) -> None:
        """line vty 0 63: AAA login when there are method lists or users, the protocols that come in, the timeout."""
        m = self.device.management
        vty = []
        if m.ssh is not None or m.telnet is not None:
            allowed = mgmt_text.transport(self.device).split()
            if allowed == ["none"]:
                self.report.add("management", "telnet server", Severity.REVIEW, "mgmt-lines",
                                "the source allows no remote login protocol; Comware has no 'protocol inbound none'")
            else:
                vty.append(f"protocol inbound {'all' if len(allowed) == 2 else allowed[0]}")
        if m.exec_timeout is not None:
            vty.append(f"idle-timeout {m.exec_timeout} 0")
        if scheme or self.device.users or vty:
            self.out.append("line vty 0 63")
            if scheme or self.device.users:
                self.out.append(f"{_IND}authentication-mode scheme")
            self.out += [f"{_IND}{line}" for line in vty]
            self.block_end()

    def management(self) -> None:
        """SSH, Telnet and HTTP(S) servers and LLDP (global commands); the VTY lines are written with AAA."""
        d = self.device
        m = d.management
        rep = self.report
        mgmt_text.items(d, rep)
        for word, value in (("ssh server enable", m.ssh), ("telnet server enable", m.telnet),
                            ("ip http enable", m.http), ("ip https enable", m.https), ("lldp global enable", m.lldp)):
            if value is not None:
                self.out.append(f"{_IND}{'' if value else 'undo '}{word}")
        if m.vty_acl:
            rep.add("management", "remote login ACL", Severity.REVIEW, "mgmt-acl",
                    f"apply ACL {m.vty_acl} with 'ssh server acl' / 'telnet server acl' (by ACL number) by hand")
        if m.vrf:
            rep.add("management", "ssh server", Severity.APPROX, "mgmt-vrf",
                    f"the servers listen in every VPN instance on Comware (the source used VRF {m.vrf})")
        if m.cdp:
            rep.add("management", "CDP", Severity.APPROX, "cdp-lldp",
                    "Comware has no CDP; LLDP announces the switch ('lldp compliance cdp' lets it talk to CDP "
                    "neighbors)")

    def users(self) -> None:
        rep = self.report
        secret = self.device.aaa.enable_secret
        if secret is not None:
            found = aaa_text.password(secret, self._HASHES, rep, "enable")
            if found is not None and found[0] != "none":
                rep.item("management", "enable secret")
                self.out.append(f"{_IND}super password role network-admin {self._FORMS[found[0]]} {found[1]}")
                self.block_end()
        for u in self.device.users:
            label = aaa_text.user_label(u)
            found = aaa_text.password(u, self._HASHES, rep)
            if found is None:
                continue
            rep.item("management", label)
            lines = [f"local-user {u.name} class manage"]
            if found[0] == "none":
                rep.add("management", label, Severity.REVIEW, "no-password",
                        "the user has no password in the source; Comware needs one for SSH and terminal logins")
            else:
                lines.append(f"{_IND}password {self._FORMS[found[0]]} {found[1]}")
            lines += [f"{_IND}service-type ssh terminal", f"{_IND}authorization-attribute user-role {self.role(u.privilege)}"]
            self.out += lines
            self.block_end()

    def _schemes(self) -> List[Tuple[str, str, List[AaaServer], str]]:
        """(protocol, name, servers, VPN instance) per scheme: the groups, and one scheme per protocol for every
        server of it when a method names the protocol or a server is in no group."""
        a = self.device.aaa
        by_address = {(s.protocol, s.address): s for s in a.servers}
        schemes = []
        grouped = set()
        for g in a.groups.values():
            servers = []
            for address in g.servers:
                server = by_address.get((g.protocol, address))
                if server is None:
                    self.report.add("management", f"{g.protocol} group {g.name}", Severity.REVIEW, "aaa-server",
                                    f"server {address} is not defined; left out")
                    continue
                servers.append(server)
                grouped.add(id(server))
            vrfs = {s.vrf for s in servers}
            schemes.append((g.protocol, g.name, servers, g.vrf or (vrfs.pop() if len(vrfs) == 1 else "")))
        used = {method for m in a.methods for method in m.methods}
        for protocol in ("radius", "tacacs"):
            servers = [s for s in a.servers if s.protocol == protocol]
            if servers and (f"group:{protocol}" in used or any(id(s) not in grouped for s in servers)):
                vrfs = {s.vrf for s in servers}
                schemes.append((protocol, protocol.upper(), servers, vrfs.pop() if len(vrfs) == 1 else ""))
        return schemes

    def aaa(self) -> None:
        a = self.device.aaa
        rep = self.report
        if not aaa_text.has_aaa(self.device):
            self._vty(False)
            return
        keys = {}
        for s in a.servers:
            rep.item("management", aaa_text.server_label(s))
            keys[id(s)] = aaa_text.key(s, rep)
        roles = {"radius": ["authentication", "accounting"], "tacacs": ["authentication", "authorization", "accounting"]}
        for protocol, name, servers, vrf in self._schemes():
            rep.item("management", f"{protocol} group {name}")
            self.out.append(f"{'radius' if protocol == 'radius' else 'hwtacacs'} scheme {name}")
            for n, s in enumerate(servers):
                for role in roles[protocol]:
                    port = s.acct_port if role == "accounting" and protocol == "radius" else s.auth_port
                    if role == "accounting" and protocol == "radius" and port is None and s.auth_port:
                        port = 1813
                    words = [f"{_IND}{'primary' if n == 0 else 'secondary'} {role} {s.address}"]
                    words += [str(port)] if port else []
                    words.append(f"key simple {keys[id(s)]}")
                    words += [f"vpn-instance {s.vrf}"] if s.vrf and s.vrf != vrf else []
                    self.out.append(" ".join(words))
            if vrf:
                self.out.append(f"{_IND}vpn-instance {vrf}")
            timeouts = [s.timeout for s in servers if s.timeout is not None]
            if timeouts:
                self.out.append(f"{_IND}timer response-timeout {max(timeouts)}")
            self.block_end()
        for protocol, source in a.source.items():
            iface = self.device.interfaces.get(source)
            if iface is None or not iface.ipv4:
                rep.add("management", f"{protocol} source", Severity.REVIEW, "aaa-source",
                        f"source {source} has no IPv4 address; set '{'radius' if protocol == 'radius' else 'hwtacacs'} "
                        "nas-ip' by hand")
                continue
            address = iface.ipv4[0].split("/")[0]
            self.out.append(f"{_IND}{'radius' if protocol == 'radius' else 'hwtacacs'} nas-ip {address}")
            self.block_end()
        lines = [f"{_IND}{line}" for m in a.methods for line in self._domain_line(m)]
        if lines:
            self.out += ["domain system"] + lines
            self.block_end()
        self._vty(bool(lines))

    _DOMAIN = {("authentication", "login"): "authentication login", ("authentication", "enable"): "authentication super",
               ("authorization", "exec"): "authorization login", ("authorization", "commands"): "authorization command",
               ("accounting", "exec"): "accounting login", ("accounting", "commands"): "accounting command",
               ("authentication", "dot1x"): "authentication lan-access"}

    def _domain_line(self, m: AaaMethod) -> List[str]:
        """The ISP domain lines for a method list, or none with a note."""
        rep = self.report
        label = aaa_text.method_label(m)
        words = self._DOMAIN.get((m.kind, m.service))
        if words is None or m.name != "default":
            why = ("Comware picks a domain by the user name, not per line" if words else "Comware has no such list")
            rep.skip("management", label, "aaa-list", f"{why}; configure it by hand")
            return []
        commands = m.service == "commands"
        lan = m.service == "dot1x"
        kept: List[str] = []
        for method in m.methods:
            protocol = aaa_text.protocol_of(self.device, method)
            if protocol:
                if kept or (commands and protocol != "tacacs") or (lan and protocol != "radius"):
                    continue
                name = method[len("group:"):]
                name = protocol.upper() if name == protocol else name
                kept.append(f"{'radius' if protocol == 'radius' else 'hwtacacs'}-scheme {name}")
            elif method in ("local", "none") and m.service != "enable":
                kept.append(method)
                break
        if len(kept) != len(m.methods):
            rep.add("management", label, Severity.APPROX, "aaa-method",
                    "Comware takes one scheme, then local or none (HWTACACS only for commands, RADIUS only for LAN "
                    f"access, a scheme only for super); written as {' '.join(kept) or 'nothing'}")
        if not kept:
            return []
        rep.item("management", label)
        if commands and m.level not in (None, 15):
            rep.add("management", label, Severity.APPROX, "aaa-level",
                    f"level {m.level} left out: Comware authorizes every command")
        if lan:  # the RADIUS reply authorizes the port as well
            return [f"{words} {' '.join(kept)}", f"authorization lan-access {' '.join(kept)}"]
        return [f"{words} {' '.join(kept)}"]

    def port_access(self) -> None:
        """802.1X and MAC authentication switched on globally, the reauthentication timer, and file transfer
        sources."""
        rep = self.report
        for protocol, source in self.device.system.transfer_source.items():
            self.out.append(f"{_IND}{protocol} client source interface {self.port(source)}")
            rep.item("system", f"{protocol} source")
        ports = [i for i in self.device.interfaces.values() if i.dot1x or i.mab]
        if self.device.aaa.dot1x:
            self.out.append(f"{_IND}dot1x")
            rep.item("management", "802.1X")
        if any(i.mab for i in ports):
            self.out.append(f"{_IND}mac-authentication")
        periods = sorted({i.dot1x_reauth_period for i in ports if i.dot1x_reauth and i.dot1x_reauth_period})
        if periods:
            self.out.append(f"{_IND}dot1x timer reauth-period {periods[-1]}")
            if len(periods) > 1:
                rep.add("management", "802.1X", Severity.APPROX, "dot1x-reauth",
                        f"Comware has one reauthentication period for all ports; {periods[-1]} s is written "
                        f"(the ports had {', '.join(str(p) for p in periods)})")
        if self.device.system.transfer_source or ports or self.device.aaa.dot1x:
            self.block_end()

    def _dot1x(self, iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
        if not (iface.dot1x or iface.mab):
            return []
        mode = iface.dot1x_host_mode or "single-host"
        lines = []
        if iface.dot1x:
            lines.append("dot1x")
            if mode == "multi-host":
                lines.append("dot1x port-method portbased")
            elif mode == "single-host":
                lines.append("dot1x max-user 1")
            elif mode == "multi-domain":
                add(Severity.APPROX, "dot1x-host-mode",
                    "multi-domain written as MAC-based access: Comware has no separate voice domain on the port")
            lines += ["dot1x re-authenticate"] if iface.dot1x_reauth else []
        if iface.mab:
            lines.append("mac-authentication")
            if mode == "single-host" or mode == "multi-host" and not iface.dot1x:
                lines.append("mac-authentication max-user 1")
        return lines


    _SNMP_AUTH = ["md5", "sha", "sha256", "sha384", "sha512"]
    _SNMP_PRIV = ["des", "3des", "aes128", "aes192", "aes256"]

    def snmp(self) -> None:
        s = self.device.snmp
        rep = self.report
        if not snmp_text.has_snmp(self.device):
            return
        self.out.append(f"{_IND}snmp-agent")
        versions = ["v2c"] if s.communities or any(h.version == "2c" for h in s.hosts) else []
        versions = (["v1"] if any(h.version == "1" for h in s.hosts) else []) + versions
        versions += ["v3"] if s.users or any(h.version == "3" for h in s.hosts) else []
        if versions:
            self.out.append(f"{_IND}snmp-agent sys-info version {' '.join(versions)}")
        for c in s.communities:
            label = snmp_text.community_label(self.device, c)
            rep.item("management", label)
            name = snmp_text.secret(c.name, rep, "management", label, "community")
            line = f"{_IND}snmp-agent community {'read' if c.access == 'ro' else 'write'} simple {name}"
            if c.acl and c.acl in self.device.acls:
                line += f" acl name {acl_text.safe_name(c.acl)}"
            elif c.acl:
                rep.add("management", label, Severity.REVIEW, "acl-missing", f"ACL {c.acl} is not defined; left out")
            self.out.append(line)
        if s.location:
            self.out.append(f"{_IND}snmp-agent sys-info location {s.location}")
            rep.item("management", "snmp location")
        if s.contact:
            self.out.append(f"{_IND}snmp-agent sys-info contact {s.contact}")
            rep.item("management", "snmp contact")
        levels = {"noauth": "", "auth": " authentication", "priv": " privacy"}
        groups = dict(s.groups)
        for u in s.users:
            if u.group not in groups:
                groups[u.group or u.name] = SnmpGroup(u.group or u.name, snmp_text.level(u))
        for g in groups.values():
            views = (f" read-view {g.read_view}" if g.read_view else "") + \
                (f" write-view {g.write_view}" if g.write_view else "")
            if views:
                rep.add("management", f"SNMPv3 group {g.name}", Severity.REVIEW, "snmp-view",
                        "MIB views are not converted; define them by hand")
            rep.item("management", f"SNMPv3 group {g.name}")
            self.out.append(f"{_IND}snmp-agent group v3 {g.name}{levels[g.level]}{views}")
        for u in s.users:
            label = snmp_text.user_label(u)
            rep.item("management", label)
            keys = snmp_text.user_keys(u, rep)
            words = [f"{_IND}snmp-agent usm-user v3 {u.name} {u.group or u.name} simple"]
            if u.auth:
                words.append(f"authentication-mode {snmp_text.pick(u.auth, self._SNMP_AUTH, rep, label)} {keys[0]}")
            if u.priv:
                priv = snmp_text.pick(u.priv, self._SNMP_PRIV, rep, label)
                words.append(f"privacy-mode {'des56' if priv == 'des' else priv} {keys[1]}")
            self.out.append(" ".join(words))
        if s.traps or s.hosts:
            self.out.append(f"{_IND}snmp-agent trap enable")
        for h in s.hosts:
            label = snmp_text.host_label(h)
            rep.item("management", label)
            secret = h.secret if h.version == "3" else snmp_text.secret(h.secret, rep, "management", label,
                                                                        "community")
            vpn = f" vpn-instance {h.vrf}" if h.vrf else ""
            level = {"auth": " authentication", "priv": " privacy"}.get(h.level, "") if h.version == "3" else ""
            self.out.append(f"{_IND}snmp-agent target-host {'inform' if h.informs else 'trap'} address udp-domain "
                            f"{h.address}{vpn} params securityname {secret} v{h.version}{level}")
        if s.source:
            self.out.append(f"{_IND}snmp-agent trap source {self.port(s.source)}")
        if s.vrf:
            rep.add("management", "snmp vrf", Severity.REVIEW, "snmp-vrf",
                    f"Comware has no agent VRF setting; set the VPN instance on each target host ({s.vrf})")

    def vrfs(self) -> None:
        # the management VRF too: Comware binds its management port to a VPN instance like any other interface
        for name in self.device.vrfs:
            self.out.append(f"ip vpn-instance {name}")
            info = self.device.vrf_info.get(name)
            if info and info.rd:
                self.out.append(f"{_IND}route-distinguisher {info.rd}")
            if info:
                kinds = {"import": "import-extcommunity", "export": "export-extcommunity", "both": "both"}
                self.out += [f"{_IND}vpn-target {v} {kinds[d]}" for d, v in vrfs_text.targets(info)]
            self.block_end()
            self.report.item("system", f"vrf {name}")

    def vlans(self) -> None:
        d = self.device
        rep = self.report
        snooped = l2sec_text.snooping_vlans(d)
        if d.dhcp_snooping or snooped:
            rep.item("vlan", "DHCP snooping")
            self.out.append(f"{_IND}dhcp snooping enable")
            self.block_end()
            if snooped and set(snooped) != set(d.vlans):
                rep.add("vlan", "DHCP snooping", Severity.APPROX, "dhcp-snooping",
                        f"Comware snoops every VLAN, not only {l2sec_text.vlan_text(snooped)}; the untrusted ports "
                        "decide where server replies are dropped")
        if any(i.port_security for i in d.interfaces.values()):
            self.out.append(f"{_IND}port-security enable")
            self.block_end()
        if l2sec_text.inspection_vlans(d):
            rep.item("vlan", "ARP inspection")
        for vlan in sorted(self.device.vlans.values(), key=lambda v: v.vlan_id):
            self.out.append(f"vlan {vlan.vlan_id}")
            if vlan.name:
                self.out.append(f"{_IND}name {vlan.name}")
            if vlan.shutdown:
                self.out.append(f"{_IND}shutdown")
            if vlan.arp_inspection:
                self.out.append(f"{_IND}arp detection enable")
            self.block_end()
            self.report.item("vlan", str(vlan.vlan_id))

    def spanning_tree(self) -> None:
        mode = self.device.stp_mode
        if mode == StpMode.NONE or (mode is None and not self.is_switch):
            return
        written = StpMode.RAPID_PVST if mode in stp_text.PER_VLAN else mode or StpMode.MSTP
        if stp_text.region(self.device, written, self.report):
            s = self.device.stp
            self.out.append("stp region-configuration")
            self.out += [f"{_IND}region-name {s.region}"] if s.region else []
            self.out += [f"{_IND}revision-level {s.revision}"] if s.revision is not None else []
            self.out += [f"{_IND}instance {n} vlan {vlan_words(stp_text.vlan_text(v))}"
                         for n, v in sorted(s.instances.items())]
            self.out += [f"{_IND}active region-configuration"]
            self.block_end()
        instances, vlans = stp_text.priorities(self.device, written, self.report)
        for instance, priority in sorted(instances.items()):
            self.out.append(f"{_IND}stp priority {priority}" if instance == 0 else
                            f"{_IND}stp instance {instance} priority {priority}")
        for priority in sorted(set(vlans.values())):
            members = stp_text.vlan_text([v for v, p in vlans.items() if p == priority])
            self.out.append(f"{_IND}stp vlan {vlan_words(members)} priority {priority}")
        if instances or vlans:
            self.report.item("system", "bridge priority")
        if mode is None:
            self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-default",
                            "the source runs spanning tree in its default mode; written as Comware's default, MSTP")
        else:
            word = {StpMode.STP: "stp", StpMode.RSTP: "rstp", StpMode.MSTP: "mstp",
                    StpMode.RAPID_PVST: "pvst", StpMode.PVST: "pvst"}[mode]
            if word != "mstp":
                self.out.append(f"{_IND}stp mode {word}")
            if mode == StpMode.PVST:
                self.report.add("system", "spanning-tree mode", Severity.APPROX, "stp-mode",
                                "PVST+ written as Comware PVST, which runs the rapid protocol")
            else:
                self.report.item("system", "spanning-tree mode")
        guarded = [i for i in self.device.interfaces.values() if i.stp_bpduguard]
        if guarded:
            self.out.append(f"{_IND}stp bpdu-protection")
            edge = [i for i in self.device.interfaces.values() if i.stp_portfast]
            if any(not i.stp_bpduguard for i in edge):
                self.report.add("system", "bpdu guard", Severity.APPROX, "bpdu-protection",
                                "Comware sets BPDU protection for all edge ports at once; edge ports without BPDU guard "
                                "on the source get it too")
        self.out.append(f"{_IND}stp global enable")
        self.block_end()

    # access lists ----------------------------------------------------------------------------------------------------

    def wlans(self) -> None:
        """A wlan service-template per network; binding it to the AP radios is left to a person."""
        rep = self.report
        for w in self.device.wlans:
            rep.item("wlan", wlan_text.label(w))
            self.out += [f"wlan service-template {w.name}", f"{_IND}ssid {w.ssid or w.name}"]
            if w.vlan is not None:
                self.out.append(f"{_IND}vlan {w.vlan}")
            if w.security == "psk":
                self.out += [f"{_IND}akm mode psk", f"{_IND}preshared-key pass-phrase simple {wlan_text.psk(w, rep)}"]
            elif w.security == "dot1x":
                self.out += [f"{_IND}akm mode dot1x", f"{_IND}client-security authentication-mode dot1x"]
            if w.security != "open":
                self.out += [f"{_IND}cipher-suite ccmp", f"{_IND}security-ie rsn"]
            if w.enabled:
                self.out.append(f"{_IND}service-template enable")
            self.block_end()
        if self.device.wlans:
            rep.add("wlan", "AP radios", Severity.REVIEW, "wlan-radio",
                    "bind the service templates to the AP radios (service-template under each radio)")

    def mpls(self) -> None:
        """mpls lsr-id (an address: taken from the router ID interface when given as one) and the mpls ldp view."""
        d = self.device
        if not mpls_text.has_mpls(d):
            return
        self.report.item("mpls", "MPLS and LDP")
        address = mpls_text.router_address(d)
        if address:
            self.out.append(f"{_IND}mpls lsr-id {address}")
            self.block_end()
        else:
            mpls_text.router_id_missing(d, self.report, "IPv4 address")
        self.out.append("mpls ldp")
        self.block_end()

    def qos(self) -> None:
        """Traffic classifiers, one traffic behavior per policy action, and QoS policies pairing them."""
        rep = self.report
        for c in self.device.qos_classes.values():
            label = f"class {c.name}"
            rep.item("qos", label)
            self.out.append(f"traffic classifier {c.name} operator {'and' if c.match_all else 'or'}")
            for n in range(0, len(c.dscp), 8):  # eight values per line
                self.out.append(f"{_IND}if-match dscp {' '.join(qos_text.dscp_name(d) for d in c.dscp[n:n + 8])}")
            if c.acl and c.acl in self.device.acls:
                self.out.append(f"{_IND}if-match acl name {acl_text.safe_name(c.acl)}")
            elif c.acl:
                rep.add("qos", label, Severity.REVIEW, "acl-missing", f"ACL {c.acl} is not defined; left out")
            self.block_end()
        for p in self.device.qos_policies.values():
            rep.item("qos", f"policy {p.name}")
            pairs = []
            for a in p.actions:
                label = qos_text.action_label(p, a)
                if a.qos_class != qos_text.DEFAULT_CLASS and a.qos_class not in self.device.qos_classes:
                    rep.skip("qos", label, "qos-class", f"class {a.qos_class} is not defined; left out")
                    continue
                behavior = f"{p.name}-{a.qos_class}"
                self.out.append(f"traffic behavior {behavior}")
                if a.set_dscp is not None:
                    self.out.append(f"{_IND}remark dscp {qos_text.dscp_name(a.set_dscp)}")
                if a.police_kbps is not None:
                    self.out.append(f"{_IND}car cir {a.police_kbps} red discard")
                self.block_end()
                classifier = "default-class" if a.qos_class == qos_text.DEFAULT_CLASS else a.qos_class
                pairs.append(f"{_IND}classifier {classifier} behavior {behavior}")
            self.out += [f"qos policy {p.name}"] + pairs
            self.block_end()

    def acls(self) -> None:
        for acl in self.device.acls.values():
            name = acl_text.safe_name(acl.name)
            label = acl.name if name == acl.name else f"{acl.name} -> {name}"
            self.report.item("acl", label)
            self.out.append(f"acl {'ipv6 ' if acl.family == 6 else ''}advanced name {name}")
            pending: List[str] = []  # remarks, written as the comment of the next rule
            for seq, entry, src, dst in acl_text.numbered(acl, step=5):
                if entry.unsupported:
                    self.report.add("acl", label, Severity.REVIEW, "acl-entry",
                                    f"entry '{entry.unsupported}' not converted; add it by hand after rule "
                                    f"{seq - 5}")
                    continue
                if entry.action == AclAction.REMARK:
                    pending.append(entry.remark)
                    continue
                self.out.append(f"{_IND}rule {seq} {self._rule(entry, acl.family, src, dst)}")
                if pending:
                    self.out.append(f"{_IND}rule {seq} comment {' '.join(pending)}")
                    pending = []
            self.block_end()

    def _rule(self, entry: AclEntry, family: int, src: Tuple[str, List[int]], dst: Tuple[str, List[int]]) -> str:
        words = [entry.action.value]
        proto = entry.protocol
        if proto == "ip":
            proto = "ipv6" if family == 6 else "ip"
        words.append(proto)
        for side, address, ports in (("source", entry.source, src), ("destination", entry.destination, dst)):
            if address != "any":
                net = ipaddress.ip_network(address)
                if net.version == 4:
                    words += [side, str(net.network_address), str(net.hostmask)]
                else:
                    words += [side, str(net.network_address), str(net.prefixlen)]
            if ports[0]:
                words += [f"{side}-port"] + acl_text.cisco_ports(ports)
        if entry.icmp_type is not None:
            words += ["icmp6-type" if family == 6 else "icmp-type", str(entry.icmp_type)]
        if entry.established:
            words.append("established")
        if entry.log:
            words.append("logging")
        return " ".join(words)

    # interfaces ------------------------------------------------------------------------------------------------------

    def interface(self, iface: Interface) -> None:
        name = self.port(iface.name)
        label = f"{iface.source_name or iface.name} -> {name}"
        self.report.item("interface", label)

        def add(severity: Severity, code: str, message: str) -> None:
            self.report.add("interface", label, severity, code, message)

        lines: List[str] = []
        if iface.kind == InterfaceKind.ETHERNET:
            lines.append("port link-mode route" if iface.mode == SwitchportMode.ROUTED else "port link-mode bridge")
        if iface.description:
            lines.append(f"description {iface.description}")
        if iface.kind == InterfaceKind.SUBINTERFACE and iface.encapsulation_vlan is not None:
            lines.append(f"vlan-type dot1q vid {iface.encapsulation_vlan}")
        if iface.speed is not None:
            lines.append(f"speed {iface.speed}")
            add(Severity.APPROX, "speed", "forced speed: check that the port takes it")
        if iface.duplex in ("full", "half"):
            lines.append(f"duplex {iface.duplex}")
        if iface.mtu is not None:
            if iface.mode == SwitchportMode.ROUTED or iface.kind in (InterfaceKind.VLAN, InterfaceKind.SUBINTERFACE):
                lines.append(f"mtu {iface.mtu}")
            else:
                lines.append(f"jumbo-frame enable {iface.mtu}")
        if iface.kind in (InterfaceKind.ETHERNET, InterfaceKind.LAG):
            lines += self._layer2(iface, add)
        if iface.lag:
            lines.append(f"port link-aggregation group {iface.lag[len('Port-channel'):]}")
            if iface.lacp_mode == LacpMode.PASSIVE:
                lines.append("lacp mode passive")
        if iface.kind == InterfaceKind.LAG:
            modes = {m.lacp_mode for m in self.device.interfaces.values() if m.lag == iface.name}
            if modes - {LacpMode.STATIC, None}:
                lines.append("link-aggregation mode dynamic")
        if iface.vrf:
            lines.append(f"ip binding vpn-instance {iface.vrf}")
        if iface.dhcp_client:
            lines.append("ip address dhcp-alloc")
        for n, cidr in enumerate(iface.ipv4):
            net = ipaddress.ip_interface(cidr)
            lines.append(f"ip address {net.ip} {net.netmask}" + (" sub" if n else ""))
        for cidr in iface.ipv6:
            lines.append(f"ipv6 address {cidr}")
        for direction, policy in (("inbound", iface.qos_policy_in), ("outbound", iface.qos_policy_out)):
            if policy and policy in self.device.qos_policies:
                lines.append(f"qos apply policy {policy} {direction}")
            elif policy:
                add(Severity.REVIEW, "qos-policy", f"policy {policy} is applied but not defined; left out")
        if iface.qos_trust in ("dscp", "cos"):
            lines.append(f"qos trust {'dot1p' if iface.qos_trust == 'cos' else 'dscp'}")
        if iface.mpls:
            lines += ["mpls enable", "mpls ldp enable"]
        if iface.dhcp_trust:
            lines.append("dhcp snooping trust")
        if iface.arp_trust:
            lines.append("arp detection trust")
        if iface.source_guard:
            lines.append("ip verify source ip-address mac-address")
        if iface.port_security:
            lines.append("port-security port-mode autolearn")
            if iface.port_security_max is not None:
                lines.append(f"port-security max-mac-count {iface.port_security_max}")
            violation = iface.port_security_violation
            if violation and violation != "protect":  # protect: no intrusion mode, the Comware default
                lines.append(f"port-security intrusion-mode {'disableport' if violation == 'shutdown' else 'blockmac'}")
        levels = l2sec_text.storm(iface, "unknown-unicast", ["broadcast", "multicast", "unknown-unicast"], self.report,
                                  label, "Comware")
        for kind, level in levels.items():
            if level != int(level):
                add(Severity.APPROX, "storm-control",
                    f"Comware takes whole percents: {kind} limit {level:g}% written as {round(level)}%")
            word = "unicast" if kind == "unknown-unicast" else kind
            lines.append(f"{word}-suppression {round(level)}")
        if not (iface.lldp_tx and iface.lldp_rx):
            status = "tx" if iface.lldp_tx else "rx" if iface.lldp_rx else "disable"
            lines.append(f"lldp admin-status {status}")
        for attr, v6, direction in (("acl_in", "", "inbound"), ("acl_out", "", "outbound"),
                                    ("acl6_in", "ipv6 ", "inbound"), ("acl6_out", "ipv6 ", "outbound")):
            acl_name = getattr(iface, attr)
            if acl_name and acl_name in self.device.acls:
                lines.append(f"packet-filter {v6}name {acl_text.safe_name(acl_name)} {direction}")
            elif acl_name:
                add(Severity.REVIEW, "acl-missing", f"ACL {acl_name} is applied but not defined; left out")
        for g in self.groups.get(iface.name, []):
            lines += self._vrrp(g, fhrp.adder(self.report, name, g))
        for p in self.device.ospf:
            if iface.name in p.interface_areas:
                lines.append(f"ospf {p.process} area {p.interface_areas[iface.name]}")
        if iface.ospf_cost is not None:
            lines.append(f"ospf cost {iface.ospf_cost}")
        if iface.ospf_network:
            lines.append(f"ospf network-type {'p2p' if iface.ospf_network == 'point-to-point' else 'broadcast'}")
        lines += self._isis_interface(iface)
        if iface.name in bfd_text.ospf_interfaces(self.device):
            lines.append("ospf bfd enable")
        lines += bfd_text.separate_lines(iface)
        if iface.pbr:
            lines.append(f"ip policy-based-route {iface.pbr}")
        lines += self._nat_interface(iface)
        lines += self._tunnel(iface)
        if iface.helper_addresses:
            lines.append("dhcp select relay")
            lines += [f"dhcp relay server-address {helper}" for helper in iface.helper_addresses]
        lines += self._dot1x(iface, add)
        if iface.stp_portfast:
            lines.append("stp edged-port")
        if iface.stp_guard:
            lines.append(f"stp {iface.stp_guard}-protection")
        if iface.stp_bpdufilter:
            lines.append("stp port bpdu-filter enable")
        if iface.stp_cost is not None:
            lines.append(f"stp cost {iface.stp_cost}")
        if iface.stp_port_priority is not None:
            lines.append(f"stp port priority {iface.stp_port_priority}")
        lines.append("shutdown" if iface.shutdown else "undo shutdown")
        mode = f" mode {iface.tunnel_mode}" if iface.kind == InterfaceKind.TUNNEL and iface.tunnel_mode else ""
        self.out.append(f"interface {name}{mode}")
        self.out += [_IND + line for line in lines]
        self.block_end()
        if (iface.source_name or iface.name, name) in self.port.renumbered:
            add(Severity.APPROX, "port-renamed",
                f"named {name} without a port map; check it against the cabling of the new device")

    def rip(self) -> None:
        rip = self.device.rip
        if rip is None:
            return
        rep = self.report
        rep.item("rip", igp_text.RIP_LABEL)
        lines: List[str] = []
        if rip.auto_summary is not None:
            lines.append("summary" if rip.auto_summary else "undo summary")
        if rip.version is not None:
            lines.append(f"version {rip.version}")
        lines += igp_text.rip_networks(rip, rep, "comware")
        if rip.passive_default:
            lines.append("silent-interface all")
            lines += [f"undo silent-interface {self.port(n)}" for n in rip.active_interfaces]
        else:
            lines += [f"silent-interface {self.port(n)}" for n in rip.passive_interfaces]
        for source in rip.redistribute:
            written = "direct" if source == "connected" else source
            if source == "ospf":
                written = f"ospf {self.device.ospf[0].process if self.device.ospf else 1}"
            rm = rip.redistribute_maps.get(source)
            lines.append(f"import-route {written}" + (f" route-policy {rm}" if rm else ""))
        if rip.default_metric is not None:
            lines.append(f"default cost {rip.default_metric}")
        if rip.default_originate:
            lines.append("default-route originate")
        self.out.append("rip 1")
        self.out += [_IND + line for line in lines]
        self.block_end()

    def isis(self) -> None:
        isis = self.device.isis
        if isis is None:
            return
        rep = self.report
        rep.item("isis", igp_text.isis_label(isis))
        lines: List[str] = []
        if isis.level:
            lines.append(f"is-level {isis.level}")
        if isis.wide_metrics:
            lines.append("cost-style wide")
        lines += [f"network-entity {net}" for net in isis.nets]
        for source in isis.redistribute:
            rm = isis.redistribute_maps.get(source)
            lines.append(f"import-route {'direct' if source == 'connected' else source}" +
                         (f" route-policy {rm}" if rm else ""))
        self.out.append(f"isis {igp_text.isis_tag(isis, 'comware', rep)}")
        self.out += [_IND + line for line in lines]
        self.block_end()

    def _isis_interface(self, iface: Interface) -> List[str]:
        isis = self.device.isis
        if isis is None or not iface.isis:
            return []
        lines = [f"isis enable {igp_text.isis_tag(isis, 'comware', Report())}"]
        if iface.isis_passive:
            lines.append("isis silent")
        if iface.isis_metric is not None:
            lines.append(f"isis cost {iface.isis_metric}")
        if iface.isis_network:
            lines.append("isis circuit-type p2p")
        return lines

    def ospf(self, p: Ospf) -> None:
        self.report.item("ospf", ospf_text.label(p))
        header = f"ospf {p.process}" + (f" router-id {p.router_id}" if p.router_id else "") + (
            f" vpn-instance {p.vrf}" if p.vrf else "")
        lines: List[str] = []
        if p.passive_default:
            lines.append("silent-interface all")
            lines += [f"undo silent-interface {self.port(n)}" for n in p.active_interfaces]
        else:
            lines += [f"silent-interface {self.port(n)}" for n in p.passive_interfaces]
        for source in p.redistribute:
            rm = p.redistribute_maps.get(source)
            lines.append(f"import-route {'direct' if source == 'connected' else source}" +
                         (f" route-policy {rm}" if rm else ""))
        if p.default_originate:
            lines.append("default-route-advertise" + (" always" if p.default_originate == "always" else ""))
        if p.reference_bandwidth is not None:
            lines.append(f"bandwidth-reference {p.reference_bandwidth}")
        areas = {n.area for n in p.networks} | set(p.area_types)
        for dotted in sorted(areas, key=ospf_text.area_number):
            lines.append(f"area {dotted}")
            for network in p.networks:
                if network.area == dotted:
                    net = ipaddress.ip_network(network.prefix)
                    lines.append(f"{_IND}network {net.network_address} {net.hostmask}")
            if dotted in p.area_types:
                lines.append(f"{_IND}{p.area_types[dotted]}")
        self.out.append(header)
        self.out += [_IND + line for line in lines]
        self.block_end()

    def dhcp(self) -> None:
        relay = any(i.helper_addresses for i in self.device.interfaces.values())
        if not self.device.dhcp_pools and not relay:
            return
        self.out.append(f"{_IND}dhcp enable")  # relay and server both need it
        for pool in self.device.dhcp_pools:
            vpn = f" vpn-instance {pool.vrf}" if pool.vrf else ""
            for first, last in dhcp_text.exclusions(pool):
                self.out.append(f"{_IND}dhcp server forbidden-ip {first}" + (f" {last}" if last != first else "") + vpn)
        self.block_end()
        for pool in self.device.dhcp_pools:
            label = dhcp_text.label(pool)
            if not pool.network:
                self.report.skip("dhcp", label, "dhcp-network", "a pool without a network (a host binding) is not written")
                continue
            self.report.item("dhcp", label)
            net = ipaddress.ip_network(pool.network)
            lines = [f"network {net.network_address} mask {net.netmask}"]
            if pool.default_routers:
                lines.append("gateway-list " + " ".join(pool.default_routers))
            if pool.dns_servers:
                lines.append("dns-list " + " ".join(pool.dns_servers))
            if pool.domain_name:
                lines.append(f"domain-name {pool.domain_name}")
            if pool.lease_seconds == 0:
                lines.append("expired unlimited")
            elif pool.lease_seconds is not None:
                days, hours, minutes = dhcp_text.lease_parts(pool.lease_seconds)
                lines.append(f"expired day {days} hour {hours} minute {minutes}")
            if pool.vrf:
                lines.append(f"vpn-instance {pool.vrf}")
            self.out.append(f"dhcp server ip-pool {pool.name.replace(' ', '_')}")
            self.out += [_IND + line for line in lines]
            self.block_end()

    def nat(self) -> None:
        """Address groups and one-to-one rules; the rest goes on the outside interfaces."""
        self.nat_groups = {}
        taken = {int(name) for name in self.device.nat_pools if name.isdigit()}
        number = 0
        for pool in self.device.nat_pools.values():
            if pool.name.isdigit():
                group = pool.name
            else:
                number = min(n for n in range(number + 1, number + len(taken) + 2) if n not in taken)
                group = str(number)
                self.report.add("nat", f"pool {pool.name}", Severity.APPROX, "nat-pool",
                                f"written as address group {group}; Comware numbers its address groups")
            self.nat_groups[pool.name] = group
            self.out += [f"nat address-group {group}", f"{_IND}address {pool.first} {pool.last}"]
            self.block_end()
        self.nat_outside: Dict[str, List[NatRule]] = {}
        static = []
        for rule in self.device.nat_rules:
            label = nat_text.label(rule)
            self.report.item("nat", label)
            if rule.acl and rule.acl not in self.device.acls:
                self.report.skip("nat", label, "acl-missing", f"ACL {rule.acl} is not defined; the rule is left out")
                continue
            if rule.kind == "dynamic" and rule.vrf:
                self.report.add("nat", label, Severity.REVIEW, "nat-vrf",
                                f"the sources are in VRF {rule.vrf}; check the outside interface binds that VPN")
            outside = nat_text.outside(self.device, rule)
            if not outside:
                self.report.skip("nat", label, "nat-outside", "no outside interface is marked; the rule is left out")
                continue
            if rule.kind == "static" and not rule.protocol and not rule.interface:
                static.append(rule)
            for name in outside:
                self.nat_outside.setdefault(name, []).append(rule)
        for rule in static:
            vpn = f" vpn-instance {rule.vrf}" if rule.vrf else ""
            self.out.append(f"{_IND}nat static outbound {rule.local}{vpn} {rule.translated}")
        if static:
            self.block_end()

    def _nat_interface(self, iface: Interface) -> List[str]:
        lines = []
        for rule in self.nat_outside.get(iface.name, []):
            if rule.kind == "dynamic":
                words = ["nat outbound"]
                if rule.acl:
                    words.append(f"name {acl_text.safe_name(rule.acl)}")
                if rule.pool:
                    words.append(f"address-group {self.nat_groups.get(rule.pool, rule.pool)}")
                    if not rule.overload:
                        words.append("no-pat")
                lines.append(" ".join(words))
            elif rule.protocol:
                vpn = f" vpn-instance {rule.vrf}" if rule.vrf else ""
                lines.append(f"nat server protocol {rule.protocol} global {rule.translated} {rule.translated_port} "
                             f"inside {rule.local} {rule.local_port}{vpn}")
            elif rule.interface:
                vpn = f" vpn-instance {rule.vrf}" if rule.vrf else ""
                lines.append(f"nat server global {rule.translated} inside {rule.local}{vpn}")
            elif "nat static enable" not in lines:
                lines.append("nat static enable")
        return lines

    def _tunnel(self, iface: Interface) -> List[str]:
        lines = []
        if iface.crypto_map and iface.crypto_map in self.ipsec_written:
            lines.append(f"ipsec apply policy {iface.crypto_map}")
        if iface.kind != InterfaceKind.TUNNEL:
            return lines
        if iface.tunnel_source:
            source = iface.tunnel_source
            lines.append(f"source {source if vpn_text.is_address(source) else self.port(source)}")
        if iface.tunnel_destination:
            lines.append(f"destination {iface.tunnel_destination}")
        if iface.tunnel_profile and iface.tunnel_profile in self.ipsec_written:
            lines.append(f"tunnel protection ipsec profile {iface.tunnel_profile}")
        return lines

    def vpn(self) -> None:
        """IKEv1 proposals, one keychain, an IKE profile per connection, transform sets, policies and profiles."""
        self.ipsec_written: Set[str] = set()
        if not vpn_text.has_vpn(self.device):
            return
        numbers = {}
        taken = {int(n) for n in self.device.ike_policies if n.isdigit()}
        for policy in self.device.ike_policies.values():
            label = vpn_text.policy_label(policy)
            self.report.item("vpn", label)
            if policy.version != 1:
                self.report.skip("vpn", label, "vpn-ikev2", "IKEv2 is not written for Comware yet; configure it by hand")
                continue
            if policy.name.isdigit():
                numbers[policy.name] = policy.name
            else:
                numbers[policy.name] = str(min(n for n in range(1, len(taken) + 2) if n not in taken))
                taken.add(int(numbers[policy.name]))
                self.report.add("vpn", label, Severity.APPROX, "vpn-renumbered",
                                f"written as IKE proposal {numbers[policy.name]}; Comware numbers its proposals")
            if policy.authentication != "pre-share":
                self.report.add("vpn", label, Severity.REVIEW, "vpn-auth",
                                f"authentication {policy.authentication} is not converted; pre-shared keys are written")
            for attr in ("encryption", "integrity", "dh_groups"):
                if len(getattr(policy, attr)) > 1:
                    self.report.add("vpn", label, Severity.APPROX, "vpn-one-algorithm",
                                    f"an IKE proposal takes one {attr.replace('_', ' ')}; the first is written")
            lines = []
            if policy.encryption:
                lines.append("encryption-algorithm " + vpn_text.pick(vpn_text.COMWARE_ENC, policy.encryption[0],
                                                                     self.report, label))
            if policy.integrity:
                lines.append("authentication-algorithm " + vpn_text.pick(vpn_text.COMWARE_IKE_INT,
                                                                         policy.integrity[0], self.report, label))
            if policy.dh_groups:
                lines.append(f"dh group{policy.dh_groups[0]}")
            if policy.lifetime is not None:
                lines.append(f"sa duration {policy.lifetime}")
            self.out.append(f"ike proposal {numbers[policy.name]}")
            self.out += [_IND + line for line in lines]
            self.block_end()
        peers = []
        for p in self.device.ipsec_peers:
            if p.ike_version != 1:
                self.report.skip("vpn", vpn_text.peer_label(p), "vpn-ikev2",
                                 "IKEv2 is not written for Comware yet; configure this connection by hand")
            else:
                peers.append(p)
        addresses = sorted({a for p in peers for a in vpn_text.peers_of(self.device, p)})
        if addresses:
            self.out.append("ike keychain KEYS")
            for address in addresses:
                key = vpn_text.key_for(self.device, address, self.report, f"IKE key {address}")
                self.out.append(f"{_IND}pre-shared-key address {address} 255.255.255.255 key simple {key}")
            self.block_end()
        for p in peers:
            self.out.append(f"ike profile {self._ike_profile(p)}")
            self.out.append(f"{_IND}keychain KEYS")
            self.out += [f"{_IND}match remote identity address {a} 255.255.255.255"
                         for a in vpn_text.peers_of(self.device, p)]
            proposals = [numbers[q.name] for q in vpn_text.policies_for(self.device, p) if q.name in numbers]
            if proposals:
                self.out.append(f"{_IND}proposal " + " ".join(proposals))
            self.block_end()
        pfs: Dict[str, int] = {}
        for p in peers:
            for name in p.transforms[:1]:
                if pfs.setdefault(name, p.pfs_group) != p.pfs_group:
                    self.report.add("vpn", vpn_text.peer_label(p), Severity.REVIEW, "vpn-pfs",
                                    f"Comware sets PFS on transform set {name}, which another connection uses with "
                                    f"a different group; copy the transform set for this one")
        for transform in self.device.ipsec_transforms.values():
            label = f"transform {transform.name}"
            self.report.item("vpn", label)
            lines = ["protocol esp", "esp encryption-algorithm " + vpn_text.pick(
                vpn_text.COMWARE_ESP_ENC, transform.encryption, self.report, label)]
            if transform.integrity:
                lines.append("esp authentication-algorithm " + vpn_text.pick(
                    vpn_text.COMWARE_ESP_INT, transform.integrity, self.report, label))
            lines.append(f"encapsulation-mode {transform.mode}")
            if pfs.get(transform.name):
                lines.append(f"pfs dh-group{pfs[transform.name]}")
            self.out.append(f"ipsec transform-set {transform.name}")
            self.out += [_IND + line for line in lines]
            self.block_end()
        for p in peers:
            label = vpn_text.peer_label(p)
            self.report.item("vpn", label)
            if p.acl and p.acl not in self.device.acls:
                self.report.skip("vpn", label, "acl-missing", f"ACL {p.acl} is not defined; the policy is left out")
                continue
            lines = [f"transform-set {' '.join(p.transforms)}"] if p.transforms else []
            if p.acl:
                lines.append(f"security acl name {acl_text.safe_name(p.acl)}")
            if p.peer:
                lines.append(f"remote-address {p.peer}")
            lines.append(f"ike-profile {self._ike_profile(p)}")
            if p.lifetime is not None:
                lines.append(f"sa duration time-based {p.lifetime}")
            self.out.append(f"ipsec profile {p.name} isakmp" if p.profile else f"ipsec policy {p.name} {p.seq} isakmp")
            self.out += [_IND + line for line in lines]
            self.block_end()
            self.ipsec_written.add(p.name)

    @staticmethod
    def _ike_profile(p: IpsecPeer) -> str:
        return f"IKE-{p.name}" + (f"-{p.seq}" if not p.profile else "")

    def policies(self) -> None:
        """Prefix lists, then the route policies that match them."""
        routemap_text.items(self.device, self.report)
        for pl in self.device.prefix_lists.values():
            self.out += routemap_text.comware_prefix_lines(pl)
        if self.device.prefix_lists:
            self.block_end()
        skip = bfd_text.pbr_only(self.device)
        for rm in self.device.route_maps.values():
            if rm.name not in skip:
                self.out += routemap_text.comware_route_policy_lines(rm, self.report, _IND)
        for name in bfd_text.pbr_maps(self.device):
            for seq, acls, next_hop in bfd_text.pbr_entries(self.device, name, self.report, "Comware"):
                self.out.append(f"policy-based-route {name} permit node {seq}")
                if acls:
                    self.out.append(f"{_IND}if-match acl name {acl_text.safe_name(acls[0])}")
                    if len(acls) > 1:
                        self.report.add("policy", f"route-map {name}", Severity.REVIEW, "rm-match-many",
                                        f"node {seq} matches any of ACLs {', '.join(acls)}; one is written")
                if next_hop:
                    self.out.append(f"{_IND}apply next-hop {next_hop}")
                self.block_end()

    def bgp(self) -> None:
        bgp = self.device.bgp
        assert bgp is not None
        self.report.item("bgp", f"bgp {bgp.local_as}")
        lines: List[str] = []
        if bgp.router_id:
            lines.append(f"router-id {bgp.router_id}")
        for group in bgp.peer_groups.values():
            kind = "internal" if group.remote_as == bgp.local_as else "external"
            lines.append(f"group {group.address} {kind}")
            lines += self._bgp_peer(group)
        for peer in bgp.neighbors:
            self.report.item("bgp", f"neighbor {peer.address}")
            if peer.peer_group:
                lines.append(f"peer {peer.address} group {peer.peer_group}")
            lines += self._bgp_peer(peer)
        for af in ("ipv4", "ipv6"):
            body: List[str] = []
            for prefix in bgp.networks:
                net = ipaddress.ip_network(prefix)
                if (net.version == 6) == (af == "ipv6"):
                    mask = str(net.netmask) if net.version == 4 else str(net.prefixlen)
                    body.append(f"network {net.network_address} {mask}")
            for source in bgp.redistribute6 if af == "ipv6" else bgp.redistribute:
                rm = bgp.redistribute_maps.get(source) if af == "ipv4" else None
                written = source
                if source == "ospf":
                    written = f"ospf {self.device.ospf[0].process if self.device.ospf else 1}"
                body.append(f"import-route {'direct' if written == 'connected' else written}" +
                            (f" route-policy {rm}" if rm else ""))
            for group in bgp.peer_groups.values():
                if any(af in n.families for n in bgp.neighbors if n.peer_group == group.address):
                    body += self._bgp_af_options(group)
            for peer in bgp.neighbors:
                if af in peer.families:
                    body.append(f"peer {peer.address} enable")
                    body += self._bgp_af_options(peer)
            if body:
                lines.append(f"address-family {af} unicast")
                lines += [_IND + line for line in body]
        self.out.append(f"bgp {bgp.local_as}")
        self.out += [_IND + line for line in lines]
        self.block_end()

    def _bgp_peer(self, peer: BgpNeighbor) -> List[str]:
        pre = f"peer {peer.address}"
        lines = []
        if peer.remote_as:
            lines.append(f"{pre} as-number {peer.remote_as}")
        if peer.description:
            lines.append(f"{pre} description {peer.description}")
        if peer.update_source:
            lines.append(f"{pre} connect-interface {self.port(peer.update_source)}")
        if peer.ebgp_multihop is not None:
            lines.append(f"{pre} ebgp-max-hop {peer.ebgp_multihop}")
        if peer.shutdown:
            lines.append(f"{pre} ignore")
        if peer.bfd:
            lines.append(f"{pre} bfd")
        return lines

    @staticmethod
    def _bgp_af_options(peer: BgpNeighbor) -> List[str]:
        lines = []
        if peer.next_hop_self:
            lines.append(f"peer {peer.address} next-hop-local")
        if peer.send_community:
            lines.append(f"peer {peer.address} advertise-community")
        for kind, attr in (("route-policy", "route_map"), ("prefix-list", "prefix_list")):
            for direction, word in (("in", "import"), ("out", "export")):
                name = getattr(peer, f"{attr}_{direction}")
                if name:
                    lines.append(f"peer {peer.address} {kind} {name} {word}")
        return lines

    def _vrrp(self, g: FhrpGroup, add: fhrp.Add) -> List[str]:
        pre = f"vrrp vrid {g.group}"
        lines = [f"{pre} virtual-ip {a}" for a in [g.address] + g.secondary]
        if g.priority is not None:
            lines.append(f"{pre} priority {g.priority}")
        if not g.preempts():
            lines.append(f"undo {pre} preempt-mode")
        if g.hello_ms is not None:
            lines.append(f"{pre} timer advertise {fhrp.interval(g.hello_ms, 10, add, 1, 4095)}")
        if g.version == 3 and self.vrrp_v2:
            add(Severity.APPROX, "fhrp-version", "VRRPv3 written as VRRPv2: Comware runs one version for all groups")
        if g.name:
            add(Severity.APPROX, "fhrp-name", f"description '{g.name}' left out: Comware has none for a group")
        if g.shutdown:
            lines.append(f"{pre} shutdown")
        return lines

    def _layer2(self, iface: Interface, add: Callable[[Severity, str, str], None]) -> List[str]:
        if iface.mode == SwitchportMode.ROUTED:
            return []
        source = self.device.interfaces.get(iface.lag) if iface.lag else iface
        if source is None:
            return []
        if source.mode == SwitchportMode.ACCESS:
            data = source.access_vlan or 1
            if source.voice_vlan is not None:
                if iface is source:
                    add(Severity.APPROX, "voice-vlan",
                        f"access VLAN {data} with voice VLAN {source.voice_vlan} written as a hybrid port (untagged "
                        f"{data}, tagged {source.voice_vlan}), the Comware way; phones learn the VLAN by LLDP")
                return ["port link-type hybrid", f"port hybrid vlan {source.voice_vlan} tagged",
                        f"port hybrid vlan {data} untagged", f"port hybrid pvid vlan {data}",
                        f"voice-vlan {source.voice_vlan} enable"]
            return [] if data == 1 else [f"port access vlan {data}"]
        lines = ["port link-type trunk"]
        if source.allowed_vlans:
            allowed = _vlan_ids(source.allowed_vlans)
            if 1 not in allowed:
                lines.append("undo port trunk permit vlan 1")
            lines.append(f"port trunk permit vlan {vlan_words(source.allowed_vlans)}")
        else:
            lines.append("port trunk permit vlan all")
        if source.native_vlan not in (None, 1):
            lines.append(f"port trunk pvid vlan {source.native_vlan}")
        return lines

    # routing ---------------------------------------------------------------------------------------------------------

    def routes(self) -> None:
        for route in self.device.static_routes:
            label = f"{route.vrf + ' ' if route.vrf else ''}{route.prefix}"
            self.report.item("route", label)
            self.out.append(_IND + self._route(route, label))
        if self.device.static_routes:
            self.block_end()

    def _route(self, route: StaticRoute, label: str) -> str:
        net = ipaddress.ip_network(route.prefix)
        words = ["ip" if net.version == 4 else "ipv6", "route-static"]
        if route.vrf:
            words += ["vpn-instance", route.vrf]
        words += [str(net.network_address), str(net.prefixlen)]
        if route.discard:
            words.append("NULL0")
        else:
            if route.interface:
                words.append(self.port(route.interface))
            if route.next_hop:
                words.append(route.next_hop)
        if route.distance is not None:
            words += ["preference", str(route.distance)]
        if route.name:
            words += ["description", route.name]
        return " ".join(words)


def emit(device: Device, ports: PortMapper, report: Report) -> str:
    return Writer(device, ports, report).emit()

# Scope

RouterShift reads the running configuration of a switch or router, turns it into a
vendor-neutral model (`src/routershift/model.py`), and writes it out for another
platform, with a report that says item by item what was converted exactly, what was
approximated and what a person has to look at.

## Platforms

| Key | Platform | Read | Write | Milestone |
|---|---|---|---|---|
| `ios` | Cisco IOS and IOS XE | `show running-config` | CLI configuration | 1 (done) |
| `eos` | Arista EOS | `show running-config` | CLI configuration | 1 (done) |
| `junos` | Juniper Junos (EX, QFX, MX, SRX in switching/routing) | `show configuration \| display set`, or braces | `set` commands, for `load set` | 2 |
| `nxos` | Cisco NX-OS | `show running-config` | CLI configuration | 2 |
| `aoscx` | HPE Aruba AOS-CX (10.x) | `show running-config` | CLI configuration | 1 (done) |
| `aoss` | HPE Aruba AOS-S (ProCurve / ProVision, 16.x) | `show running-config` | CLI configuration | 1 (done) |
| `comware` | HPE Comware 7 (FlexFabric, 5130/5140/5510...) | `display current-configuration` | system-view commands | 1 (done) |

Every reader writes to the model and every writer reads from it, so each new
platform converts to and from all the others.

## Configuration areas

| Area | Model | Milestone |
|---|---|---|
| System: hostname, domain, banner, DNS, NTP, syslog, time zone | `System` | 1 |
| NTP authentication keys, trusted keys, preferred server, source interface | `System.ntp_*`, `NtpKey` | 2 (done) |
| VLANs | `Vlan` | 1 |
| Interfaces: physical, LAG, SVI, loopback, management, subinterfaces | `Interface` | 1 |
| Switchport: access, trunk, native, allowed, voice VLAN | `Interface` | 1 |
| Link aggregation and LACP | `Interface.lag`, `lacp_mode` | 1 |
| IPv4/IPv6 addressing, DHCP relay, VRFs | `Interface`, `Device.vrfs` | 1 |
| Static routes | `StaticRoute` | 1 |
| DHCP server: pools, ranges and exclusions, gateways, DNS, domain, lease | `DhcpPool` | 2 (done) |
| Gateway redundancy: HSRP, VRRP, anycast gateways (IPv4) | `FhrpGroup` | 2 (done) |
| Spanning tree mode, edge ports, BPDU guard | `Device.stp_mode`, `Interface` | 2 |
| OSPFv2: processes per VRF, areas and area types, passive interfaces, redistribution, cost, network type | `Ospf`, `Interface.ospf_cost` | 2 (done) |
| BGP: neighbors, peer groups, IPv4/IPv6 activation, networks, redistribution | `Bgp`, `BgpNeighbor` | 2 (done) |
| Access lists (IPv4 and IPv6) and their interface bindings | `Acl`, `AclEntry`, `Interface.acl_in` ... | 2 (done) |
| NAT: pools, dynamic source NAT and PAT, one-to-one and port forwarding rules, inside/outside interfaces | `NatPool`, `NatRule`, `Interface.nat` | 2 (done) |
| Site-to-site IPsec VPN: IKE proposals, transform sets, crypto maps, IPsec profiles on tunnel interfaces, pre-shared keys | `IkePolicy`, `IpsecTransform`, `IpsecPeer`, `PreSharedKey`, `Interface.tunnel_*` | 2 (done) |
| SNMP: communities with access and ACL, location, contact, notification hosts (v1/v2c/v3, traps or informs), v3 groups and users, source interface | `Snmp`, `SnmpCommunity`, `SnmpHost`, `SnmpGroup`, `SnmpUser` | 2 (done) |
| Local users, privilege levels and roles, enable secret | `LocalUser`, `Aaa.enable_secret` | 3 (done) |
| AAA: RADIUS and TACACS+ servers, server groups, login/enable/exec/command method lists, source interfaces | `Aaa`, `AaaServer`, `AaaGroup`, `AaaMethod` | 3 (done) |
| LDAP, Kerberos, TFTP/FTP, 802.1X | to come | 3 |
| Route maps, prefix lists, QoS, MLAG/VSX/vPC, VXLAN/EVPN | to come | 3+ |

### AOS-S specifics

* VLANs list their ports (`untagged 1-3,Trk1`, `tagged 49`); the reader turns that into access and trunk ports and
  the writer gathers the ports back per VLAN. A port in no VLAN is untagged in VLAN 1.
* A port untagged in a data VLAN and tagged only in a VLAN marked `voice` is an access port with a voice VLAN.
* Link aggregations are `trunk 47-48 trk1 lacp`; `Trk1` is the port-channel.
* AOS-S has no routed ports: the writer puts such a port untagged in a VLAN of its own (3999 downwards) and the
  address on that VLAN. It has no VRFs either: their interfaces and routes go in the one routing table, reported.
* The out-of-band port is the `oobm` block; a layer 2 switch with a single default route gets `ip default-gateway`.
* Time zones are a fixed offset in minutes (`time timezone 60`), read as `UTC+01:00`; IOS takes the same offset,
  a tz database zone (EOS, AOS-CX) does not convert to it and is reported.

### Comware specifics

* Blocks are separated by `#` and global lines are indented by one space; `undo` is Comware's `no`.
* A trunk permits only VLAN 1 until told otherwise (`port trunk permit vlan 10 20 30 to 40`), and its native VLAN
  is the PVID. The writer removes VLAN 1 with `undo port trunk permit vlan 1` when the source does not allow it.
* A hybrid port untagged in a data VLAN and tagged in its voice VLAN (`voice-vlan 20 enable`) is an access port
  with a voice VLAN, and the writer writes such ports that way.
* `Bridge-Aggregation` is a layer 2 port-channel and `Route-Aggregation` a layer 3 one;
  `link-aggregation mode dynamic` means LACP.
* BPDU protection is global (`stp bpdu-protection`) and guards every edge port.
* VRFs are VPN instances, the management VRF included: `M-GigabitEthernet0/0/0` is bound to one like any port.

## Access lists

* Every ACL becomes an extended list: protocol, source, destination, ports (`eq`, `range`, `gt`, `lt`), ICMP type,
  `established` and `log`. Standard lists become extended lists with `ip` and `any` destination.
* An entry with several ports, or a range the target can't write in one line, is split into one entry per port.
  The report marks that as approximated.
* Sequence numbers are kept when every entry keeps its own line; otherwise the list is renumbered in steps of 10
  (5 on Comware).
* Entries the model can't hold (object groups, `neq`, non-contiguous wildcards) are written as a remark and flagged
  for review, so the rule count and order stay visible.
* Bindings: `ip access-group` / `ipv6 traffic-filter` (IOS, EOS), `apply access-list` (AOS-CX, `routed-in` on VLAN
  interfaces), `ip access-group` in the interface or VLAN (AOS-S), `packet-filter` (Comware).

## Gateway redundancy

* HSRP exists only on IOS. On every other target an HSRP group becomes a VRRP group with the same number (1-255;
  group 0 or above 255 takes a free number), priority and virtual addresses. HSRP does not preempt by default and
  VRRP does, so the writer states preemption explicitly. The report marks the change, because every router of a
  group has to move at once.
* Anycast gateways (Arista VARP `ip virtual-router address`, AOS-CX `active-gateway`) convert between EOS and AOS-CX
  with their shared MAC. Elsewhere they become a VRRP group, flagged for review: one router forwards instead of both.
* Intervals are kept in milliseconds and rounded to the target's unit (seconds on EOS and AOS-S, centiseconds on
  Comware); a rounding is reported. The HSRP hold time has no VRRP equivalent.
* VRRP version: Comware 7 runs VRRPv3 unless `vrrp version 2` is set, and IOS XE needs `fhrp version vrrp v3` and the
  `vrrp N address-family ipv4` form for v3. The writers carry the version across; AOS-S runs VRRPv2 only.
* AOS-S writes the group inside its VLAN, as `owner` when the virtual address is the VLAN's own, and switches on
  `ip routing` and `router vrrp`.
* Authentication, tracking, preempt delays and IPv6 groups are listed under "Not understood" for now (secrets
  masked).

## OSPF

* A process keeps its number, router ID, VRF, network statements, interface areas, passive interfaces (default
  passive with exceptions, or the other way round), stub and NSSA areas, redistribution of connected, static and BGP
  routes, default-route origination and reference bandwidth. Interfaces keep their cost and network type.
* IOS, EOS and Comware write network statements as they are. AOS-CX and AOS-S have none: the writer puts the area on
  every interface a statement matches (the most specific one wins) and the report says so, because an interface added
  later is not picked up.
* Areas are kept in dotted form; IOS shows them as numbers (`area 0`), AOS-S calls the backbone `backbone`.
* AOS-S runs one process in one routing table, without NSSA, default-route origination or reference bandwidth;
  what it can't hold is flagged. Its router ID is the global `ip router-id`.
* Authentication, timers, summaries, virtual links and redistribution through route maps are listed under "Not
  understood" for now.

## BGP

* The one BGP process of the global routing table: local AS, router ID, neighbors and peer groups (remote AS,
  description, update source, eBGP multihop, shutdown, next-hop-self, send-community), the address families each
  neighbor is active in, networks and redistribution of connected, static and OSPF routes, for IPv4 and IPv6.
* IOS and EOS activate IPv4 neighbors by default; the reader follows `no bgp default ipv4-unicast`, and the writers
  switch the default off and activate every neighbor where it belongs. AOS-CX and Comware list each activation.
* AOS-CX has no peer groups here: a group's settings are written on each member, and the report says so. Comware
  groups are `group NAME internal|external`.
* AOS-S is not written: its BGP depends on the model and release, and the report asks a person to configure it.
* Passwords, timers, route maps, prefix lists, communities other than standard, and BGP in VRFs are listed under
  "Not understood" for now (secrets masked).

## DHCP server

* A pool keeps its network, the addresses it hands out, default routers, DNS servers, domain name, lease time and
  VRF. DHCP relay (helper addresses) was already converted with the interfaces.
* IOS and Comware exclude addresses (`ip dhcp excluded-address`, `dhcp server forbidden-ip`); AOS-CX, AOS-S and EOS
  list ranges. The readers turn exclusions into ranges and the writers turn ranges back into exclusions, so both
  directions are exact.
* EOS (4.22 and later) writes `dhcp server` with a subnet per pool, and `dhcp server ipv4` on the interfaces in a
  pool's subnet. It takes one gateway per subnet and one domain name per VRF; anything more is reported.
* Pools without a network (static host bindings), DHCP options and IPv6 pools are listed under "Not understood" for
  now.

## NAT

* Source NAT from inside to outside: dynamic rules (an ACL for the sources, onto a pool or the outside interface,
  with or without PAT), one-to-one static rules and static port forwarding (TCP/UDP).
* IOS marks interfaces `ip nat inside`/`outside` and writes the rules globally. EOS and Comware put the rules on the
  outside interface (`ip nat source ...`, `nat outbound`, `nat server`, `nat static enable`). When the source names
  no inside interfaces, the IOS writer asks a person to mark them.
* Comware numbers its address groups; a named pool becomes the next free number (reported), and since an address
  group has no mask, the reader takes it from the interface subnet the addresses sit in, or asks a person to check
  the /24 that IOS and EOS are then given.
* EOS port forwarding and a Comware `nat outbound` without an ACL (which IOS and EOS cannot express) are reported
  and left out. AOS-CX and AOS-S switches have no NAT: every rule is reported, to move to a router or firewall.
* Destination NAT other than port forwarding, NAT for IPv6 (NAT64, NPTv6), route maps in NAT rules and NAT
  timeouts are listed under "Not understood" for now.

## NTP and SNMP

* NTP servers keep their key and the preferred server; keys keep their algorithm and trust, and `ntp authenticate`
  carries over. AOS-S has no preferred server (it is listed first) and switches from SNTP to NTP when keys are used.
  AOS-CX and AOS-S pick the NTP and SNMP source interface themselves; a source interface is reported there.
* SNMP communities keep read-only or read-write access and, on IOS, EOS and Comware, their ACL. AOS-S writes
  read-only as `operator restricted` and read-write as `manager unrestricted`.
* Notification hosts keep their version, community or user, traps or informs, and VRF. `snmp-server enable traps`
  with a list of trap types is written as all traps. AOS-S takes v1/v2c hosts only; SNMPv3 targets are reported.
* SNMPv3 users keep their group, authentication and privacy algorithms and keys. AOS-CX has no groups, AOS-S has
  fixed ones (`managerpriv`, ...); both are reported. MIB views are reported, not converted.
* Communities and keys in clear text are carried over. Encrypted ones (Comware cipher, AOS-CX ciphertext, EOS
  localized keys, IOS and EOS type 7 NTP keys) become `CHANGE-ME`, and the report asks for them. The report never
  shows a community or key: communities are numbered (`community #1 (ro)`).

## Users and AAA

* Local users keep their name, privilege and password. A clear-text password (and an IOS type 7 one, which is
  reversible) goes to every platform. A hash goes only where the target takes the same kind: md5-crypt to IOS and
  EOS, sha512-crypt to EOS, IOS type 8/9 to IOS, AOS-S SHA-1 and Comware hashes to their own platform.
  Any other user is reported and left out: RouterShift never invents a password.
* Privilege levels map to roles: 15 is `network-admin` (EOS, Comware) or `administrators` (AOS-CX), 1 is
  `network-operator`/`operators`. Comware keeps other levels as `level-N` roles; AOS-S has one manager and one
  operator user, so further users are reported.
* The enable secret becomes `enable secret` (IOS), `enable password` (EOS) or `super password role network-admin`
  (Comware). AOS-CX and AOS-S have none; it is reported.
* RADIUS and TACACS+ servers keep their address, ports, timeout, VRF and key; server groups keep their members.
  IOS writes `radius server`/`tacacs server` blocks and sets the VRF on the group; Comware writes a `radius scheme` or
  `hwtacacs scheme` per group (and one for the servers in no group). Encrypted keys become `CHANGE-ME`, as for SNMP.
* Method lists for login authentication, enable, exec and command authorization, and exec and command accounting
  carry over where the target has them. Comware puts them in `domain system` (one scheme, then local or none;
  commands through HWTACACS only) and adds `line vty 0 63` with `authentication-mode scheme`. AOS-CX has no enable or
  exec authorization (a user's group gives the rights); AOS-S has per-access authentication and two methods at most.
  Named lists (applied to lines) are reported.
* The source interface for RADIUS and TACACS+ carries over; Comware takes the address (`nas-ip`) instead.

## Site-to-site VPN (IPsec)

* A connection is a crypto map entry (policy-based: a peer and an ACL for the traffic) or an IPsec profile used by
  tunnel interfaces (route-based). Each keeps its peer, ACL, transform sets, PFS group, SA lifetime and IKE version;
  IKE proposals keep their algorithms, Diffie-Hellman groups and lifetime.
* IOS: `crypto isakmp policy`/`key`, `crypto ikev2 proposal`/`policy`/`keyring`/`profile`, `crypto ipsec
  transform-set`/`profile`, `crypto map`, and `tunnel protection ipsec profile`. IKEv2 is written with one keyring
  and one IKEv2 profile per connection.
* EOS (`ip security`: IKE policies, SA policies, profiles) does route-based VPNs only, so crypto maps are reported.
  EOS counts lifetimes in hours; other values are rounded and reported.
* Comware 7: `ike proposal`/`keychain`/`profile`, `ipsec transform-set`/`policy`/`profile`, `ipsec apply policy`,
  and `interface Tunnel N mode ipsec|gre`. PFS lives on the transform set there. Only IKEv1 is written for Comware so
  far; IKEv2 connections are reported.
* Algorithms a platform lacks are replaced by the next stronger one, with a note that the peer must change too.
* Pre-shared keys in clear text are carried over. Encrypted keys (IOS type 6/7, Comware cipher, EOS type 7) cannot be
  read on another device, so `CHANGE-ME` is written in their place and the report asks for the key. The report
  never shows a key.
* AOS-CX and AOS-S do not terminate IPsec: every connection and tunnel interface is reported.
* Certificate authentication, DPD, NAT traversal settings, IPv6 IPsec, GRE tunnel options (keys, MTU) and IKEv2 on
  Comware are listed under "Not understood" or reported for now.

## Port names

### AOS-CX specifics

* Ports start shut down on AOS-CX, so the writer says `shutdown` or `no shutdown` on every port.
* A voice VLAN is a VLAN marked `voice` and tagged on a port whose native VLAN is the data VLAN. The reader turns
  such a port into an access port with a voice VLAN, and the writer does the reverse.
* The management port is always in VRF `mgmt`; a default route in that VRF becomes its `default-gateway`.
* LACP is set on the LAG, not on its members.
* AOS-CX counts the slot of the fixed ports from 1 and IOS from 0, so `1/1/7` becomes `GigabitEthernet1/0/7`.

## Port names

Each platform names ports its own way (`GigabitEthernet1/0/1`, `Ethernet1`,
`ge-0/0/0`, `1/1/1`, `A1`). Readers store a canonical name and keep the source
name; writers turn the canonical name into the target's through a port map. A
default map covers like-for-like moves; for a real migration the user gives a
map file, because the new hardware rarely has the same port layout.

## What is never lost

A line no reader section understands goes into `Device.unparsed` and shows up in
the report under "Not understood". Secrets (password hashes, SNMP communities,
keys) are carried only when the target accepts the same form, and are never
printed in a report.

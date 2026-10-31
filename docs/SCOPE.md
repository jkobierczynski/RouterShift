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
| Spanning tree: mode, bridge priorities (per instance or per VLAN), MST region, edge ports, BPDU guard and filter, root and loop guard, port cost and priority | `Device.stp_mode`, `Stp`, `Interface.stp_*` | 3 (done) |
| OSPFv2: processes per VRF, areas and area types, passive interfaces, redistribution, cost, network type | `Ospf`, `Interface.ospf_cost` | 2 (done) |
| BGP: neighbors, peer groups, IPv4/IPv6 activation, networks, redistribution | `Bgp`, `BgpNeighbor` | 2 (done) |
| Access lists (IPv4 and IPv6) and their interface bindings | `Acl`, `AclEntry`, `Interface.acl_in` ... | 2 (done) |
| NAT: pools, dynamic source NAT and PAT, one-to-one and port forwarding rules, inside/outside interfaces | `NatPool`, `NatRule`, `Interface.nat` | 2 (done) |
| Site-to-site IPsec VPN: IKE proposals, transform sets, crypto maps, IPsec profiles on tunnel interfaces, pre-shared keys | `IkePolicy`, `IpsecTransform`, `IpsecPeer`, `PreSharedKey`, `Interface.tunnel_*` | 2 (done) |
| SNMP: communities with access and ACL, location, contact, notification hosts (v1/v2c/v3, traps or informs), v3 groups and users, source interface | `Snmp`, `SnmpCommunity`, `SnmpHost`, `SnmpGroup`, `SnmpUser` | 2 (done) |
| Local users, privilege levels and roles, enable secret | `LocalUser`, `Aaa.enable_secret` | 3 (done) |
| AAA: RADIUS and TACACS+ servers, server groups, login/enable/exec/command method lists, source interfaces | `Aaa`, `AaaServer`, `AaaGroup`, `AaaMethod` | 3 (done) |
| 802.1X and MAC authentication on ports: host mode, reauthentication, the RADIUS servers used | `Aaa.dot1x`, `Interface.dot1x`, `Interface.mab` ... | 3 (done) |
| TFTP and FTP client source interface | `System.transfer_source` | 3 (done) |
| QoS: classes (DSCP or ACL), policies with DSCP marking and policing, policies on ports, port trust | `QosClass`, `QosPolicy`, `QosAction`, `Interface.qos_*` | 3 (done) |
| MPLS: label switching with LDP on interfaces, the LDP router ID | `Mpls`, `Interface.mpls` | 3 (done) |
| WLAN: SSIDs with their VLAN, security (open, WPA2-PSK, WPA2-Enterprise) and state, on IOS XE and Comware controllers | `Wlan` | 3 (done) |
| Management access: SSH, Telnet, HTTP and HTTPS servers, remote login ACL and idle timeout, syslog level and source, LLDP and CDP | `Management`, `System.logging_*`, `Interface.lldp_*` | 3 (done) |
| L2 security: DHCP snooping and ARP inspection (per VLAN, trusted ports), IP source guard, port security, storm control | `Vlan.dhcp_snooping`, `Vlan.arp_inspection`, `Interface.dhcp_trust` ... | 4 (done) |
| LDAP and Kerberos servers (listed under "Not understood") | to come | 3+ |
| VRF route leaking: route distinguisher, import and export route targets | `VrfInfo` | 4 (done) |
| Multi-chassis LAG: EOS MLAG and AOS-CX VSX (peer link, keepalive, shared LAGs) | `Mlag`, `Interface.mlag_id` | 4 (done) |
| Prefix lists and route maps (Comware route policies), on BGP neighbors and redistribution | `PrefixList`, `RouteMap`, `BgpNeighbor.route_map_*` | 4 (done) |
| Policy-based routing (route map on an interface; EOS pbr policy, Comware policy-based-route) | `Interface.pbr` | 4 (done) |
| BFD: interface timers, BGP neighbors, OSPF interfaces | `Interface.bfd_*`, `BgpNeighbor.bfd`, `Ospf.bfd_all` | 4 (done) |
| vPC (NX-OS), VXLAN/EVPN | to come | 3+ |

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

## Spanning tree

* The mode carries over where the target has it (IOS has no RSTP and writes rapid PVST+; AOS-CX has no RSTP and
  writes MSTP; PVST+ becomes the rapid variant).
* Bridge priorities follow the mode the target runs: per MST instance (instance 0 for STP and RSTP) or per VLAN for
  PVST. MST priorities going to PVST are written for each VLAN defined, through the instance the VLAN is in (reported).
  Per-VLAN priorities going to MST become one priority for the common tree; when they differed the lowest is written
  and the report suggests MST instances for load sharing.
* The MST region (name, revision, instance-to-VLAN map) is written where the target runs MSTP and reported otherwise.
* AOS-CX and AOS-S count bridge priorities in steps of 4096 and port priorities in steps of 16; the readers and writers
  convert to and from 0-61440 and 0-240.
* Ports keep root and loop guard, BPDU filter, cost and port priority. AOS-S has no loop guard (reported, with
  `loop-protect` as the alternative).
* Per-instance and per-VLAN port costs and priorities, and timers (hello, forward delay, max age), are listed under
  "Not understood" for now.

## Layer 2 security

* DHCP snooping keeps its VLANs and trusted ports, ARP inspection its VLANs and trusted ports; ports keep IP source
  guard, port security (MAC limit, violation mode) and storm control levels (percent).
* IOS and EOS: `ip dhcp snooping [vlan]`, `ip arp inspection vlan`, `ip dhcp snooping trust`, `ip arp inspection
  trust`, `ip verify source`, `switchport port-security [maximum|violation]`, `storm-control ... level`. AOS-CX:
  `dhcpv4-snooping` (global and per VLAN), `arp inspection` per VLAN, `... trust`, `ipv4 source-lockdown`,
  `port-access port-security` with `client-limit`. AOS-S: `dhcp-snooping [vlan|trust]`, `arp-protect [vlan|trust]`,
  `ip source-lockdown`, `port-security PORTS learn-mode static address-limit N action ...`, `broadcast-limit`.
  Comware: `dhcp snooping enable` (every VLAN), `arp detection enable` per VLAN, `... trust`, `ip verify source`,
  `port-security port-mode autolearn` with `max-mac-count` and `intrusion-mode`, `*-suppression`.
* Violation modes: shutdown, restrict (drop and report) and protect (drop). Each reader fills in its platform's
  default; EOS has no restrict (protect is written), AOS-S maps them to send-disable, send-alarm and none, Comware to
  disableport and blockmac (protect is the default). AOS-CX violation actions are left to a person (reported).
* Reported limits: EOS DHCP snooping only adds option 82, so its trusted ports are not written; Comware snoops every
  VLAN, and from Comware the VLANs defined are listed; IOS limits all unicast and the others unknown unicast; AOS-S
  limits broadcast only, and AOS-S and Comware take whole percents; AOS-CX rate-limits in kbps or pps, so storm
  control is left to a person.

## Prefix lists and route maps

* Prefix lists keep their sequence numbers, actions, prefixes and length ranges (ge, le); IPv4 and IPv6. IOS and AOS-CX
  write one line per entry, EOS a block, Comware `ip prefix-list NAME index N permit A LEN greater-equal X
  less-equal Y`.
* Route maps keep their numbered entries (permit, deny), descriptions, matches (prefix lists, ACLs, tags) and sets:
  local preference, metric (MED, OSPF cost), weight, tag, next hop, origin, AS path prepend and communities (with
  additive). Comware writes them as route policies: `if-match`, and `apply local-preference|cost|preferred-value|tag|
  ip-address next-hop|origin|as-path ... additive|community`.
* BGP neighbors and peer groups keep their route maps and prefix lists in and out (Comware `peer X route-policy|
  prefix-list NAME import|export`), and BGP and OSPF redistribution its route map (Comware `import-route ...
  route-policy`).
* Reported limits: EOS, AOS-CX and Comware match one prefix list, ACL or tag per entry (the first is written); AOS-CX
  route maps match no ACLs (the entry is written without the match); AOS-S writes no prefix lists or route maps, and
  its OSPF redistribution goes without the route map. Other match and set clauses (continue, communities lists, ...)
  are listed under "Not understood".

## Policy-based routing and BFD

* PBR is a route map on the interface, with entries that match ACLs and set a next hop. IOS: `ip policy route-map`.
  EOS: `service-policy type pbr input P` with `policy-map type pbr` and a `class-map type pbr` per entry (read back
  as a route map, entries numbered 10, 20, ...). Comware: `ip policy-based-route P` with `policy-based-route P
  permit node N`, `if-match acl name`, `apply next-hop`. A route map used only for PBR is written in the PBR form only.
* Reported limits: deny entries, and matches or sets other than ACLs and the next hop, are left out of EOS and
  Comware PBR policies; AOS-CX (PBR action lists) and AOS-S leave PBR to a person.
* BFD keeps its interface timers (IOS `bfd interval T min_rx R multiplier M`, EOS `min-rx`; AOS-CX and Comware
  `bfd min-transmit-interval`, `min-receive-interval`, `detect-multiplier`), BGP neighbors (IOS and AOS-CX
  `fall-over bfd`, EOS `bfd`, Comware `peer X bfd`) and OSPF (IOS `ip ospf bfd` or `bfd all-interfaces`, EOS
  `ip ospf neighbor bfd` or `bfd default`, AOS-CX `ip ospf bfd` or `bfd all-interfaces` with global `bfd`, Comware
  `ospf bfd enable` on each OSPF interface). AOS-S has no BFD (reported).

## VRF route leaking

* Each VRF keeps its route distinguisher and its import and export route targets. A target both imported and exported
  is written as `both` where the platform has it.
* IOS: `vrf definition` (or `ip vrf`) with `rd` and `route-target import|export|both`, directly or under
  `address-family ipv4`. EOS: `rd` and `route-target import|export vpn-ipv4` under `vrf V` in `router bgp`. AOS-CX:
  `rd` and `address-family ipv4 unicast` / `route-target import|export|both` in the `vrf` block. Comware:
  `route-distinguisher` and `vpn-target V import-extcommunity|export-extcommunity|both` in `ip vpn-instance`.
* Reported limits: AOS-S has no VRFs; EOS needs `router bgp` for them (without BGP they are left out); the AOS-CX
  management VRF takes none.

## Multi-chassis LAG (MLAG, VSX)

* The pair keeps its peer link, its keepalive (peer address and source interface) and the LAGs shared by both
  switches.
* EOS: `mlag configuration` with `domain-id`, `local-interface`, `peer-address` and `peer-link`, and `mlag N` on a
  port channel. AOS-CX: `vsx` with `inter-switch-link lag N`, `role` and `keepalive peer A source B [vrf V]`, and
  `interface lag N multi-chassis`.
* Reported limits: VSX has no domain name and EOS no role (primary is written to AOS-CX, to be swapped on the peer);
  the EOS peer address on the peer-link SVI becomes the VSX keepalive, which VSX prefers outside the inter-switch
  link. IOS (StackWise Virtual), AOS-S (distributed trunking) and Comware (IRF, DRNI) pair switches in other ways,
  left to a person.

## Management access, logging, LLDP and CDP

* What the source states is converted; what it leaves to the platform default stays unwritten, so the target keeps
  its own default.
* IOS: `ip ssh version 2`, `[no] ip http server|secure-server`, `line vty` with `transport input`, `access-class` and
  `exec-timeout` (the writer uses `line vty 0 15` and asks for the host key to be generated). EOS: `management ssh`
  (`ip access-group`, `idle-timeout`, `vrf V`), `management telnet`. AOS-CX: `ssh server vrf`, `https-server vrf`,
  `cli-session timeout`. AOS-S: `[no] ip ssh`, `[no] telnet-server`, `web-management plaintext|ssl`, `console
  idle-timeout` (in seconds). Comware: `ssh server enable`, `telnet server enable`, `ip http(s) enable`, and
  `protocol inbound` and `idle-timeout` on `line vty 0 63`.
* Reported limits: AOS-CX has no Telnet or plain HTTP server, EOS no web interface (its eAPI is not converted). Only
  IOS and EOS take an ACL on remote logins; AOS-CX (control-plane ACL), AOS-S (`ip authorized-managers`) and Comware
  (`ssh server acl` by number) are left to a person. AOS-S and Comware have no management VRF for the servers.
* Syslog keeps its level (IOS and EOS `logging trap`, AOS-CX `severity` per server, AOS-S `logging severity` with five
  levels, the nearest one that sends at least as much; Comware `info-center source default loghost level`) and its
  source interface.
* LLDP on or off, and per port transmit and receive (`no lldp transmit|receive`, AOS-S `lldp admin-status PORTS
  txonly|rxonly|disable`, Comware `lldp admin-status tx|rx|disable`). CDP is kept on IOS and AOS-S; EOS, AOS-CX and
  Comware have none and report it (LLDP announces the switch).
* Console and AUX lines, banners other than the MOTD, logging buffers, facilities and timestamps, and SSH ciphers are
  listed under "Not understood" for now.

## Wireless (WLAN)

* Only IOS XE (Catalyst 9800 and embedded wireless controllers) and Comware (WX controllers) carry wireless networks.
  On EOS, AOS-CX and AOS-S every WLAN is reported with its VLAN and security, and left out; RouterShift does not guess
  a wireless configuration for a switch.
* A WLAN keeps its SSID, VLAN, security (open, WPA2-PSK, WPA2-Enterprise with 802.1X) and whether it is enabled. A
  clear-text pre-shared key carries over; an encrypted one becomes `CHANGE-ME` (reported).
* IOS XE: `wlan NAME ID SSID` (WPA2 with 802.1X unless the `security wpa` lines say otherwise), the VLAN through
  `wireless tag policy` and `wireless profile policy`. The writer adds a policy profile per WLAN with a VLAN and one
  tag, `RS-POLICY-TAG`, to assign to the access points (reported).
* Comware: `wlan service-template` with `ssid`, `vlan`, `akm mode`, `preshared-key`, `service-template enable`.
  Binding the templates to the AP radios is left to a person (reported).
* RF profiles, AP groups and tags, radio settings, guest portals, WPA3 and per-WLAN RADIUS lists are listed under "Not
  understood" for now. Other wireless platforms (Aruba controllers and Instant, Juniper Mist) are outside the five
  platforms converted today.

## MPLS

* An interface keeps MPLS label switching with LDP, and the device keeps LDP and its router ID.
* IOS: `mpls label protocol ldp`, `mpls ldp router-id IFACE force`, `mpls ip` on the interface. EOS: `mpls ip` and an
  `mpls ldp` block with `router-id [interface]`; the writer adds `interface disabled default` so LDP runs only on the
  interfaces with `mpls ldp interface`. Comware: `mpls lsr-id`, the `mpls ldp` view, `mpls enable` and `mpls ldp
  enable` on the interface.
* IOS takes the router ID as an interface and Comware as an address: the writers use the interface that holds the
  address, or the address of the interface (reported when there is none).
* AOS-CX and AOS-S have no MPLS; it is reported.
* MPLS L3VPN (VRF route distinguishers and targets, VPNv4 BGP), RSVP-TE, segment routing and LDP options (timers,
  authentication, label filters) are listed under "Not understood" for now.

## QoS

* A class matches DSCP values or an ACL, all or any; a policy gives each class a DSCP marking and a police rate
  (conform transmits, exceed drops). Policies keep their direction on ports and VLAN interfaces, and ports keep their
  trust (DSCP, CoS/802.1p, none).
* IOS: `class-map match-all|match-any`, `policy-map` with `set dscp` and `police cir` (in bps), `service-policy
  input|output`, `mls qos trust`. EOS: `class-map type qos`, `policy-map type quality-of-service`, `police rate ...
  kbps`, `qos trust`. AOS-CX: `class ip` and `policy` entries with `action dscp` and `action cir kbps`, `apply policy`.
  AOS-S: `class ipv4` and `policy qos` with `action rate-limit kbps`, `service-policy`. Comware: `traffic classifier`,
  `traffic behavior` (`remark dscp`, `car cir`) and `qos policy`, `qos apply policy`; the writer adds one behavior
  per class, named after the policy and class.
* AOS-CX and AOS-S classes hold their own match entries: an ACL class is written entry by entry (deny becomes
  `ignore`), and the reader turns them back into an ACL, reusing an existing ACL with the same entries.
* Police bursts are not converted; where a burst is needed it is written as 1/8 s of the rate (reported).
* Limits are reported: AOS-CX has no default class in a policy, EOS applies QoS policies inbound only, EOS classes are
  match-any, and IOS on a Catalyst 9000 trusts DSCP by default (other trust settings are reported, not written).
* Queuing, shaping, priority queues, CoS marking and DSCP maps are listed under "Not understood" for now.

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
* LDAP and Kerberos are not converted yet; their lines are listed under "Not understood".

## 802.1X and MAC authentication

* A port keeps 802.1X, MAC authentication (MAB), its host mode and reauthentication with its period; the device keeps
  802.1X switched on and the RADIUS group ports authenticate against.
* IOS: `authentication host-mode`/`port-control auto`/`periodic`/`timer reauthenticate`, `mab`, `dot1x pae
  authenticator` (`access-session` is read too), `dot1x system-auth-control`, `aaa authentication dot1x`.
* EOS: `dot1x pae authenticator`, `dot1x host-mode single-host|multi-host [authenticated]` (multi-auth is
  `multi-host authenticated`), `dot1x mac based authentication`, `dot1x reauthentication`.
* AOS-CX: `aaa authentication port-access` with `client-limit` and `auth-mode` (client mode with one client is
  single-host, device mode is multi-host) and the `dot1x authenticator` and `mac-auth` blocks.
* AOS-S: `aaa port-access authenticator PORTS` (no client limit opens the port for all, multi-host; a limit of 1 is
  single-host), `aaa port-access mac-based PORTS`, `aaa authentication port-access eap-radius`.
* Comware: `dot1x` and `mac-authentication` on the port (MAC-based access with `max-user 1` is single-host,
  `port-method portbased` multi-host), `dot1x re-authenticate`, one global `dot1x timer reauth-period`, and
  `authentication lan-access radius-scheme` in `domain system`.
* Multi-auth becomes a client limit of 32 where the platform counts clients (reported); multi-domain becomes multi-auth
  where the platform has no voice domain on the port (reported).
* TFTP and FTP keep their client source interface. AOS-CX and AOS-S have no FTP client setting (reported), and AOS-S
  takes a VLAN or loopback as TFTP source.

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

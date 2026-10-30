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
| VLANs | `Vlan` | 1 |
| Interfaces: physical, LAG, SVI, loopback, management, subinterfaces | `Interface` | 1 |
| Switchport: access, trunk, native, allowed, voice VLAN | `Interface` | 1 |
| Link aggregation and LACP | `Interface.lag`, `lacp_mode` | 1 |
| IPv4/IPv6 addressing, DHCP relay, VRFs | `Interface`, `Device.vrfs` | 1 |
| Static routes | `StaticRoute` | 1 |
| Gateway redundancy: HSRP, VRRP, anycast gateways (IPv4) | `FhrpGroup` | 2 (done) |
| Spanning tree mode, edge ports, BPDU guard | `Device.stp_mode`, `Interface` | 2 |
| OSPFv2: processes per VRF, areas and area types, passive interfaces, redistribution, cost, network type | `Ospf`, `Interface.ospf_cost` | 2 (done) |
| BGP | `Bgp`, `BgpNeighbor` | 2 |
| Access lists (IPv4 and IPv6) and their interface bindings | `Acl`, `AclEntry`, `Interface.acl_in` ... | 2 (done) |
| SNMP, local users | `Snmp`, `LocalUser` | 2 |
| Route maps, prefix lists, AAA/TACACS/RADIUS, QoS, MLAG/VSX/vPC, VXLAN/EVPN | to come | 3+ |

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

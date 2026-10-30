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
| `comware` | HPE Comware (FlexFabric, 5130/5510...) | `display current-configuration` | CLI configuration | 3 |

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
| Spanning tree mode, edge ports, BPDU guard | `Device.stp_mode`, `Interface` | 2 |
| OSPFv2 | `Ospf` | 2 |
| BGP | `Bgp`, `BgpNeighbor` | 2 |
| Access lists, standard and extended | `Acl`, `AclEntry` | 2 |
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

# Scope

RouterShift reads the running configuration of a switch or router, turns it into a
vendor-neutral model (`src/routershift/model.py`), and writes it out for another
platform, with a report that says item by item what was converted exactly, what was
approximated and what a person has to look at.

## Platforms

| Key | Platform | Read | Write | Milestone |
|---|---|---|---|---|
| `ios` | Cisco IOS and IOS XE | `show running-config` | CLI configuration | 1 |
| `eos` | Arista EOS | `show running-config` | CLI configuration | 1 |
| `junos` | Juniper Junos (EX, QFX, MX, SRX in switching/routing) | `show configuration \| display set`, or braces | `set` commands, for `load set` | 2 |
| `nxos` | Cisco NX-OS | `show running-config` | CLI configuration | 2 |
| `aoscx` | HPE Aruba AOS-CX | `show running-config` | CLI configuration | 2 |
| `aoss` | HPE Aruba AOS-S (ProCurve / ProVision) | `show running-config` | CLI configuration | 3 |
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

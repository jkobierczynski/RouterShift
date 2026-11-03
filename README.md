# RouterShift

Multi-vendor network device configuration converter. It reads a switch or router
configuration, turns it into a vendor-neutral model, and writes it out for another
platform, together with a report that says, item by item, what was converted
exactly, what was approximated and what a person has to look at.

It handles eight platforms from Cisco, Arista, Juniper and HPE (Aruba and Comware): see [Status](#status).
The [manual](docs/MANUAL.md) explains how to use it, [docs/SCOPE.md](docs/SCOPE.md) lists what converts per area and platform,
[CONTRIBUTING.md](CONTRIBUTING.md) explains how to help and [CHANGELOG.md](CHANGELOG.md)
lists the releases.

It is a quick reference for how a configuration looks on another platform, not a
migration tool: read the output and the report before anything goes near a live device.

RouterShift is the sibling of [FWShift](https://github.com/jkobierczynski/FWShift),
which does the same for firewall policies.

## Status

Alpha. The current release is the top entry of [CHANGELOG.md](CHANGELOG.md), and `routershift --version` prints
the one installed. Every platform reads and writes, so each converts to and from all the others.

### Platforms

| Platform | Key | Depth |
|---|---|---|
| Cisco IOS / IOS XE | `ios` | Full: every area below |
| Arista EOS | `eos` | Full: every area below |
| Cisco NX-OS | `nxos` | Full, plus vPC, NX-API and EEM applets |
| Juniper Junos | `junos` | Full, in curly braces or `display set` lines |
| HPE Aruba AOS-CX | `aoscx` | Full, plus VSX, VSF and the REST API |
| Cisco IOS-XR | `iosxr` | Full for what a router carries; switch features are reported |
| HPE Comware 7 | `comware` | The common areas below; deeper features not written yet ([#42](https://github.com/jkobierczynski/RouterShift/pull/42) pending) |
| HPE Aruba AOS-S (ProCurve) | `aoss` | The common areas below; deeper features not written yet ([#42](https://github.com/jkobierczynski/RouterShift/pull/42) pending) |

"Full" means the platform reads and writes the whole list below, plus the deeper settings: community and AS-path
lists, BGP options, CoPP, MACsec, MAC ACLs, PTP, SSH keys, syslog over TLS and OSPF authentication. On Comware and
AOS-S those deeper settings are reported as "not written yet" for now. [docs/SCOPE.md](docs/SCOPE.md) has the
per-platform details.

### What converts

* **System:** hostname, domain, DNS client (lookup, search domains, source, static hosts), NTP with
  authentication keys, syslog level and source, banner, time zone, TFTP/FTP source interface.
* **Layer 2:** VLANs, access and trunk ports, voice VLANs, LAGs and LACP, spanning tree (mode, priorities, MST
  region, port guards), PoE per port, IGMP snooping with its querier.
* **Layer 2 security:** DHCP snooping, ARP inspection, IP source guard, port security, storm control, 802.1X and
  MAC authentication.
* **Interfaces and addressing:** SVIs, loopbacks, the management port, subinterfaces, IPv4 and IPv6 addresses,
  DHCP relay and server.
* **Gateways:** HSRP, VRRP and anycast gateways, with tracked objects.
* **Routing:** VRFs with route leaking (RD, import and export route targets), static routes, OSPF, BGP (peer
  templates, VRFs, passwords, timers, route reflectors, prefix limits, allowas-in, remove-private-as,
  maximum-paths), RIP and IS-IS, prefix lists and route maps, policy-based routing, BFD.
* **Data centre:** VXLAN (VTEP source, VLAN and VRF VNIs, flood lists), BGP EVPN, MLAG pairs (EOS MLAG, AOS-CX
  VSX, NX-OS vPC), MPLS with LDP.
* **Multicast:** multicast routing, PIM mode, IGMP version, static RPs.
* **Security and services:** IPv4/IPv6 access lists with their bindings, NAT, site-to-site IPsec VPNs, QoS
  (classes, DSCP marking, policing, port trust).
* **Management:** local users and privilege levels, AAA (RADIUS and TACACS+ servers, groups and method lists),
  SNMP (communities, v3 users, notification hosts), SSH, Telnet and HTTP(S) servers, login ACL and idle timeout,
  LLDP and CDP.
* **Monitoring:** port mirroring (SPAN), sFlow, NetFlow (Comware NetStream, Junos J-Flow), IP SLA probes
  (Comware NQA).
* **Wireless:** SSIDs with their VLAN and security, between IOS XE and Comware controllers.

### What a platform cannot express

When the target has no form for a setting, RouterShift writes the nearest construct and flags it as
approximated, or leaves it out and reports it. The main gaps:

* **AOS-S:** no VRFs, routed ports, BGP, PIM, MPLS, NAT or IPsec.
* **AOS-CX:** no RIP, IS-IS, MPLS, NAT or IPsec.
* **Comware and AOS-S:** no VXLAN or EVPN yet; RIP and IS-IS only between IOS, EOS, NX-OS, Junos, IOS-XR and
  Comware.
* **NX-OS:** no DHCP server, PoE or IPsec.
* **Junos:** no NAT or IPsec on a switch, no RD per EVPN instance, no BFD slow timer.
* **IOS-XR:** no switch features (spanning tree, port security, 802.1X, PoE, sFlow), VXLAN, MLAG, NAT or IPsec.
* **NetFlow and sFlow:** IOS has no sFlow, and EOS, AOS-CX and AOS-S NetFlow is reported, not written.

### What is reported, not converted

Features RouterShift recognises but does not convert (telemetry, certificates, the zone-based firewall, EIGRP,
DMVPN, NBAR, ...) are listed once per feature under "Recognised, not converted", with
the reason and the line numbers. Everything else is listed under "Not understood", grouped by the block it is in,
with secrets masked.

## Usage

```
pip install routershift      # or, from a checkout: pip install .
routershift convert --from ios --to aoscx running-config.txt -o aoscx.cfg --report report.txt
routershift roundtrip --from eos --via ios running-config.txt   # there and back: what did not survive
routershift parse --from eos running-config.txt      # the vendor-neutral model as JSON
routershift platforms
```

The report says, for each item, whether it was converted **exactly**,
**approximated** (with what changed), needs **review**, or was **skipped**.

### Port maps

Ports are renumbered for the target (for example `GigabitEthernet1/0/1` becomes
`Ethernet1` on EOS) and every renumbered port is flagged in the report. To see
the output with your own port names, give a port map with `--port-map ports.txt`:

```
# source port = target port
GigabitEthernet1/0/1 = Ethernet7
TenGigabitEthernet1/1/1 = Ethernet49/1
```

## Requirements

Python 3.9 or later, no other dependencies.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).

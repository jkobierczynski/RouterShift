# RouterShift

Multi-vendor network device configuration converter. It reads a switch or router
configuration, turns it into a vendor-neutral model, and writes it out for another
platform, together with a report that says, item by item, what was converted
exactly, what was approximated and what a person has to look at.

Platforms: Cisco IOS / IOS XE and NX-OS, Arista EOS, Juniper Junos, HPE Aruba
AOS-CX, AOS-S (ProCurve) and Comware 7. The [manual](docs/MANUAL.md) explains how to
use it, [docs/SCOPE.md](docs/SCOPE.md) lists what converts per area and platform,
[CONTRIBUTING.md](CONTRIBUTING.md) explains how to help and [CHANGELOG.md](CHANGELOG.md)
lists the releases.

It is a quick reference for how a configuration looks on another platform, not a
migration tool: read the output and the report before anything goes near a live device.

RouterShift is the sibling of [FWShift](https://github.com/jkobierczynski/FWShift),
which does the same for firewall policies.

## Status

Alpha (0.1.0). Cisco IOS / IOS XE, Arista EOS, HPE Aruba AOS-CX, AOS-S (ProCurve) and
HPE Comware 7 convert in every direction for the system settings (hostname,
domain, DNS, NTP with authentication keys, syslog, banner, spanning tree (mode, priorities, MST region, port guards), SNMP
communities, v3 users and notification hosts), VLANs, interfaces
(switchport access and trunk, voice VLAN, LAGs and LACP, SVIs, loopbacks, the
management port, subinterfaces), IPv4 and IPv6 addressing, DHCP relay and server, VRFs,
static routes, IPv4/IPv6 access lists with their interface bindings, gateway
redundancy (HSRP, VRRP, anycast gateways), OSPF, BGP, NAT and site-to-site
IPsec VPNs (on IOS, EOS and Comware; the AOS switches have neither), local users and
privilege levels, and AAA (RADIUS and TACACS+ servers and groups, login, enable, command
and accounting method lists), 802.1X and MAC authentication on ports, the TFTP/FTP
source interface, QoS (classes, policies with DSCP marking and policing, port trust), MPLS with LDP
(on IOS, EOS and Comware), and wireless networks (SSID, VLAN, security) between IOS XE and Comware
controllers, flagged on the switches that have none.
Management access converts too: SSH, Telnet and HTTP(S) servers, the remote login ACL and idle timeout,
the syslog level and source, and LLDP and CDP (globally and per port).
Layer 2 security converts as well: DHCP snooping, ARP inspection, IP source guard, port security and storm
control.
VRF route leaking (route distinguisher, import and export route targets) and multi-chassis LAG pairs
(EOS MLAG and AOS-CX VSX, flagged on IOS, AOS-S and Comware) convert too.
Prefix lists and route maps (Comware route policies) convert with the BGP neighbors and
redistribution that apply them, and so do policy-based routing and BFD (timers, BGP neighbors, OSPF).
RIP and IS-IS convert between IOS, EOS and Comware (flagged on the Aruba switches).
Multicast converts too: IGMP snooping per VLAN with its querier, and multicast routing (PIM mode,
IGMP version, static RPs).
Port mirroring (SPAN) and sFlow convert on every platform; NetFlow between IOS (Flexible NetFlow)
and Comware (NetStream), and is flagged elsewhere, as is sFlow on IOS.
IP SLA probes (Comware NQA) and tracked objects convert between IOS and Comware with the static routes
and gateway groups that use them; EOS takes the interface tracks, and the rest is flagged.
The DNS client (lookup switch, search domains, source interface, static hosts) and PoE per port
(on/off, priority, power limit) convert as far as each platform has the setting.
VXLAN (VTEP source, VLAN and VRF VNIs, static flood lists) and BGP EVPN (neighbors, advertised VLANs)
convert between IOS, EOS and AOS-CX, and are flagged on AOS-S and Comware.
Juniper Junos reads and writes the core of a switch or router configuration, in either the curly-brace
form or `display set` lines: system settings (hostname, DNS, NTP with keys, syslog, time zone, banner, SSH,
local users), SNMP communities, VLANs, ports and aggregates with LACP, access and trunk ports, irb, loopback and
management interfaces, subinterfaces, IPv4/IPv6 addresses, VRFs (routing instances with RD and route targets),
static routes, OSPF, BGP (groups, EVPN family), LLDP and spanning tree (RSTP, MSTP, VSTP). Every other feature
read from another platform is listed in the report as "not written for Junos yet".
Cisco NX-OS reads through the IOS reader (with its own blocks: features, vrf context, neighbor blocks, hsrp and
vrrp blocks, use-vrf) and writes the system settings, users, SNMP communities, VLANs, ports, port-channels, SVIs,
the management port in VRF management, VRFs and their static routes, ACLs, prefix lists and route maps, HSRP and
VRRP, DHCP relay, storm control, OSPF (interface-based, VRFs in the process), BGP (neighbor blocks, EVPN family),
spanning tree (rapid PVST+, MST), LLDP and the vty settings. Everything else is reported as "not written for
NX-OS yet".
BGP covers IOS XE peer templates (written into each neighbor), BGP inside VRFs (IOS `address-family ipv4 vrf`, EOS,
NX-OS and AOS-CX `vrf`, Comware `ip vpn-instance`), session passwords, timers, route-reflector clients, prefix
limits, allowas-in, remove-private-as and maximum-paths.
What RouterShift recognises but does not convert (EEM, telemetry, certificates, the zone-based firewall, EIGRP,
DMVPN, NBAR, queuing, ...) is reported once per feature under "Recognised, not converted", with the reason and the
line numbers. Everything else is listed under "Not understood", grouped by the block it is in, with secrets masked.

## Usage

```
pip install routershift      # or, from a checkout: pip install .
routershift convert --from ios --to aoscx running-config.txt -o aoscx.cfg --report report.txt
routershift parse --from eos running-config.txt      # the vendor-neutral model as JSON
routershift platforms
```

The report says, for each item, whether it was converted **exactly**,
**approximated** (with what changed), needs **review**, or was **skipped**.

### Port maps

Ports are renumbered for the target (for example `GigabitEthernet1/0/1` becomes
`Ethernet1` on EOS) and every renumbered port is flagged in the report. For a
real migration, give a port map with `--port-map ports.txt`:

```
# source port = target port
GigabitEthernet1/0/1 = Ethernet7
TenGigabitEthernet1/1/1 = Ethernet49/1
```

## Requirements

Python 3.9 or later, no other dependencies.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).

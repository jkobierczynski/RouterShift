# RouterShift

Multi-vendor network device configuration converter. It reads a switch or router
configuration, turns it into a vendor-neutral model, and writes it out for another
platform, together with a report that says, item by item, what was converted
exactly, what was approximated and what a person has to look at.

Platforms: Cisco IOS / IOS XE, NX-OS and IOS-XR, Arista EOS, Juniper Junos, HPE Aruba
AOS-CX, AOS-S (ProCurve) and Comware 7. The [manual](docs/MANUAL.md) explains how to
use it, [docs/SCOPE.md](docs/SCOPE.md) lists what converts per area and platform,
[CONTRIBUTING.md](CONTRIBUTING.md) explains how to help and [CHANGELOG.md](CHANGELOG.md)
lists the releases.

It is a quick reference for how a configuration looks on another platform, not a
migration tool: read the output and the report before anything goes near a live device.

RouterShift is the sibling of [FWShift](https://github.com/jkobierczynski/FWShift),
which does the same for firewall policies.

## Status

Alpha: the current release is the top entry of [CHANGELOG.md](CHANGELOG.md), and `routershift --version` prints
the one installed. Cisco IOS / IOS XE, Arista EOS, HPE Aruba AOS-CX, AOS-S (ProCurve) and
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
(EOS MLAG, AOS-CX VSX and Comware M-LAG, flagged on IOS and AOS-S) convert too.
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
Juniper Junos reads and writes a switch or router configuration to the same depth as IOS and EOS, in either the
curly-brace form or `display set` lines: besides the core (system, users, SNMP, VLANs, ports and aggregates,
irb/loopback/management units, VRFs, static routes, OSPF, BGP, LLDP, spanning tree) it covers firewall filters and
policy statements, VRRP and anycast gateways, DHCP relay and server, layer 2 security, AAA and 802.1X, EVPN/VXLAN,
MC-LAG, route leaking, multicast, class of service, control-plane protection and MACsec, sFlow, J-Flow and
analyzers, SNMPv3 and login classes, PTP and event policies, BFD, ECMP hashing, OSPF options, filter-based
forwarding for PBR, RIP, IS-IS, MPLS/LDP and GRE tunnels. What Junos has no form for (an EOS route distinguisher
per EVPN instance, a BFD slow timer, NAT and IPsec on a switch, ...) is written as the nearest construct or left
out, and the report says which.
HPE Aruba AOS-CX reads and writes to the same depth as well: besides the switch core it covers anycast gateways
(active gateway), DHCP relay to another VRF, community and AS-path lists, EVPN instances with their route targets,
VSX options and VSF stacks, VRF route targets for EVPN and route leaking, BGP options (timers, graceful restart,
distance, best-path, aggregates, prefix limits), rendezvous points per VRF and MSDP, the DSCP map and schedule
profiles, control-plane ACLs and CoPP classes, MACsec and MKA policies, MAC ACLs, LLDP options, tracked objects,
banners, user groups and SSH keys, the REST API, syslog over TLS, PTP, OSPF authentication and timers, GRE tunnels
and policy-based routing as classifier policies. What AOS-CX has no form for (RIP, IS-IS, MPLS, NAT, IPsec, event
handlers, TWAMP, SNMP views, ...) is left out and reported, and the nearest construct is flagged as approximated.
Cisco NX-OS reads and writes to the same depth too: AAA servers and lists, 802.1X, DHCP snooping, port security,
SNMPv3, community and AS-path lists, VXLAN and EVPN with the anycast gateway, vPC and ethernet segments, VRF route
targets and leaking, BGP templates and options, IGMP snooping, PIM rendezvous points, anycast RP and MSDP, QoS and
queuing policies, CoPP, MACsec, MAC ACLs, NAT, SPAN, sFlow, NetFlow, IP SLA and tracking, banners, local logging,
syslog over TLS, roles, SSH keys, NX-API, PTP, EEM applets, OSPF authentication and options, BFD, ECMP hashing, RIP,
IS-IS, MPLS/LDP, GRE tunnels and PBR. What NX-OS has no form for (the DHCP server, PoE, IPsec, TWAMP, ...) is left
out and reported, and the nearest construct is flagged as approximated.
Cisco IOS-XR reads and writes to the same depth for what a router carries: AAA with TACACS+ and RADIUS groups,
SNMPv3, ACLs, prefix lists, community and AS-path lists and route maps as RPL sets and route policies, bundles and
subinterfaces, VLANs as bridge domains with BVIs, VRFs, static routes, OSPF, IS-IS, MPLS/LDP, BGP with neighbor
groups and VRFs, HSRP and VRRP, DHCP relay, PIM and IGMP, QoS policy maps, NetFlow, SPAN, IP SLA and tracking, and
the SSH, NETCONF and gRPC servers. The switch features IOS-XR has no form for (spanning tree, port security, 802.1X,
PoE, sFlow, ...) are left out and reported.
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
routershift roundtrip --from eos --via ios running-config.txt   # there and back: what did not survive
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

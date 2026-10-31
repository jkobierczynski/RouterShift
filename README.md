# RouterShift

Multi-vendor network device configuration converter. It reads a switch or router
configuration, turns it into a vendor-neutral model, and writes it out for another
platform, together with a report that says, item by item, what was converted
exactly, what was approximated and what a person has to look at.

Planned platforms: Cisco IOS / IOS XE and NX-OS, Arista EOS, Juniper Junos,
HPE Aruba AOS-CX, AOS-S (ProCurve) and Comware. See [docs/SCOPE.md](docs/SCOPE.md)
for the platforms, the configuration areas and the order they arrive in.

RouterShift is the sibling of [FWShift](https://github.com/jkobierczynski/FWShift),
which does the same for firewall policies.

## Status

Pre-alpha. Cisco IOS / IOS XE, Arista EOS, HPE Aruba AOS-CX, AOS-S (ProCurve) and
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
Everything else (IP SLA, LDAP, ...) is listed in the report under "Not understood", line by
line, with secrets masked.

## Usage

```
pip install .
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

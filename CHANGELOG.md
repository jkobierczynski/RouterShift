# Changelog

Every release of RouterShift, newest first. Versions follow [semantic versioning](https://semver.org): see
[DEVELOPMENT.md](DEVELOPMENT.md#versions-and-releases) for what bumps which number while RouterShift is below 1.0.
Each release is tagged `vX.Y.Z` in git.

Add a line under "Unreleased" in every pull request that changes what RouterShift reads, writes or reports.

## Unreleased

* Junos is written and read to the same depth as IOS and EOS: policy statements and firewall filters, port
  settings, gateways, DHCP, layer 2 security, AAA and 802.1X, EVPN/VXLAN, MC-LAG, route leaking, multicast, class
  of service, control-plane protection, MACsec, monitoring, management (login classes, SNMPv3, APIs), PTP, event
  policies, BFD, ECMP hashing, OSPF authentication and options, PBR as filter-based forwarding, RIP, IS-IS,
  MPLS/LDP and tunnels. Each converts EOS (the bl1-dc1 border leaf) to Junos and back with no line left unread;
  what Junos lacks is flagged instead of labelled exact.
* AOS-CX is written and read to the same depth as IOS and EOS: anycast gateways, relay VRFs, community and AS-path
  lists, EVPN instances, VSX options and VSF, VRF EVPN targets and leaking, BGP options, rendezvous points per VRF
  and MSDP, the DSCP map and schedule profiles, CoPP, MACsec, MAC ACLs, LLDP options, tracked objects, banners,
  user groups, SSH keys, the REST API, syslog transport, PTP, OSPF authentication and timers, GRE tunnels and PBR.
  Each converts EOS (the bl1-dc1 border leaf) to AOS-CX and back with no line left unread; what AOS-CX lacks is
  flagged instead of labelled exact.
* NX-OS is written and read to the same depth as IOS and EOS: AAA and 802.1X, SNMPv3, DHCP snooping and port
  security, community and AS-path lists, VXLAN/EVPN with the anycast gateway, vPC and ethernet segments, VRF route
  targets and leaking, BGP templates and options, multicast (IGMP snooping and querier, PIM RPs, anycast RP, MSDP),
  QoS, the DSCP map and queuing policies, CoPP, MACsec, MAC ACLs, NAT, SPAN, sFlow, NetFlow, IP SLA and tracking,
  banners, local logging, syslog over TLS, roles, SSH keys, NX-API, password length, tz database zones (offset plus
  summer-time rule), PTP, EEM applets, OSPF authentication and options, BFD, ECMP hashing, RIP, IS-IS, MPLS/LDP, GRE
  tunnels and PBR. EOS (the bl1-dc1 border leaf) converts to NX-OS with nothing left as not written yet, and every
  sample converts to NX-OS and back with no line left unread; what NX-OS lacks is flagged instead of labelled exact.
* The EOS reader reads `ip address unnumbered`.
* The text report shows the device security section (CoPP, MACsec).
* The report names the RouterShift version that wrote it: in the first line of the text report and as `version` in
  the JSON report.

## 0.1.0 (2026-11-02, first release)

The first release converts configurations between seven platforms: Cisco IOS / IOS XE, Cisco NX-OS, Arista EOS,
Juniper Junos, HPE Aruba AOS-CX, AOS-S (ProCurve) and HPE Comware 7. It writes a fidelity report beside every
conversion.

* **IOS, EOS, AOS-CX, AOS-S and Comware** cover:
  * system settings: hostname, DNS, NTP with keys, syslog, banner and time zone
  * layer 2: VLANs, access and trunk ports, voice VLANs, LAGs and LACP, spanning tree, layer 2 security,
    802.1X and MAC authentication, PoE
  * layer 3 and routing: addresses, SVIs, loopbacks, subinterfaces, VRFs with RD and route targets, static
    routes, HSRP, VRRP and anycast gateways, DHCP relay and server, OSPF, BGP with EVPN, RIP, IS-IS, prefix lists
    and route maps, policy-based routing, BFD, multicast, IP SLA and tracking, MPLS/LDP, VXLAN
  * services and management: ACLs, NAT, IPsec VPNs, QoS, users and AAA, SNMP, management access, LLDP and CDP,
    mirroring, sFlow and NetFlow, MLAG and VSX, wireless networks on controllers
* **Junos** reads and writes the core:
  * system settings, users, SNMP communities
  * VLANs, ports, aggregates, irb, loopback and management units, subinterfaces
  * VRFs, static routes, OSPF, BGP, LLDP and spanning tree
  * It takes both braces and `display set` lines.
* **NX-OS** reads through the IOS reader and writes the core:
  * system settings, users, SNMP communities
  * VLANs, ports, port-channels, SVIs
  * VRFs, static routes, ACLs, prefix lists and route maps
  * HSRP and VRRP, DHCP relay, OSPF, BGP, spanning tree and LLDP
* **Everything else** a platform cannot express, or that Junos and NX-OS do not write yet, is reported. Lines no
  reader understands are listed by line number, with secrets masked.

Also in 0.1.0, beyond the list above:

* The report lists what RouterShift recognises but does not convert once per feature, with the reason and the line
  numbers ("Recognised, not converted"), and groups the remaining "Not understood" lines by block. A real IOS XE
  core router went from 558 separate "not understood" items to none.
* IOS XE: BGP peer templates, `address-family ipv4 vrf`, scrypt (`algorithm-type`) users and enable secret,
  `interface range`, `spanning-tree portfast [bpduguard] default`, syslog hosts and sources in a VRF, RADIUS source
  in a VRF, static NAT in a VRF with `extendable`.
* BGP, on every platform that has it: BGP inside VRFs, session passwords, timers, route-reflector clients,
  maximum-prefix, allowas-in, remove-private-as and maximum-paths.
* Fixes: a static route's `tag` was read as its distance; per-VLAN spanning-tree priorities for a whole range
  (`spanning-tree vlan 1-4094 priority`) became one line per VLAN; Junos IPv6 static routes and the management
  port's description did not read back; AOS-S did not read a QoS policy on a VLAN; IP SLA lines were listed twice.

* An item of the report is never "exact" when part of it was not converted: an interface, route map, BGP VRF, OSPF
  process, VLAN or QoS policy with an unconverted line in its block is marked needs-review and names the lines, and
  settings only the IOS and EOS writers write are listed on the other targets.
* EOS to IOS, from a border leaf: anycast gateways (`ip address virtual`, written as the SVI's address with the
  shared MAC), DHCP relay to a server in another VRF with its source interface, interface ranges such as
  `Ethernet1/1-4/1`, SSH that runs only in a VRF (it was written as `transport input none`; `access-class` gets
  `vrf-also`), the console login list (`line con 0`), `ntp local-interface vrf`, syslog hosts with port and
  protocol, the notification types of `snmp-server enable traps`, the policer's burst, `storm-control all`, unicast
  RPF, redirects, unreachables and proxy ARP, prefix lists with `eq`, community and AS-path lists and the route-map
  clauses that use them, EVPN route targets and the export route map of a VRF, BGP and OSPF options (see SCOPE),
  BGP peer groups defined in a VRF, the IPv6 address family of a BGP VRF, and static route tags.
* Fixes: a route-map entry with an unread match clause was written without it (a deny that matched every route); an
  EOS pbr policy written before its class maps was lost; `maximum-routes 0` (no limit) became a limit of 0.

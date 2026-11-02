# Changelog

## Unreleased

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

## 0.1.0 (first release)

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

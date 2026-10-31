# Changelog

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

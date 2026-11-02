# RouterShift - multi-vendor network device configuration converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Configuration RouterShift recognises but does not convert, with the reason, so the report can say "this is EEM,
there is no equivalent" once instead of listing every line as not understood."""

from __future__ import annotations

import re
from typing import List, Optional, Tuple

# (pattern on the line or on the block it is in, group label, why it is not converted). The first match wins, so the
# narrower patterns come first. Patterns match from the start of the text.
_RAW: List[Tuple[str, str, str]] = [
    # Cisco-only features: no other platform has them
    (r"event manager ", "Embedded Event Manager (EEM) applets",
     "EEM is Cisco only; rebuild the automation with the target's own scripting or an external tool"),
    (r"call-home", "Smart Call Home", "Smart Call Home is Cisco only"),
    (r"(router eigrp |redistribute eigrp |set metric \d+ \d+ \d+ \d+ \d+$|ip summary-address eigrp |"
     r"ip hello-interval eigrp |ip hold-time eigrp |"
     r"ip authentication (mode|key-chain) eigrp )", "EIGRP",
     "EIGRP is Cisco only; run OSPF or BGP on the target instead"),
    (r"(ip nhrp |ipv6 nhrp |tunnel mode gre multipoint|tunnel key |tunnel path-mtu-discovery)",
     "DMVPN (mGRE and NHRP)", "DMVPN is Cisco only; the target needs point-to-point tunnels or another overlay"),
    (r"(zone security |zone-pair security |zone-member security |class-map type inspect |policy-map type inspect )",
     "Zone-based firewall", "the IOS zone-based firewall is a stateful firewall that switches do not have; move the "
     "policy to a firewall (FWShift converts firewall policies)"),
    (r"(telemetry |netconf-yang|restconf|gnxi|gnmi-yang)", "Model-driven telemetry and programmability",
     "set up telemetry and the management APIs with the target's own tools"),
    (r"match protocol ", "NBAR application matching",
     "application recognition (NBAR) is Cisco only; classify by ACL or DSCP on the target"),
    # Features not converted yet
    (r"(router ospfv3 |ipv6 ospf |ospfv3 )", "OSPFv3 (IPv6)", "OSPFv3 is not converted yet; set it up by hand"),
    (r"ip as-path regex-mode ", "BGP AS-path regular expressions",
     "the AS-path lists are converted with their expressions as written; EOS 'regex-mode asn' matches whole AS numbers, "
     "so check each expression on the target"),
    (r"router general", "Routes leaked between VRFs (EOS router general)",
     "leaking routes from one VRF into another without route targets is not converted; on IOS XE import the source "
     "VRF's route target into the other VRF, with an import map for the route map"),
    (r"(rpki |router bgp \S+ / rpki |rpki origin-validation)", "RPKI origin validation",
     "the RPKI cache servers and origin validation are not converted; route maps that match the validation state are"),
    (r"(ip as-path access-list |ip community-list |ip extcommunity-list |ip large-community-list |match as-path |"
     r"match community |match extcommunity |set community |set comm-list |set extcommunity )",
     "BGP AS-path and community lists", "these AS-path and community list forms are not converted yet (standard "
     "and expanded community lists, AS-path lists and route-target sets are)"),
    (r"(key chain |ip ospf authentication key-chain )", "Key chains",
     "key chains for routing-protocol authentication are not converted yet; set the keys on the target"),
    (r"(bfd-template |bfd template |bfd interval )", "BFD timers",
     "BFD timer templates are not converted; BFD on the routing sessions is, with the target's default timers"),
    (r"(service-policy (?!input|output|type)\S+$|shape |bandwidth remaining |priority level |fair-queue|"
     r"random-detect|queue-limit )",
     "QoS queuing and shaping", "queuing and shaping are not converted yet (marking and policing are)"),
    (r"(area \S+ range |area \S+ authentication|area \S+ virtual-link|area \S+ filter-list|ip ospf "
     r"message-digest-key |ip ospf authentication)", "OSPF area ranges and authentication",
     "area summaries and OSPF authentication are not converted yet; set them on the target"),
    (r"ip nat inside source route-map ", "NAT rules matched by a route map",
     "route-map NAT is not converted yet; rewrite the rule with an ACL on the target"),
    (r"(aggregate-address )", "BGP aggregates", "aggregate-address is not converted yet; add the aggregate on the "
     "target"),
    (r"(neighbor \S+ ttl-security |neighbor \S+ as-override|neighbor \S+ local-as )", "BGP neighbor options",
     "TTL security, as-override and local-as are not converted yet"),
    (r"(police (cir )?percent |police .*violate-action )", "QoS policers in percent or with three colours",
     "only single-rate policers in bits per second are converted"),
    (r"logging host .* transport tls", "Syslog over TLS", "TLS syslog servers are not converted; add them on the "
     "target with its certificates"),
    (r"(monitor session \S+ filter |monitor session \S+ source vlan |monitor session \S+ source remote |"
     r"monitor session \S+ destination remote )", "Mirroring of VLANs and remote SPAN",
     "VLAN sources, filters and RSPAN are not converted; port sources and destinations are"),
    (r"(ip nat translation |ip nat log )", "NAT timeouts and logging",
     "translation timeouts and logging are not converted; the NAT rules are"),
    (r"(set metric-type |set dampening |match ip route-source |match interface |set ip default next-hop |"
     r"set ip vrf )", "Route-map clauses not converted yet",
     "these match and set clauses are not converted yet; the rest of the route map is, so check what the entry "
     "does without them"),
    (r"control-plane", "Control-plane policing", "each platform protects its CPU its own way"),
    (r"(ipv6 nd raguard|ipv6 dhcp guard|ipv6 snooping|device-tracking|ipv6 nd .*attach-policy|ipv6 source-guard)",
     "IPv6 first-hop security", "RA guard, DHCPv6 guard and device tracking are not converted yet"),
    (r"(ipv6 nd (managed|other)-config-flag|ipv6 nd prefix |ipv6 nd ra |ipv6 dhcp relay |ipv6 dhcp server )",
     "IPv6 router advertisements and DHCPv6", "router advertisement options and DHCPv6 relay are not converted yet"),
    (r"(crypto pki |crypto key )", "Certificates and trustpoints", "enrol new certificates on the target"),
    (r"(crypto ikev2 dpd|crypto ikev2 fragmentation|crypto ipsec security-association |crypto ikev2 profile .*|"
     r"crypto isakmp keepalive)", "IPsec tuning", "dead-peer detection, fragmentation, replay windows and profile "
     "matching are not converted; the tunnels are, with the target's defaults"),
    (r"(aaa accounting |aaa authorization |aaa server radius dynamic-author|radius-server attribute |"
     r"radius-server dead-criteria |radius-server deadtime |aaa group server .*|radius server .*|tacacs server .*)",
     "AAA accounting, authorization and RADIUS tuning",
     "accounting, authorization, change of authorization and RADIUS tuning are not converted yet; the servers and "
     "login authentication are"),
    (r"(authentication (event|open|order|priority|timer|violation|control-direction|periodic)|dot1x timeout |"
     r"dot1x max-reauth-req|dot1x max-req|access-session |mab eap)", "802.1X session options",
     "fallback actions, method order, timers and violation modes are not converted; port authentication is"),
    (r"(switchport port-security aging|switchport port-security mac-address sticky)", "Port security sticky MACs "
     "and aging", "sticky MACs and aging are not converted; the port-security limit is"),
    (r"(ip dhcp snooping information |ip dhcp snooping database|ip dhcp snooping limit |ip arp inspection validate|"
     r"ip arp inspection limit )", "DHCP snooping and ARP inspection options",
     "option 82, the binding database, rate limits and validation checks are not converted; snooping and inspection "
     "are"),
    (r"storm-control action ", "Storm-control actions",
     "the action (shutdown, trap) is not converted; the thresholds are, with the target's default action"),
    (r"(no ip redirects|no ip unreachables|no ip proxy-arp|ip proxy-arp|no ipv6 redirects|no ipv6 unreachables|"
     r"ip verify unicast |ipv6 verify unicast )", "Interface hardening (redirects, proxy ARP, uRPF)",
     "check the target's defaults for ICMP redirects, unreachables, proxy ARP and unicast RPF"),
    (r"(ip mtu |ipv6 mtu |ip tcp adjust-mss |ipv6 tcp adjust-mss )", "IP MTU and TCP MSS clamping",
     "the IP MTU and MSS clamping are not converted; set them on the target"),
    (r"(bandwidth \d|delay \d)", "Interface bandwidth and delay",
     "these only feed routing metrics; set the costs on the target"),
    (r"lacp rate ", "LACP rate", "the LACP rate is not converted; the target uses its default (usually slow)"),
    (r"(ip ssh |ip scp |ip http (authentication|secure-trustpoint|secure-ciphersuite|max-connections|client|"
     r"timeout-policy|active-session|path)|ip http access-class)",
     "SSH and HTTPS server options", "algorithms, timeouts, retries and source interfaces of the login servers are "
     "not converted; the servers themselves are"),
    (r"(login block-for|login quiet-mode|login on-failure|login on-success|login delay)", "Login protection",
     "set the login lockout and logging of the target its own way"),
    (r"(snmp-server view |snmp-server group |snmp-server engineid |snmp-server ifindex|snmp-server trap-source)",
     "SNMP views and v3 options", "views, engine IDs and the options of v3 groups are not converted yet"),
    (r"(ntp access-group |ntp update-calendar|ntp master)", "NTP access control and calendar",
     "NTP access groups and the hardware calendar are not converted"),
    (r"(logging buffered|logging rate-limit|logging console|no logging console|logging monitor|logging "
     r"discriminator|logging origin-id|logging facility|logging history|logging queue-limit)",
     "Local logging options", "the logging buffer, console logging and syslog formatting are not converted; the "
     "syslog servers are"),
    (r"(spanning-tree loopguard default|spanning-tree pathcost method|spanning-tree logging|spanning-tree "
     r"extend system-id|spanning-tree etherchannel)", "Spanning-tree global options",
     "loop guard by default and the path-cost method are not converted; check the target's defaults"),
    (r"(errdisable |udld )", "Error-disable recovery and UDLD",
     "set error-disable recovery and UDLD the target's own way"),
    (r"(track \d+ list )", "Boolean track lists", "track lists are not converted yet; the objects in them are"),
    (r"(ip sla responder|ip sla enable|ip sla \d+$|threshold \d|udp-jitter |tos \d)",
     "IP SLA options", "only icmp-echo operations are converted, with their frequency, timeout and VRF"),
    (r"(ip flow monitor \S+ sampler |flow record |sampler |cache timeout |template data timeout |"
     r"option (interface|application|vrf)-table)",
     "NetFlow records and samplers", "the target exports its own record; set sampling and timeouts there"),
    (r"(line con |line aux |logging synchronous|transport output|transport preferred|stopbits|no exec$)",
     "Console and line settings",
     "set the console and line options on the target"),
    (r"(bgp graceful-restart|bgp deterministic-med|bgp bestpath |bgp dampening|bgp additional-paths|"
     r"timers throttle |soft-reconfiguration |ttl-security |timers lsa |max-metric |nsf|timers \d+ \d+$)",
     "Routing protocol tuning", "graceful restart, timers, best-path and dampening options are not converted; set "
     "them on the target if they matter"),
    # The device itself: hardware, software, files
    (r"(service |no service |platform |boot |license |switch \d+ provision|diagnostic |memory |redundancy|"
     r"transceiver |archive|ip forward-protocol|ip cef|ipv6 cef|clock summer-time|hw-module |vtp |"
     r"no ip http server|no ip domain lookup|ip routing|ipv6 unicast-routing|load-interval |carrier-delay |"
     r"negotiation auto|enable algorithm-type|cdp run|lldp run)", "Device housekeeping",
     "software, licence, hardware and service settings of the device itself; set them the target's own way"),
]

_PATTERNS = [(re.compile(p, re.IGNORECASE), label, reason) for p, label, reason in _RAW]


def classify(text: str, section: str = "") -> Optional[Tuple[str, str]]:
    """(group label, reason) for a line RouterShift recognises but does not convert; None when it does not know it.
    The block the line is in counts first: every line of an EEM applet is EEM."""
    candidates = [section.split(" / ")[0], section, text] if section else [text]
    for candidate in candidates:
        for pattern, label, reason in _PATTERNS:
            if pattern.match(candidate):
                return label, reason
    return None

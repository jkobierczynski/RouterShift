# RouterShift manual

RouterShift shows how a switch or router configuration looks on another vendor's platform. It reads the
configuration, turns it into a vendor-neutral model, writes it out for the target platform, and reports item by
item what was converted exactly, what was approximated and what a person has to look at.

It is a reference, not a migration tool: read the output and the report before anything goes near a live device.

## Contents

1. [Installing](#installing)
2. [Platforms](#platforms)
3. [Converting a configuration](#converting-a-configuration)
4. [Reading the report](#reading-the-report)
5. [Port names and port maps](#port-names-and-port-maps)
6. [The vendor-neutral model](#the-vendor-neutral-model)
7. [What converts](#what-converts)
8. [Secrets](#secrets)
9. [Using RouterShift from Python](#using-routershift-from-python)
10. [Troubleshooting](#troubleshooting)

## Installing

RouterShift needs Python 3.9 or later and nothing else.

```
pip install routershift
```

From a checkout of the repository:

```
pip install .
```

`routershift --version` shows the version.

## Platforms

`routershift platforms` lists the platform keys:

| Key | Platform | What to give it |
|---|---|---|
| `ios` | Cisco IOS and IOS XE | `show running-config` |
| `nxos` | Cisco NX-OS (Nexus 9000/3000) | `show running-config` |
| `eos` | Arista EOS | `show running-config` |
| `junos` | Juniper Junos (EX, QFX, MX, SRX) | `show configuration`, or `show configuration \| display set` |
| `aoscx` | HPE Aruba AOS-CX (10.x) | `show running-config` |
| `aoss` | HPE Aruba AOS-S / ProCurve (16.x) | `show running-config` |
| `comware` | HPE Comware 7 | `display current-configuration` |

Every platform converts to every other one. Junos and NX-OS write the core of a configuration so far (see
[What converts](#what-converts)); the others write everything the model holds that the platform can express.

## Converting a configuration

```
routershift convert --from ios --to aoscx running-config.txt -o aoscx.cfg --report report.txt
```

| Option | Meaning |
|---|---|
| `input` | the configuration file, or `-` for standard input |
| `--from KEY` | the platform the configuration comes from |
| `--to KEY` | the platform to write |
| `-o`, `--output FILE` | where to write the configuration; standard output when left out |
| `--report FILE` | where to write the report; standard error when left out |
| `--report-format text\|json` | the report as text (the default) or JSON |
| `--port-map FILE` | the target name of each port (see [Port maps](#port-maps)) |

The command exits with status 0 when it converted, and 1 with a message when it could not (an unknown platform, a
file it cannot read, a configuration with no lines it recognises).

Pipes work too:

```
ssh admin@sw1 'show running-config' | routershift convert --from eos --to nxos - > nxos.cfg 2> report.txt
```

To see what RouterShift understood, without converting:

```
routershift parse --from comware current-config.txt > model.json
```

## Reading the report

The report lists every item it met, grouped by area (System, VLANs, Interfaces, Gateway redundancy, Static
routes, IP SLA and tracking, OSPF, RIP, IS-IS, MPLS, BGP, Access lists, Prefix lists and route maps, DHCP server,
NAT, VPN, QoS, Port mirroring, Wireless, Management, Recognised not converted, Not understood). Each item has one
status:

| Status | Meaning |
|---|---|
| **exact** | written with the same meaning |
| **approximated** | written, but not with identical behaviour; the finding says what changed |
| **needs-review** | written, but a person has to check or finish it before it goes live |
| **skipped** | not written at all; the finding says why and what to do |

The first line counts the items per status. Below each item that is not exact, its findings follow:

```
Interfaces
  GigabitEthernet1/0/2 -> Ethernet2: approximated
    - [approximated] named Ethernet2 without a port map; check it against the cabling of the new device
Gateway redundancy (HSRP, VRRP)
  Vlan99 VRRP 99: approximated
    - [approximated] HSRP group 99 becomes VRRP group 99, as eos has no HSRP; move every router of the group at once
```

The section **Recognised, not converted** lists, once per feature, what RouterShift knows but does not convert:
features only one vendor has (EEM applets, Smart Call Home, EIGRP, DMVPN, NBAR, the IOS zone-based firewall),
features not converted yet (OSPFv3, queuing and shaping, key chains, IPv6 first-hop security, ...), and settings of
the device itself (boot, licences, services). Each says why and lists the line numbers, for example:

```
Recognised, not converted
  Embedded Event Manager (EEM) applets: skipped
    - [needs-review] EEM is Cisco only; rebuild the automation with the target's own scripting or an external tool (11 lines: 1493-1494, 1496-1503, 1505)
```

The section **Not understood** lists every other line no reader recognised, grouped by the block it is in (an
interface, a router process) with the line numbers. Neither section is in the output: translate those lines by hand
if the new device needs them.

With `--report-format json` the report is:

```json
{
  "source": "ios",
  "target": "eos",
  "counts": {"exact": 69, "approximated": 6, "needs-review": 11, "skipped": 9},
  "items": [
    {"kind": "fhrp", "name": "Vlan99 VRRP 99", "status": "approximated",
     "findings": [{"severity": "approximated", "code": "fhrp-protocol", "message": "..."}]}
  ]
}
```

`kind` is the area, `code` a stable short name for the kind of finding (for example `fhrp-protocol`,
`not-yet`, `not-converted`), handy for filtering.

## Port names and port maps

Every platform names ports its own way: `GigabitEthernet1/0/1`, `Ethernet1/1`, `ge-0/0/0`, `1/1/1`, `A1`,
`Ten-GigabitEthernet1/0/49`. RouterShift stores a canonical name, keeps the source name, and names the port for the
target. Without a port map:

* where both platforms number ports member/slot/port, the numbers are kept (with the slot moved from 0 to 1
  between IOS/Comware and AOS-CX);
* elsewhere the physical ports are numbered in order on the target (`Ethernet1`, `Ethernet1/1`, `ge-0/0/0`,
  `1/1/1`, `1`), keeping their speed class where the target names it (`TenGigabitEthernet`, `xe-`);
* logical interfaces follow the target's naming: `Port-channel10` becomes `lag 10`, `Trk10`,
  `Bridge-Aggregation10`, `port-channel10` or `ae9`; `Vlan10` becomes `interface vlan 10`, `Vlan-interface10` or
  `irb.10`; the management port becomes `mgmt`, `oobm`, `M-GigabitEthernet0/0/0`, `mgmt0` or `me0`.

Every renumbered port is in the report.

### Port maps

For the real layout of the new device, give a port map with `--port-map ports.txt`: one `source = target` per line,
`#` starts a comment. The source side is the name in the source configuration or the canonical name.

```
# source port = target port
GigabitEthernet1/0/1 = Ethernet7
TenGigabitEthernet1/1/1 = Ethernet49/1
Port-channel1 = Port-Channel100
```

Ports the map does not name are numbered as above.

## The vendor-neutral model

`routershift parse` prints the model as JSON. It is what every reader produces and every writer consumes:
`system` (hostname, DNS, NTP, syslog), `vlans`, `interfaces` (by canonical name), `static_routes`, `ospf`, `bgp`,
`acls`, `prefix_lists`, `route_maps`, `dhcp_pools`, `nat_rules`, the VPN, QoS, spanning tree, multicast, VXLAN,
tracking, SNMP, users and AAA sections, and `unparsed`, the lines no reader understood. The fields are documented
in [`src/routershift/model.py`](../src/routershift/model.py).

## What converts

[SCOPE.md](SCOPE.md) has the full list per area and per platform, and the details of each platform. In short:

* **System:** hostname, domain, DNS servers, search domains, static hosts, banner, time zone, NTP (servers, keys,
  source), syslog (servers, level, source), the service VRF.
* **Layer 2:** VLANs, access and trunk ports, voice VLANs, LAGs and LACP, spanning tree (mode, priorities, MST
  region, edge ports and guards), layer 2 security (DHCP snooping, ARP inspection, source guard, port security,
  storm control), IGMP snooping, 802.1X and MAC authentication, PoE, mirroring, sFlow.
* **Layer 3:** addresses, SVIs, loopbacks, subinterfaces, VRFs with RD and route targets, static routes, HSRP, VRRP
  and anycast gateways, DHCP relay and server, OSPF, BGP (with EVPN), RIP, IS-IS, prefix lists and route maps,
  policy-based routing, BFD, multicast routing, IP SLA and tracking, MPLS/LDP, VXLAN.
* **Security and management:** ACLs and their bindings, NAT, IPsec site-to-site VPNs, QoS marking and policing,
  local users and privilege levels, RADIUS/TACACS+ and method lists, SNMP v2c/v3, SSH/Telnet/HTTP(S), the vty ACL
  and timeout, LLDP and CDP, NetFlow, wireless networks on controllers.

What a target platform cannot do is reported, never guessed: an AOS-S switch gets no NAT, and the report says to
move those rules to a router. Junos and NX-OS do not write every area yet; what they leave out is listed as
"not written for Junos yet" or "not written for NX-OS yet".

## Secrets

* Passwords and keys that the source holds in clear text, or in a form the target accepts (Cisco type 7, crypt
  hashes the target takes), are carried over.
* A secret the source holds encrypted in its own form is written as `CHANGE-ME`, with a finding that says so.
* The report never shows a secret: words after `password`, `secret`, `key`, `community` and the like are replaced
  with `<removed>`, in the "Not understood" lines too.

The output configuration does contain the secrets that were carried over; treat it like the source.

## Using RouterShift from Python

```python
from routershift.convert import convert, parse

text = open("running-config.txt").read()
output, report = convert(text, "ios", "nxos", port_map={"GigabitEthernet1/0/1": "Ethernet1/7"})
print(output)
print(report.to_text())          # or report.to_json(), report.counts()
device = parse(text, "ios")      # the model: a dataclass tree
print(device.to_json())
```

`report.items` maps `(kind, name)` to an item with `status`, `skipped` and `findings`.

## Troubleshooting

**"no configuration lines found"**: the file is empty or not a configuration of that platform; check `--from`.

**Many lines under "Not understood"**: the source uses features RouterShift does not read yet, or a syntax of a
release it does not know. The lines are listed with their line numbers; please open an issue with a redacted
example.

**Ports in the wrong place**: give a port map.

**The target rejects a line**: some syntax could not be checked on every release. Each pull request lists the
syntax it could not verify; please open an issue with the platform, the release and the error.

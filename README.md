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

Pre-alpha. Cisco IOS / IOS XE, Arista EOS and HPE Aruba AOS-CX convert in every
direction for the system
settings (hostname, domain, DNS, NTP, syslog, banner, spanning-tree mode), VLANs,
interfaces (switchport access and trunk, voice VLAN, LAGs and LACP, SVIs,
loopbacks, the management port, subinterfaces), IPv4 and IPv6 addressing, DHCP
relay, VRFs and static routes. Everything else (BGP, OSPF, ACLs, SNMP, AAA, ...)
is listed in the report under "Not understood", line by line, with secrets
masked.

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

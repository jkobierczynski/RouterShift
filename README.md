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

Pre-alpha: the model and report exist; the first readers and writers (Cisco IOS
and Arista EOS) are next.

## Requirements

Python 3.9 or later, no other dependencies.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE).

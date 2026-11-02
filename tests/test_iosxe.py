"""IOS XE habits that a real configuration is full of: BGP peer templates and VRF address families, scrypt
secrets, global spanning-tree defaults, and the many features RouterShift recognises without converting them."""

import pytest

from routershift import bgp as bgp_text
from routershift.convert import convert, parse
from routershift.report import _ranges, redact

IOS = """\
hostname edge-01
enable algorithm-type scrypt secret 9 $9$abcdefghijklmn$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq
username admin privilege 15 algorithm-type scrypt secret 9 $9$abcdefghijklmn$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq
service timestamps log datetime msec
spanning-tree mode rapid-pvst
spanning-tree portfast default
spanning-tree portfast bpduguard default
vrf definition CORP
 rd 65010:100
 address-family ipv4
  route-target export 65010:100
  route-target import 65010:100
 exit-address-family
interface Loopback0
 ip address 10.255.0.1 255.255.255.255
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
interface GigabitEthernet1/0/2
 switchport mode trunk
interface Vlan10
 vrf forwarding CORP
 ip address 10.10.10.1 255.255.255.0
 no ip redirects
 no ip proxy-arp
 standby version 2
 standby 10 ip 10.10.10.254
 standby 10 preempt delay minimum 60
router bgp 65010
 bgp router-id 10.255.0.1
 bgp graceful-restart
 no bgp default ipv4-unicast
 template peer-policy TPOL
  route-reflector-client
  next-hop-self all
  send-community both
 exit-peer-policy
 template peer-session TSES
  remote-as 65010
  password 0 s3cret
  update-source Loopback0
  timers 10 30
  fall-over bfd
 exit-peer-session
 neighbor 10.255.0.2 inherit peer-session TSES
 neighbor 10.255.0.2 description core-2
 neighbor 198.51.100.9 remote-as 64496
 neighbor 198.51.100.9 password 0 isp-key
 !
 address-family ipv4
  network 198.51.100.0 mask 255.255.255.0
  neighbor 10.255.0.2 activate
  neighbor 10.255.0.2 inherit peer-policy TPOL
  neighbor 198.51.100.9 activate
  neighbor 198.51.100.9 remove-private-as
  neighbor 198.51.100.9 maximum-prefix 950000
  maximum-paths 2
  maximum-paths ibgp 2
 exit-address-family
 !
 address-family ipv4 vrf CORP
  redistribute connected
  neighbor 192.0.2.1 remote-as 65100
  neighbor 192.0.2.1 activate
  neighbor 192.0.2.1 allowas-in 2
  neighbor 192.0.2.1 route-map RM-IN in
  maximum-paths 2
 exit-address-family
ip route 0.0.0.0 0.0.0.0 198.51.100.9 name DEFAULT
ip route 10.30.0.0 255.255.0.0 10.10.10.250 tag 300
ip sla 30
 udp-jitter 10.255.0.10 16384
 frequency 30
event manager applet NIGHTLY
 event timer cron cron-entry "15 2 * * *"
 action 1.0 syslog msg "hello"
route-map RM-IN permit 10
 set local-preference 200
"""

FULL = ["ios", "eos", "nxos", "aoscx", "comware"]


def test_reads_users_and_spanning_tree_defaults() -> None:
    d = parse(IOS, "ios")
    assert [(u.name, u.privilege, u.hash_type) for u in d.users] == [("admin", 15, "ios-type9")]
    assert d.aaa.enable_secret is not None and d.aaa.enable_secret.hash_type == "ios-type9"
    access, trunk = d.interfaces["Ethernet1/0/1"], d.interfaces["Ethernet1/0/2"]
    assert (access.stp_portfast, access.stp_bpduguard) == (True, True)
    assert (trunk.stp_portfast, trunk.stp_bpduguard) == (None, None)
    assert d.interfaces["Vlan10"].fhrp[0].preempt


def test_reads_bgp_templates_and_vrfs() -> None:
    bgp = parse(IOS, "ios").bgp
    assert bgp is not None
    peers = {n.address: n for n in bgp.neighbors}
    core = peers["10.255.0.2"]
    assert (core.remote_as, core.update_source, core.password, core.keepalive, core.hold, core.bfd) == (
        "65010", "Loopback0", "s3cret", 10, 30, True)
    assert (core.route_reflector_client, core.next_hop_self, core.send_community, core.description) == (
        True, True, True, "core-2")
    isp = peers["198.51.100.9"]
    assert (isp.remove_private_as, isp.maximum_prefix, isp.password) == (True, 950000, "isp-key")
    assert (bgp.maximum_paths, bgp.maximum_paths_ibgp) == (2, 2)
    corp = bgp.vrfs["CORP"]
    [pe] = corp.neighbors
    assert (pe.remote_as, pe.allowas_in, pe.route_map_in, pe.families) == ("65100", 2, "RM-IN", ["ipv4"])
    assert (corp.redistribute, corp.maximum_paths) == (["connected"], 2)


def test_static_route_tag_is_not_a_distance() -> None:
    routes = {r.prefix: r for r in parse(IOS, "ios").static_routes}
    assert routes["10.30.0.0/16"].distance is None and routes["10.30.0.0/16"].next_hop == "10.10.10.250"


@pytest.mark.parametrize("target", FULL)
def test_bgp_round_trips(target: str) -> None:
    first = parse(IOS, "ios")
    out, report = convert(IOS, "ios", target)
    back = parse(out, target)
    assert [u.text for u in back.unparsed] == [], target
    assert first.bgp is not None and back.bgp is not None
    expected = bgp_text.flat(first.bgp)
    if target == "aoscx":  # AOS-CX leaves the prefix limit to a person, and says so
        assert "the maximum-prefix limit not written for AOS-CX" in report.to_text()
        for peer in expected:
            peer.maximum_prefix = None
    else:
        # every neighbor option is written (the process-wide graceful restart is left to a person on some targets)
        assert not [f for i in report.items.values() if i.kind == "bgp" for f in i.findings
                    if f.code == "bgp-option"], target
    assert bgp_text.flat(back.bgp) == expected, target
    assert [n for v in back.bgp.vrfs.values() for n in v.neighbors] == first.bgp.vrfs["CORP"].neighbors
    assert back.bgp.vrfs["CORP"].redistribute == ["connected"]


def test_junos_writes_the_session_options_and_reports_the_rest() -> None:
    out, report = convert(IOS, "ios", "junos")
    assert "authentication-key s3cret;" in out and "hold-time 30;" in out and "remove-private;" in out
    text = report.to_text()
    assert "bgp vrf CORP: skipped" in text
    assert "route-reflector-client not written for Junos" in text
    back = parse(out, "junos")
    assert back.unparsed == []
    peers = {n.address: n for n in bgp_text.flat(back.bgp)}  # type: ignore[arg-type]
    assert (peers["10.255.0.2"].password, peers["10.255.0.2"].keepalive, peers["10.255.0.2"].hold) == (
        "s3cret", 10, 30)


def test_report_groups_what_it_recognises() -> None:
    _, report = convert(IOS, "ios", "eos")
    text = report.to_text()
    assert "Not understood" not in text
    known = {name for kind, name in report.items if kind == "known"}
    assert {"Embedded Event Manager (EEM) applets", "Device housekeeping", "IP SLA options",
            "Gateway redundancy options"} <= known
    # converted now: no ip redirects, no ip proxy-arp, bgp graceful-restart, the static route's tag
    assert not {"Interface hardening (redirects, proxy ARP, uRPF)", "Routing protocol tuning",
                "Static route options"} & known
    eem = report.items[("known", "Embedded Event Manager (EEM) applets")]
    assert eem.skipped and "(3 lines: " in eem.findings[0].message


def test_unknown_lines_are_grouped_by_block() -> None:
    text = IOS + "interface Vlan10\n frobnicate on\n frobnicate off\nfoo bar\n"
    _, report = convert(text, "ios", "eos")
    item = report.items[("unparsed", "in 'interface Vlan10'")]
    assert [f.message for f in item.findings][-2:] == [
        f"line {IOS.count(chr(10)) + 2}: frobnicate on not converted",
        f"line {IOS.count(chr(10)) + 3}: frobnicate off not converted"]
    assert ("unparsed", f"line {IOS.count(chr(10)) + 4}: foo bar") in report.items


def test_ip_sla_lines_are_listed_once() -> None:
    lines = [u.line for u in parse(IOS, "ios").unparsed]
    assert len(lines) == len(set(lines))


def test_ranges_and_redaction() -> None:
    assert _ranges([9, 10, 11, 23, 71, 72]) == "9-11, 23, 71-72"
    assert redact("match community CL-ISP") == "match community CL-ISP"
    assert redact("snmp-server community public RO") == "snmp-server community <removed> RO"


def test_interface_range_and_vlan_priority_range() -> None:
    text = ("hostname s\nvlan 10\nvlan 20\nspanning-tree mode rapid-pvst\nspanning-tree vlan 1-4094 priority 4096\n"
            "interface range GigabitEthernet1/0/26 - 28, GigabitEthernet1/0/30\n switchport access vlan 20\n"
            " switchport mode access\n shutdown\ninterface GigabitEthernet1/0/27\n description kept\n")
    d = parse(text, "ios")
    ports = {n: i for n, i in d.interfaces.items() if n.startswith("Ethernet1/0/")}
    assert sorted(ports) == ["Ethernet1/0/26", "Ethernet1/0/27", "Ethernet1/0/28", "Ethernet1/0/30"]
    assert all(i.access_vlan == 20 and i.shutdown for i in ports.values())
    assert ports["Ethernet1/0/27"].description == "kept"
    for target in ("ios", "nxos", "junos"):
        out, report = convert(text, "ios", target)
        assert 1 <= out.count("4096") <= 3, target  # VLANs 1, 10 and 20, not 4094 lines
        assert "4091 other VLANs" in report.to_text(), target


def test_junos_ipv6_routes_round_trip() -> None:
    text = "hostname r\nipv6 route ::/0 2001:db8::1\nipv6 route 2001:db8:100::/48 Null0\n"
    out, _ = convert(text, "ios", "junos")
    back = parse(out, "junos")
    assert back.unparsed == [] and sorted(r.prefix for r in back.static_routes) == ["2001:db8:100::/48", "::/0"]

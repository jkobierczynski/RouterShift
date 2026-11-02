"""Junos ports and services: speed, voice VLAN, storm control, port security, DHCP snooping and trust, 802.1X,
PoE, VRRP and anycast gateways, DHCP relay and server, interface hardening and AAA, written and read back."""

from helpers import sample

from routershift.convert import convert, parse

EOS = sample("eos_border_leaf.cfg")


def _back(text: str, source: str):
    first = parse(text, source)
    out, report = convert(text, source, "junos")
    back = parse(out, "junos")
    assert back.unparsed == []
    return first, out, report, back


def _by_source(device, out):
    return {i.source_name: i for i in device.interfaces.values()}


def test_border_leaf_ports() -> None:
    first, out, report, back = _back(EOS, "eos")
    ifaces = list(back.interfaces.values())
    dot1x = next(i for i in ifaces if i.dot1x)
    assert (dot1x.mab, dot1x.dot1x_host_mode, dot1x.dot1x_fail_vlan) == (True, "multi-auth", 900)
    assert "supplicant multiple;" in out and "server-reject-vlan" in out
    assert {"broadcast": 2.0, "multicast": 2.0, "unknown-unicast": 2.0} in [i.storm_control for i in ifaces]
    assert "no-multicast;" in out  # a port that limits broadcast only
    assert back.vlans[900].dhcp_snooping and back.vlans[900].arp_inspection and back.dhcp_option82
    vlan900 = back.interfaces["Vlan900"]
    assert [(g.protocol, g.group, g.address, g.priority) for g in vlan900.fhrp] == [("vrrp", 90, "172.21.0.1", 120)]
    vlan100 = back.interfaces["Vlan100"]
    assert vlan100.virtual_ipv4 == first.interfaces["Vlan100"].virtual_ipv4 and back.anycast_mac == first.anycast_mac
    assert vlan100.helper_addresses == ["10.100.0.67"] and vlan100.helper_source == "Loopback100"
    assert report.items[("interface", "Vlan100 -> irb.100")].status == "needs-review"  # the relay's server VRF


def test_border_leaf_aaa() -> None:
    first, out, report, back = _back(EOS, "eos")
    assert [(s.protocol, s.address, s.vrf) for s in back.aaa.servers] == \
        [(s.protocol, s.address, "mgmt_junos") for s in first.aaa.servers]
    login = next(m for m in back.aaa.methods if m.kind == "authentication" and m.service == "login")
    assert login.methods == ["group:tacacs", "local"]
    assert "authentication-order [ tacplus password ];" in out
    assert back.aaa.source == {"tacacs": "Management0", "radius": "Management0"}


def test_access_switch_ports() -> None:
    first, out, report, back = _back(sample("ios_access.cfg"), "ios")
    src = {i.name: i for i in first.interfaces.values()}
    got = _by_source(back, out)
    voice = [i for i in src.values() if i.voice_vlan]
    assert voice and all(any(g.voice_vlan == i.voice_vlan for g in got.values()) for i in voice)
    secured = [i for i in src.values() if i.port_security]
    assert {(i.port_security_max, i.port_security_violation) for i in secured} <= \
        {(g.port_security_max, g.port_security_violation) for g in got.values() if g.port_security}
    assert [p.name for p in back.dhcp_pools] == [p.name for p in first.dhcp_pools]
    for a, b in zip(first.dhcp_pools, back.dhcp_pools):
        assert (a.network, a.default_routers, a.dns_servers, a.lease_seconds) == \
            (b.network, b.default_routers, b.dns_servers, b.lease_seconds)


def test_reads_native_junos_ports() -> None:
    text = """\
set interfaces ge-0/0/1 ether-options speed 1g
set interfaces ge-0/0/1 ether-options link-mode full-duplex
set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members USERS
set interfaces irb unit 10 family inet address 10.0.10.2/24 vrrp-group 7 virtual-address 10.0.10.1
set interfaces irb unit 10 family inet address 10.0.10.2/24 vrrp-group 7 priority 150
set interfaces irb unit 10 family inet address 10.0.10.2/24 vrrp-group 7 no-preempt
set interfaces irb unit 10 family inet rpf-check mode loose
set vlans USERS vlan-id 10
set vlans USERS l3-interface irb.10
set vlans USERS forwarding-options dhcp-security arp-inspection
set switch-options interface ge-0/0/1.0 interface-mac-limit 3
set switch-options interface ge-0/0/1.0 interface-mac-limit packet-action drop
set poe interface ge-0/0/1 priority high
set protocols layer2-control bpdu-block interface ge-0/0/1 drop
"""
    d = parse(text, "junos")
    assert d.unparsed == []
    port = d.interfaces["Ethernet0/0/1"]
    assert (port.speed, port.duplex, port.port_security_max, port.port_security_violation) == (1000, "full", 3,
                                                                                             "protect")
    assert port.poe_priority == "high" and port.stp_bpdufilter
    irb = d.interfaces["Vlan10"]
    assert irb.urpf == "loose" and irb.fhrp[0].preempt is False and irb.fhrp[0].priority == 150
    assert d.vlans[10].arp_inspection and d.vlans[10].dhcp_snooping

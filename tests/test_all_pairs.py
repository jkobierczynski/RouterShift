from typing import Optional

import pytest
from helpers import DATA

from routershift import bgp as bgp_text
from routershift import nat as nat_text
from routershift import aaa as aaa_text
from routershift import snmp as snmp_text
from routershift import qos as qos_text
from routershift import stp as stp_text
from routershift import vpn as vpn_text
from routershift import ospf as ospf_text
from routershift.acl import safe_name
from routershift.convert import PLATFORMS, convert, parse
from routershift.model import AclAction, Device, InterfaceKind, StpMode

SAMPLES = {"ios": "ios_access.cfg", "eos": "eos_leaf.cfg", "aoscx": "aoscx_access.cfg", "aoss": "aoss_edge.cfg",
           "comware": "comware_access.cfg"}


def test_every_platform_has_a_sample() -> None:
    assert set(SAMPLES) == set(PLATFORMS)


@pytest.mark.parametrize("source", sorted(SAMPLES))
@pytest.mark.parametrize("target", sorted(PLATFORMS))
def test_converts_and_reads_back(source: str, target: str) -> None:
    text = (DATA / SAMPLES[source]).read_text(encoding="utf-8")
    first = parse(text, source)
    out, report = convert(text, source, target)
    back = parse(out, target)
    # the writer's own output holds nothing its reader does not understand
    assert [u.text for u in back.unparsed if not u.section.startswith("a trunk without")] == []
    # VLANs and layer 3 addresses survive every conversion
    assert set(first.vlans) <= set(back.vlans)
    # (the AOS switches have no tunnel interfaces)
    tunnels = target in vpn_text.SUPPORTED
    addresses = lambda dev: sorted(a for i in dev.interfaces.values() for a in i.ipv4  # noqa: E731
                                   if tunnels or i.kind != InterfaceKind.TUNNEL)
    assert addresses(first) == addresses(back)
    # every ACL arrives, with at least its convertible entries (more where a platform needs one port per entry),
    # and stays applied in the same direction
    for name, acl in first.acls.items():
        other = back.acls[safe_name(name)]
        rules = lambda a: [e for e in a.entries if e.action != AclAction.REMARK and not e.unsupported]  # noqa: E731
        assert len(rules(other)) >= len(rules(acl)), name
    bound = lambda dev: sorted((d, safe_name(getattr(i, d))) for i in dev.interfaces.values()  # noqa: E731
                               for d in ("acl_in", "acl_out", "acl6_in", "acl6_out") if getattr(i, d))
    assert bound(first) == bound(back)
    # every gateway redundancy address arrives
    virtual = lambda dev: sorted(a for i in dev.interfaces.values() for g in i.fhrp  # noqa: E731
                                 for a in [g.address] + g.secondary)
    assert virtual(first) == virtual(back)
    assert all(g.address for i in back.interfaces.values() for g in i.fhrp)
    # OSPF runs on the same number of interfaces, in the same areas, as passive or not, with the same router ID
    for p in first.ospf:
        other = next(o for o in back.ospf if o.router_id == p.router_id)
        areas = lambda dev, q: sorted((a, q.passive(i)) for i, a in ospf_text.interfaces(dev, q).items())  # noqa: E731
        assert areas(first, p) == areas(back, other)
        assert other.redistribute == p.redistribute and other.area_types == p.area_types
    costs = lambda dev: sorted(i.ospf_cost for i in dev.interfaces.values() if i.ospf_cost)  # noqa: E731
    assert costs(first) == costs(back)
    # DHCP pools keep their addresses and options (AOS-S has no VRFs)
    pools = lambda dev: sorted(  # noqa: E731
        (p.network, p.ranges, p.default_routers, p.dns_servers, p.domain_name, p.lease_seconds,
         p.vrf if target != "aoss" else "") for p in dev.dhcp_pools)
    assert pools(first) == pools(back)
    # NAT rules keep their addresses, sources and pools; EOS has no static port forwarding and the AOS switches
    # have no NAT, which the report says
    def nat(dev: Device) -> list:
        pool = lambda name: (dev.nat_pools[name].first, dev.nat_pools[name].last) if name else ()  # noqa: E731
        return sorted((r.kind, r.local, r.translated, r.protocol, r.local_port, r.translated_port,
                       safe_name(r.acl) if r.acl else "", pool(r.pool), r.overload) for r in dev.nat_rules
                      if not (target == "eos" and r.protocol))
    if target in nat_text.SUPPORTED:
        assert nat(first) == nat(back)
    else:
        assert not back.nat_rules
        assert not first.nat_rules or "do not do NAT" in report.to_text()
    # IPsec connections keep their peers, protected traffic, algorithms, PFS, lifetimes and readable keys; EOS has
    # route-based VPNs only, Comware is written with IKEv1 only, and the AOS switches have no IPsec
    def vpn(dev: Device) -> list:
        def key(address: str) -> str:
            psk = dev.psks.get(address)
            return psk.key if psk is not None and psk.key != vpn_text.PLACEHOLDER_KEY else ""
        transform = lambda name: ((t.encryption, t.integrity, t.mode)  # noqa: E731
                                  if (t := dev.ipsec_transforms.get(name)) else ())
        ike = lambda p: sorted((q.encryption, q.integrity, q.dh_groups, q.lifetime)  # noqa: E731
                               for q in vpn_text.policies_for(dev, p))
        return sorted((p.profile, vpn_text.peers_of(dev, p), [key(a) for a in vpn_text.peers_of(dev, p)],
                       safe_name(p.acl) if p.acl else "", [transform(t) for t in p.transforms], p.pfs_group,
                       p.lifetime, p.ike_version, ike(p)) for p in dev.ipsec_peers
                      if not (target == "eos" and not p.profile) and not (target == "comware" and p.ike_version != 1))
    if tunnels:
        assert vpn(first) == vpn(back)
        ikev2 = {p.name for p in first.ipsec_peers if p.ike_version == 2} if target == "comware" else set()
        tunnel = lambda dev: sorted(  # noqa: E731
            (bool(i.tunnel_source), i.tunnel_destination, i.tunnel_mode,
             i.tunnel_profile if i.tunnel_profile not in ikev2 else "")
            for i in dev.interfaces.values() if i.kind == InterfaceKind.TUNNEL)
        assert tunnel(first) == tunnel(back)
    else:
        assert not back.ipsec_peers
        assert not first.ipsec_peers or "do not terminate IPsec" in report.to_text()
    # NTP keeps its servers, keys and trust; SNMP its communities, location and contact, notification hosts and v3
    # users. Encrypted secrets come back as the placeholder. The AOS switches drop ACLs, groups and (AOS-S) VRFs and
    # SNMPv3 hosts, which the report says.
    plain = lambda value: "" if value in (snmp_text.PLACEHOLDER, vpn_text.PLACEHOLDER_KEY) else value  # noqa: E731
    ntp = lambda dev: (sorted(dev.system.ntp_servers), dev.system.ntp_prefer if target != "aoss" else "",  # noqa: E731
                       dev.system.ntp_server_keys,
                       sorted((k.number, k.algorithm, plain(k.key), k.trusted) for k in dev.system.ntp_keys.values()),
                       dev.system.ntp_authenticate or target == "aoss")
    assert ntp(first) == ntp(back)
    aos = target in ("aoscx", "aoss")
    snmp = lambda dev: (  # noqa: E731
        sorted((plain(c.name), c.access, "" if aos else safe_name(c.acl) if c.acl else "") for c in dev.snmp.communities),
        dev.snmp.location, dev.snmp.contact,
        sorted((h.address, h.version, plain(h.secret), h.informs, bool(h.vrf) and target != "aoss")
               for h in dev.snmp.hosts if not (target == "aoss" and h.version == "3")),
        sorted((u.name, "" if aos else u.group or u.name, u.auth, plain(u.auth_key), u.priv, plain(u.priv_key))
               for u in dev.snmp.users))
    assert snmp(first) == snmp(back)
    # AAA keeps every RADIUS and TACACS+ server with its key, the protocol and fallback of the login method list, and
    # every user whose password the source holds in clear text
    aaa = lambda dev: (  # noqa: E731
        sorted((s.protocol, s.address, plain(s.key)) for s in dev.aaa.servers),
        [(aaa_text.protocol_of(dev, m.methods[0]), m.methods[1:]) for m in dev.aaa.methods
         if (m.kind, m.service, m.name) == ("authentication", "login", "default")])
    assert aaa(first) == aaa(back)
    users = lambda dev: sorted(u.name for u in dev.users if u.password)  # noqa: E731
    assert users(first) == users(back)
    # 802.1X keeps the ports with 802.1X and MAB, their host mode and reauthentication, and the RADIUS servers they
    # use; TFTP and FTP keep their source interface (the AOS switches have no FTP client setting, and AOS-S takes a
    # VLAN or loopback only)
    dot1x = lambda dev: (  # noqa: E731
        dev.aaa.dot1x,
        sorted((i.dot1x, i.mab, i.dot1x_host_mode, i.dot1x_reauth, (i.dot1x_reauth_period or 3600) if i.dot1x_reauth
                else 0) for i in dev.interfaces.values() if i.dot1x or i.mab),
        [aaa_text.protocol_of(dev, m.methods[0]) for m in dev.aaa.methods if m.service == "dot1x"],
        sorted(k for k, source in dev.system.transfer_source.items() if not (aos and k == "ftp") and not (
            target == "aoss" and not source.startswith(("Vlan", "Loopback")))))
    assert dot1x(first) == dot1x(back)
    # Spanning tree keeps the bridge priority of every VLAN (per VLAN or through its MST instance), the MST region,
    # and the guards, BPDU filter, cost and priority of the ports (AOS-S has no loop guard)
    def priority(dev: Device, vlan: int) -> Optional[int]:
        instance = next((n for n, vlans in dev.stp.instances.items() if vlan in vlans), 0)
        return dev.stp.vlan_priority.get(vlan, dev.stp.priority.get(instance, dev.stp.priority.get(0)))

    vlans = sorted(first.vlans) or [1]
    assert [priority(first, v) for v in vlans] == [priority(back, v) for v in vlans]
    if first.stp_mode == StpMode.MSTP:
        region = lambda dev: (dev.stp.region, dev.stp.revision, dev.stp.instances)  # noqa: E731
        assert region(first) == region(back)
    stp_ports = lambda dev: sorted(  # noqa: E731
        ("" if target == "aoss" and i.stp_guard == "loop" else i.stp_guard, i.stp_bpdufilter, i.stp_cost,
         i.stp_port_priority) for i in dev.interfaces.values() if stp_text.has_port_settings(i)
        and not (target == "aoss" and i.stp_guard == "loop" and not (i.stp_bpdufilter or i.stp_cost or
                                                                     i.stp_port_priority)))
    assert stp_ports(first) == stp_ports(back)
    # QoS keeps every applied policy with its classes (DSCP values, or an ACL with as many rules), markings and
    # police rates, and the trust of every port (AOS-CX has no default class; EOS takes no output policy)
    def qos(dev: Device) -> list:
        def matches(name: str) -> tuple:
            c = dev.qos_classes.get(name)
            if c is None:
                return ()
            acl = dev.acls.get(c.acl) if c.acl else None
            return (sorted(c.dscp), len([e for e in acl.entries if e.action != AclAction.REMARK]) if acl else 0)

        return sorted((d, [(matches(a.qos_class), a.set_dscp, a.police_kbps)
                                   for a in dev.qos_policies[getattr(i, d)].actions
                                   if not (target == "aoscx" and a.qos_class == qos_text.DEFAULT_CLASS)])
                      for i in dev.interfaces.values() for d in ("qos_policy_in", "qos_policy_out")
                      if getattr(i, d) and not (target == "eos" and d == "qos_policy_out"))

    assert qos(first) == qos(back)
    # (IOS writes nothing for DSCP trust, which a Catalyst 9000 does by default)
    trust = lambda dev: sorted(i.qos_trust for i in dev.interfaces.values()  # noqa: E731
                               if i.qos_trust and not (target == "ios" and i.qos_trust == "dscp"))
    assert trust(first) == trust(back)
    # BGP keeps every neighbor with its settings (peer groups may be written out on their members), networks and
    # redistribution; AOS-S leaves it to a person
    if first.bgp is not None and target == "aoss":
        assert back.bgp is None and "configure it by hand" in report.to_text()
    elif first.bgp is not None:
        assert back.bgp is not None
        assert (back.bgp.local_as, back.bgp.router_id) == (first.bgp.local_as, first.bgp.router_id)
        assert bgp_text.flat(back.bgp) == bgp_text.flat(first.bgp)
        assert sorted(back.bgp.networks) == sorted(first.bgp.networks)
        assert (back.bgp.redistribute, back.bgp.redistribute6) == (first.bgp.redistribute, first.bgp.redistribute6)
    assert report.counts()

from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    vlan = ios.interfaces["Vlan99"]
    assert (vlan.bfd_interval, vlan.bfd_min_rx, vlan.bfd_multiplier, vlan.ospf_bfd, vlan.pbr) == (
        300, 300, 3, True, "PBR-USERS")
    assert ios.route_maps["PBR-USERS"].entries[0].sets == {"next-hop": "10.99.0.2"}
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert eos.interfaces["Ethernet49/1"].bfd_interval == 100
    assert [p.bfd_all for p in eos.ospf] == [True]
    assert eos.bgp is not None and [n.address for n in eos.bgp.neighbors if n.bfd] == ["10.255.255.9"]
    assert eos.interfaces["Vlan100"].pbr == "PBR-BACKUP"
    [e] = eos.route_maps["PBR-BACKUP"].entries
    assert (e.match_acls, e.sets) == (["BACKUP"], {"next-hop": "10.100.0.250"})
    cx = parse(sample("aoscx_access.cfg"), "aoscx")
    vlan = cx.interfaces["Vlan99"]
    assert (vlan.bfd_interval, vlan.bfd_min_rx, vlan.bfd_multiplier, vlan.ospf_bfd) == (500, 500, 5, True)
    assert cx.bgp is not None and cx.bgp.neighbors[0].bfd
    comware = parse(sample("comware_access.cfg"), "comware")
    assert comware.interfaces["Vlan99"].bfd_multiplier == 4 and comware.interfaces["Vlan99"].ospf_bfd
    assert comware.interfaces["Vlan10"].pbr == "PBR-WEB"
    assert comware.route_maps["PBR-WEB"].entries[0].match_acls == ["USERS-IN"]
    assert comware.bgp is not None and comware.bgp.neighbors[0].bfd


def test_writers() -> None:
    out, _ = convert(sample("comware_access.cfg"), "comware", "ios")
    assert " ip ospf bfd\n bfd interval 400 min_rx 400 multiplier 4\n" in out
    assert " ip policy route-map PBR-WEB\n" in out
    assert "route-map PBR-WEB permit 10\n match ip address USERS-IN\n set ip next-hop 10.10.0.2\n" in out
    assert " neighbor 10.99.0.1 fall-over bfd\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "   ip ospf neighbor bfd\n   bfd interval 300 min-rx 300 multiplier 3\n" in out
    assert "   service-policy type pbr input PBR-USERS\n" in out
    assert "class-map type pbr match-any PBR-USERS-10\n   match ip access-group USERS-IN\n!\n" \
           "policy-map type pbr PBR-USERS\n   class PBR-USERS-10\n      set nexthop 10.99.0.2\n!\n" in out
    assert "route-map PBR-USERS" not in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert "policy-based-route PBR-BACKUP permit node 10\n if-match acl name BACKUP\n apply next-hop 10.100.0.250\n" \
           in out
    assert " bfd min-transmit-interval 100\n bfd min-receive-interval 100\n bfd detect-multiplier 3\n" in out
    assert " peer 10.255.255.9 bfd\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "\nbfd\n" in out and "    bfd all-interfaces\n" in out and "neighbor 10.255.255.9 fall-over bfd\n" in out


def test_reported_limits() -> None:
    out, report = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "AOS-CX: policy-based routing with route map PBR-BACKUP is not written" in report.to_text()
    assert "PBR-BACKUP" not in out
    out, report = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert "bfd" not in out.lower()
    assert "AOS-S: BFD is not written" in report.to_text()
    text = "route-map P permit 10\n match ip address A\n set ip next-hop 10.0.0.1\n set metric 5\n!\n" \
           "route-map P deny 20\n!\ninterface Vlan1\n ip address 10.0.0.2 255.255.255.0\n ip policy route-map P\n" \
           " bfd interval 300 min_rx 300 multiplier 3\n"
    out, report = convert(text, "ios", "comware")
    assert "policy-based-route P permit node 10\n if-match acl name A\n apply next-hop 10.0.0.1\n#\n" in out
    assert "node 20" not in out and "entry 20 denies" in report.to_text()
    assert "entry 10 holds more" in report.to_text()

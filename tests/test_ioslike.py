from helpers import sample

from routershift import confparse
from routershift.convert import convert, parse
from routershift.model import InterfaceKind, LacpMode, SwitchportMode, StpMode
from routershift.names import canonical, read_port_map


def test_canonical_names() -> None:
    assert canonical("Gi1/0/1") == ("Ethernet1/0/1", InterfaceKind.ETHERNET, "1g")
    assert canonical("TenGigabitEthernet1/1/1") == ("Ethernet1/1/1", InterfaceKind.ETHERNET, "10g")
    assert canonical("Ethernet49/1") == ("Ethernet49/1", InterfaceKind.ETHERNET, "")
    assert canonical("Port-Channel10")[:2] == ("Port-channel10", InterfaceKind.LAG)
    assert canonical("Gi0/1.100")[:2] == ("Ethernet0/1.100", InterfaceKind.SUBINTERFACE)


def test_banner_delimiters() -> None:
    _, banners = confparse.read("banner motd ^CHello^C\nhostname a\n")
    assert banners[0].text == "Hello"
    _, banners = confparse.read("banner motd #\nline one\nline two#\nhostname a\n")
    assert banners[0].text == "line one\nline two"
    roots, banners = confparse.read("banner motd\nHi there\nEOF\nhostname a\n")
    assert banners[0].text == "Hi there" and roots[0].text == "hostname a"


def test_parse_ios_access_switch() -> None:
    dev = parse(sample("ios_access.cfg"), "ios")
    assert dev.system.hostname == "sw-access-01"
    assert dev.system.domain_name == "example.net"
    assert dev.stp_mode == StpMode.RAPID_PVST
    assert sorted(dev.vlans) == [10, 20, 99]
    desk = dev.interfaces["Ethernet1/0/1"]
    assert desk.mode == SwitchportMode.ACCESS and desk.access_vlan == 10 and desk.voice_vlan == 20
    assert desk.stp_portfast and desk.stp_bpduguard
    printer = dev.interfaces["Ethernet1/0/2"]
    assert printer.speed == 100 and printer.duplex == "full" and printer.shutdown
    uplink = dev.interfaces["Ethernet1/1/1"]
    assert uplink.lag == "Port-channel1" and uplink.lacp_mode == LacpMode.ACTIVE
    assert uplink.allowed_vlans == "10,20,99" and uplink.media == "10g"
    assert dev.interfaces["Port-channel1"].mode == SwitchportMode.TRUNK
    mgmt = dev.interfaces["Management1"]
    assert mgmt.kind == InterfaceKind.MANAGEMENT and mgmt.vrf == "Mgmt-vrf" and mgmt.ipv4 == ["192.168.255.11/24"]
    assert dev.interfaces["Vlan99"].helper_addresses == ["10.0.0.67"]
    assert [(r.prefix, r.vrf, r.next_hop) for r in dev.static_routes] == [
        ("0.0.0.0/0", "", "10.99.0.1"), ("0.0.0.0/0", "Mgmt-vrf", "192.168.255.1")]
    assert dev.system.banner_motd == "Authorised access only."
    assert [(c.name, c.access) for c in dev.snmp.communities] == [("s3cret", "ro")]


def test_parse_eos_leaf() -> None:
    dev = parse(sample("eos_leaf.cfg"), "eos")
    assert dev.system.service_vrf == "MGMT"
    assert dev.interfaces["Ethernet1"].mode == SwitchportMode.ACCESS
    assert dev.interfaces["Ethernet49/1"].mode == SwitchportMode.ROUTED
    assert dev.interfaces["Ethernet49/1"].ipv4 == ["10.255.0.1/31"]
    assert dev.interfaces["Port-channel10"].mode == SwitchportMode.TRUNK
    assert dev.interfaces["Management1"].vrf == "MGMT"
    assert dev.static_routes[2].discard
    assert dev.bgp is not None and dev.bgp.local_as == "65001"


def test_ios_to_eos() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "interface Management1\n   vrf Mgmt-vrf\n   ip address 192.168.255.11/24\n" in out
    assert "interface Port-Channel1\n" in out
    assert "   switchport trunk allowed vlan 10,20,99\n" in out
    assert "ip route 0.0.0.0/0 10.99.0.1\n" in out
    assert "banner motd\nAuthorised access only.\nEOF\n" in out
    text = report.to_text()
    assert "s3cret" not in text and "community #1 (ro): exact" in text
    assert report.counts()["skipped"] >= 1


def test_eos_to_ios() -> None:
    out, report = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert "interface GigabitEthernet0/0\n vrf forwarding Mgmt-vrf\n" in out
    assert "ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 192.168.255.1\n" in out
    assert "ip route vrf PROD 10.200.0.0 255.255.0.0 Null0\n" in out
    assert " ip address 10.255.0.1 255.255.255.254\n" in out
    assert "ntp server vrf Mgmt-vrf 10.0.0.123 key 3 prefer\n" in out
    assert " mtu 9198\n" in out
    # members of a port-channel are configured like it on IOS
    member = out.split("description spine-02\n", 1)[1].split("!", 1)[0]
    assert " switchport mode trunk\n" in member and " channel-group 10 mode active\n" in member
    assert "vrf MGMT" in report.to_text()


def test_port_map() -> None:
    port_map = read_port_map("# new access switch\nGi1/0/1 = Ethernet7\nTenGigabitEthernet1/1/1 = Ethernet49/1\n")
    assert port_map == {"Gi1/0/1": "Ethernet7", "TenGigabitEthernet1/1/1": "Ethernet49/1"}
    out, report = convert(sample("ios_access.cfg"), "ios", "eos",
                          {"GigabitEthernet1/0/1": "Ethernet7", "TenGigabitEthernet1/1/1": "Ethernet49/1"})
    assert "interface Ethernet7\n   description desk 1.01\n" in out
    assert "interface Ethernet49/1\n   description uplink core-01\n" in out
    statuses = {i.name: i.status for i in report.items.values() if i.kind == "interface"}
    assert statuses["TenGigabitEthernet1/1/1 -> Ethernet49/1"] == "exact"


def test_round_trip_keeps_the_model() -> None:
    first = parse(sample("ios_access.cfg"), "ios")
    eos, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    back = parse(eos, "eos")
    assert first.vlans.keys() == back.vlans.keys()
    assert first.system.ntp_servers == back.system.ntp_servers
    assert [(r.prefix, r.vrf, r.next_hop) for r in first.static_routes] == [
        (r.prefix, r.vrf, r.next_hop) for r in back.static_routes]
    assert back.interfaces["Port-channel1"].allowed_vlans == "10,20,99"
    assert back.interfaces["Ethernet2"].access_vlan == 10


def test_odd_values_are_reported_not_fatal() -> None:
    dev = parse("hostname x\ninterface Gi1/0/1\n switchport access vlan abc\n mtu big\nntp server\n", "ios")
    assert {u.text for u in dev.unparsed} >= {"switchport access vlan abc", "mtu big", "ntp server"}


def test_redact() -> None:
    from routershift.report import redact
    assert redact("username a privilege 15 secret 9 $9$abc") == "username a privilege 15 secret 9 <removed>"
    assert redact("user admin password ciphertext AQBx") == "user admin password ciphertext <removed>"
    assert redact("key 7 0822455D0A16") == "key 7 <removed>"


def test_cli(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from routershift.cli import main
    src = tmp_path / "in.cfg"
    src.write_text(sample("ios_access.cfg"))
    out, rep = tmp_path / "out.cfg", tmp_path / "report.json"
    assert main(["convert", "--from", "ios", "--to", "eos", str(src), "-o", str(out),
                 "--report", str(rep), "--report-format", "json"]) == 0
    assert out.read_text().startswith("hostname sw-access-01\n")
    assert '"source": "ios"' in rep.read_text()
    assert main(["convert", "--from", "ios", "--to", "eos", str(tmp_path / "missing.cfg")]) == 1

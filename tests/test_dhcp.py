import pytest
from helpers import sample

from routershift import dhcp as dhcp_text
from routershift.convert import PLATFORMS, convert, parse
from routershift.model import DhcpPool


def test_subtract_and_exclusions() -> None:
    ranges = dhcp_text.subtract("10.0.0.0/24", [], [("10.0.0.1", "10.0.0.9"), ("10.0.0.100", "10.0.0.100")])
    assert ranges == [("10.0.0.10", "10.0.0.99"), ("10.0.0.101", "10.0.0.254")]
    pool = DhcpPool("P", network="10.0.0.0/24", ranges=ranges)
    assert dhcp_text.exclusions(pool) == [("10.0.0.1", "10.0.0.9"), ("10.0.0.100", "10.0.0.100")]
    assert dhcp_text.subtract("10.0.0.0/24", [("10.0.0.50", "10.0.0.60")], []) == [("10.0.0.50", "10.0.0.60")]


def test_ios_reader() -> None:
    [pool] = parse(sample("ios_access.cfg"), "ios").dhcp_pools
    assert (pool.name, pool.network, pool.ranges, pool.default_routers, pool.dns_servers, pool.domain_name,
            pool.lease_seconds) == ("USERS", "10.10.0.0/24", [("10.10.0.21", "10.10.0.254")], ["10.10.0.1"],
                                    ["10.0.0.53", "10.0.1.53"], "example.net", 8 * 3600)


def test_eos_reader() -> None:
    device = parse(sample("eos_leaf.cfg"), "eos")
    [pool] = device.dhcp_pools
    assert (pool.name, pool.vrf, pool.ranges, pool.domain_name, pool.lease_seconds) == (
        "SERVERS", "PROD", [("10.100.0.100", "10.100.0.199")], "example.net", 86400)


def test_aoscx_reader() -> None:
    [pool] = parse(sample("aoscx_access.cfg"), "aoscx").dhcp_pools
    assert (pool.network, pool.vrf, pool.ranges, pool.lease_seconds) == (
        "10.10.0.0/24", "PROD", [("10.10.0.50", "10.10.0.250")], 12 * 3600)


def test_aoss_reader() -> None:
    text = ('dhcp-server pool "LAB"\n   network 10.5.0.0 255.255.255.0\n   range 10.5.0.10 10.5.0.99\n'
            '   default-router "10.5.0.1"\n   dns-server "10.0.0.53"\n   domain-name "lab.example"\n'
            '   lease 01:00:00\n   exit\ndhcp-server enable\n')
    device = parse(text, "aoss")
    [pool] = device.dhcp_pools
    assert (pool.name, pool.network, pool.ranges, pool.default_routers, pool.domain_name, pool.lease_seconds) == (
        "LAB", "10.5.0.0/24", [("10.5.0.10", "10.5.0.99")], ["10.5.0.1"], "lab.example", 86400)
    assert device.unparsed == []


def test_comware_reader() -> None:
    [pool] = parse(sample("comware_access.cfg"), "comware").dhcp_pools
    assert (pool.vrf, pool.ranges, pool.lease_seconds) == ("PROD", [("10.10.0.50", "10.10.0.254")], 12 * 3600)


def test_host_pools_are_flagged() -> None:
    text = "ip dhcp pool PRINTER\n host 10.10.0.50 255.255.255.0\n client-identifier 0100.1122.3344.55\n"
    for target in sorted(set(PLATFORMS) - {"junos", "nxos"}):
        out, report = convert(text, "ios", target)
        assert "PRINTER" not in out, target
        assert "PRINTER: skipped" in report.to_text(), target


def test_eos_serves_on_the_interface() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "interface Vlan10\n" not in out or "   dhcp server ipv4\n" not in out.split("interface Vlan10\n")[1]
    text = ("vlan 10\ninterface Vlan10\n ip address 10.10.0.1 255.255.255.0\n"
            "ip dhcp pool P\n network 10.10.0.0 255.255.255.0\n default-router 10.10.0.1 10.10.0.2\n")
    out, report = convert(text, "ios", "eos")
    assert "interface Vlan10\n   ip address 10.10.0.1/24\n   dhcp server ipv4\n" in out
    assert "EOS hands out one gateway" in report.to_text()


def test_infinite_lease() -> None:
    text = "ip dhcp pool P\n network 10.10.0.0 255.255.255.0\n lease infinite\n"
    for target in ("ios", "aoscx", "aoss", "comware"):
        [pool] = parse(convert(text, "ios", target)[0], target).dhcp_pools
        assert pool.lease_seconds == 0, target


@pytest.mark.parametrize("target", sorted(set(PLATFORMS) - {"junos", "nxos"}))
def test_every_writer_round_trips(target: str) -> None:
    text = ("ip dhcp excluded-address 10.20.0.1 10.20.0.9\nip dhcp excluded-address 10.20.0.200 10.20.0.254\n"
            "ip dhcp pool VOICE\n network 10.20.0.0 255.255.255.0\n default-router 10.20.0.1\n"
            " dns-server 10.0.0.53\n domain-name voice.example\n lease 2 0 30\n")
    first = parse(text, "ios")
    back = parse(convert(text, "ios", target)[0], target)
    [a], [b] = first.dhcp_pools, back.dhcp_pools
    assert (b.network, b.ranges, b.default_routers, b.dns_servers, b.domain_name, b.lease_seconds) == (
        a.network, a.ranges, a.default_routers, a.dns_servers, a.domain_name, a.lease_seconds), target
    assert a.ranges == [("10.20.0.10", "10.20.0.199")]
    assert back.unparsed == [], target

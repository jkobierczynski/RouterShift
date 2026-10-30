from helpers import sample

from routershift import vpn as vpn_text
from routershift.convert import convert, parse
from routershift.report import Report, redact


def test_ios_reader() -> None:
    device = parse(sample("ios_vpn.cfg"), "ios")
    assert device.unparsed == []
    v1, v2 = device.ike_policies["10"], device.ike_policies["PROP-V2"]
    assert (v1.version, v1.encryption, v1.integrity, v1.dh_groups, v1.lifetime, v1.authentication) == (
        1, ["aes-256"], ["sha256"], [14], 28800, "pre-share")
    assert (v2.version, v2.encryption, v2.integrity, v2.dh_groups) == (2, ["aes-256"], ["sha256"], [14])
    transform = device.ipsec_transforms["TS-AES"]
    assert (transform.encryption, transform.integrity, transform.mode) == ("aes-256", "sha256", "tunnel")
    profile, crypto_map = device.ipsec_peers
    assert (profile.profile, profile.ike_version, profile.pfs_group, vpn_text.peers_of(device, profile)) == (
        True, 2, 14, ["203.0.113.9"])
    assert (crypto_map.peer, crypto_map.acl, crypto_map.lifetime, crypto_map.ike_version) == (
        "198.51.100.2", "VPN-B", 3600, 1)
    assert {a: k.key for a, k in device.psks.items()} == {"198.51.100.2": "Sup3rKey", "203.0.113.9": "V2key!"}
    tunnel = device.interfaces["Tunnel10"]
    assert (tunnel.tunnel_mode, tunnel.tunnel_destination, tunnel.tunnel_profile) == ("ipsec", "203.0.113.9", "VTI")


def test_ios_round_trip_keeps_ikev2() -> None:
    out, report = convert(sample("ios_vpn.cfg"), "ios", "ios")
    assert "crypto ikev2 keyring IKEV2-KEYS\n peer 203.0.113.9\n  address 203.0.113.9\n  pre-shared-key V2key!" in out
    assert "set ikev2-profile IKEV2-VTI" in out
    back = parse(out, "ios")
    assert back.unparsed == []
    assert [p.ike_version for p in back.ipsec_peers] == [2, 1]
    assert "V2key!" not in report.to_text()


def test_encrypted_key_becomes_a_placeholder() -> None:
    out, report = convert(sample("ios_access.cfg"), "ios", "comware")
    assert f"pre-shared-key address 203.0.113.9 255.255.255.255 key simple {vpn_text.PLACEHOLDER_KEY}" in out
    assert "pre-shared-key address 198.51.100.2 255.255.255.255 key simple Sup3rKey" in out
    assert "stored encrypted in the source" in report.to_text()


def test_eos_reader_and_writer() -> None:
    device = parse(sample("eos_leaf.cfg"), "eos")
    [peer] = device.ipsec_peers
    assert (peer.name, peer.ike_version, peer.pfs_group, peer.lifetime, peer.ike_policies) == (
        "VTI", 2, 14, 3600, ["IKE-AES"])
    assert device.ike_policies["IKE-AES"].lifetime == 8 * 3600
    assert device.psks["203.0.113.17"].key == ""  # type 7
    out, _ = convert(sample("ios_vpn.cfg"), "ios", "eos")
    assert "ip security\n   ike policy 10\n      version 1\n      encryption aes256" in out
    assert "   profile VTI\n      ike-policy PROP-V2\n      sa-policy TS-AES\n      connection start\n" in out
    assert "   tunnel source interface " in out and "   tunnel ipsec profile VTI" in out


def test_comware_reader() -> None:
    device = parse(sample("comware_access.cfg"), "comware")
    [peer] = device.ipsec_peers
    assert (peer.name, peer.seq, peer.peer, peer.acl, peer.pfs_group, peer.ike_policies) == (
        "HQ", 10, "198.51.100.6", "USERS-IN", 14, ["10"])
    assert device.interfaces["Ethernet1/0/48"].crypto_map == "HQ"
    assert device.psks["198.51.100.6"].key == ""  # cipher


def test_comware_tunnel_interface() -> None:
    text = ("interface Tunnel1 mode ipsec\n ip address 172.16.0.1 255.255.255.252\n source LoopBack0\n"
            " destination 203.0.113.9\n tunnel protection ipsec profile VTI\n#\n")
    tunnel = parse(text, "comware").interfaces["Tunnel1"]
    assert (tunnel.tunnel_mode, tunnel.tunnel_source, tunnel.tunnel_destination, tunnel.tunnel_profile) == (
        "ipsec", "Loopback0", "203.0.113.9", "VTI")


def test_comware_writes_ikev1_only() -> None:
    out, report = convert(sample("ios_vpn.cfg"), "ios", "comware")
    assert "ipsec policy VPN 10 isakmp\n transform-set TS-AES\n security acl name VPN-B\n remote-address 198.51.100.2" in out
    assert "interface Tunnel10 mode ipsec" in out
    assert "tunnel protection ipsec profile VTI" not in out
    assert "IKEv2 is not written for Comware yet" in report.to_text()


def test_missing_algorithm_takes_the_next_stronger() -> None:
    report = Report()
    assert vpn_text.pick(vpn_text.EOS_ENC, "aes-192", report, "x") == "aes256"
    assert "aes-192 is not offered; aes-256 is written" in report.to_text()


def test_aos_switches_report_every_connection() -> None:
    for target, name in (("aoscx", "AOS-CX"), ("aoss", "AOS-S")):
        out, report = convert(sample("ios_vpn.cfg"), "ios", target)
        assert "crypto" not in out and "ipsec" not in out
        assert report.to_text().count(f"{name} switches do not terminate IPsec") == 2
        assert "tunnel interfaces are not converted" in report.to_text()


def test_keys_are_masked() -> None:
    for line in ("pre-shared-key address 192.0.2.1 255.255.255.255 key simple Secret1",
                 "pre-shared-key local Secret1", "shared-key Secret1", "crypto isakmp key Secret1 address 192.0.2.1"):
        assert "Secret1" not in redact(line), line

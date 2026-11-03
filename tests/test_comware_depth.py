"""Comware at the depth of the other targets: the EOS border leaf converts with nothing left as not written yet, the
fabric (VSIs, the distributed gateway, layer 3 VNIs, M-LAG, the ethernet segment), MACsec, queuing, multicast, the
route policy lists, OSPF and BGP options and the management settings are written, and read back."""

from typing import Tuple

from helpers import sample

from routershift.convert import convert, parse

BORDER = sample("eos_border_leaf.cfg")


def _convert() -> Tuple[str, str]:
    out, report = convert(BORDER, "eos", "comware")
    return out, report.to_text()


def test_nothing_left_as_not_written_yet() -> None:
    _, text = _convert()
    assert "not written for Comware yet" not in text


def test_fabric() -> None:
    out, _ = _convert()
    assert "tunnel global source-address 10.255.1.21\n" in out
    assert ("vsi VLAN100\n gateway vsi-interface 100\n vxlan 10100\n evpn encapsulation vxlan\n"
            "  route-distinguisher 10.255.0.21:50001\n") in out
    assert "interface Vsi-interface3900\n" in out and " l3-vni 50002\n" in out
    assert " service-instance 100\n" in out and "  xconnect vsi VLAN100\n" in out
    assert "m-lag system-number 1\n" in out and "m-lag keepalive ip destination 10.100.10.22 vpn-instance MGMT\n" in out
    assert " port m-lag peer-link 1\n" in out and " port m-lag group 10\n" in out
    assert " esi 0000.0000.0021.0022.0020\n" in out


def test_security_queuing_and_multicast() -> None:
    out, _ = _convert()
    assert "mka policy MACSEC-DCI\n macsec cipher-suite gcm-aes-xpn-256\n" in out
    assert "acl mac name MACL-PROTECT-LEGACY\n" in out
    assert "qos map-table dscp-lp\n" in out and "qos qmprofile QP-FABRIC\n" in out
    assert "anycast-rp 10.255.0.1 10.255.0.11\n" in out
    assert " igmp-snooping general-query source-ip 10.1.100.2\n" in out
    assert "radius dynamic-author server\n" in out


def test_policy_routing_and_management() -> None:
    out, _ = _convert()
    assert "ip community-list basic CL-FROM-ISP-A permit 65021:1001\n" in out
    assert "ip as-path AS-ISP-A permit ^64496( 64496)*$\n" in out
    assert " spf-schedule-interval 5 50 200\n" in out and " lsdb-overflow-limit 12000\n" in out
    assert "router id 10.255.0.21\n" in out and "bfd multi-hop detect-multiplier 3\n" in out
    assert "ip load-sharing mode per-flow src-ip dest-ip src-port dest-port\n" in out
    assert " info-center loghost vpn-instance MGMT 10.100.1.50 port 6514\n" in out
    assert " info-center logbuffer size 1024\n" in out or "info-center logbuffer size 1024\n" in out
    assert "lldp timer tx-interval 15\n" in out and "password-control length 12\n" in out
    assert "netconf ssh server enable\n" in out and "header login %" in out


def test_reads_back() -> None:
    out, _ = _convert()
    source, back = parse(BORDER, "eos"), parse(out, "comware")
    assert [u.text for u in back.unparsed] == []
    assert source.vxlan is not None and back.vxlan is not None
    assert back.vxlan.vlan_vnis == source.vxlan.vlan_vnis and back.vxlan.vrf_vnis == source.vxlan.vrf_vnis
    assert back.mlag is not None and back.mlag.heartbeat == "10.100.10.22" and back.mlag.reload_delay == 300
    assert list(back.macsec_profiles) == ["MACSEC-DCI"] and list(back.mac_acls) == ["MACL-PROTECT-LEGACY"]
    assert list(back.qos_profiles) == ["QP-FABRIC", "QP-EDGE"] and back.pim_rps == ["10.255.0.1"]
    assert back.system.router_id == "10.255.0.21" and back.bfd_multihop == (300, 300, 3)
    assert back.anycast_mac == source.anycast_mac
    assert back.interfaces["Vlan100"].virtual_ipv4 == ["10.1.100.1/24"]

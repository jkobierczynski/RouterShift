"""BFD multihop and slow timers, BFD templates, ECMP hashing and BGP options between EOS and IOS."""
from routershift.convert import convert, parse

EOS = """hostname leaf1
vrf instance INET
ip routing
ip routing vrf INET
ip load-sharing trident fields ip source-ip destination-ip source-port destination-port
router bfd
   multihop interval 300 min-rx 300 multiplier 3
   slow-timer 2000
router ospf 100 vrf INET
   network 10.0.0.0/24 area 0.0.0.0
router bgp 65021
   router-id 10.255.0.21
   bgp asn notation asdot
   vrf INET
      rd 10.255.0.21:3
      bgp bestpath med missing-as-worst
      redistribute ospf match internal
      redistribute ospf match external
"""

IOS = """hostname core1
ip cef load-sharing algorithm universal
bfd-template single-hop BFD-FAST
 interval min-tx 150 min-rx 150 multiplier 3
bfd slow-timers 3000
interface GigabitEthernet1/0/1
 no switchport
 ip address 10.0.0.1 255.255.255.254
 bfd template BFD-FAST
router ospf 1
 network 10.0.0.0 0.0.0.255 area 0
router bgp 65000
 bgp asnotation dot
 bgp bestpath med missing-as-worst
 address-family ipv4
  redistribute ospf 1 match internal external 1 external 2
 exit-address-family
"""


def _clean(text: str, brand: str) -> None:
    left = [u.text for u in parse(text, brand).unparsed]
    assert left == [], left


def test_eos_to_ios() -> None:
    dev = parse(EOS, "eos")
    _clean(EOS, "eos")
    assert dev.bfd_multihop == (300, 300, 3) and dev.bfd_slow_timer == 2000
    assert dev.ecmp_platform == "trident" and len(dev.ecmp_hash) == 4
    assert dev.bgp is not None and dev.bgp.asdot
    assert dev.bgp.vrfs["INET"].ospf_match == ["internal", "external"] and dev.bgp.vrfs["INET"].med_missing_as_worst
    out, report = convert(EOS, "eos", "ios")
    assert "bfd-template multi-hop RS-MULTIHOP\n interval min-tx 300 min-rx 300 multiplier 3\n" in out
    assert "bfd slow-timers 2000\n" in out
    assert "ip cef load-sharing algorithm include-ports source destination\n" in out
    assert " bgp asnotation dot\n" in out and " bgp bestpath med missing-as-worst\n" in out
    assert "match internal external 1 external 2" in out
    text = report.to_text()
    assert "bfd map ipv4" in text and "whole BGP process" in text
    _clean(out, "ios")


def test_ios_to_eos() -> None:
    dev = parse(IOS, "ios")
    _clean(IOS, "ios")
    port = dev.interfaces["Ethernet1/0/1"]
    assert (port.bfd_interval, port.bfd_min_rx, port.bfd_multiplier) == (150, 150, 3)
    out, report = convert(IOS, "ios", "eos")
    assert "router bfd\n   slow-timer 3000\n" in out
    assert "ip load-sharing trident fields ip source-ip destination-ip\n" in out
    assert "   bfd interval 150 min-rx 150 multiplier 3\n" in out
    assert "   bgp asn notation asdot\n" in out and "   bgp bestpath med missing-as-worst\n" in out
    assert "redistribute ospf match internal\n" in out and "redistribute ospf match external\n" in out
    assert "use sand on 7280R" in report.to_text()
    _clean(out, "eos")

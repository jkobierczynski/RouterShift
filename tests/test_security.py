"""CoPP, MACsec, MAC ACLs, the 802.1X fail VLAN, DHCP option 82 and RADIUS CoA between EOS and IOS."""
from routershift.convert import convert, parse

EOS = """hostname leaf1
vrf instance MGMT
ip access-list ACL-CPP-MGMT
   10 permit tcp 10.0.0.0/8 any eq ssh
system control-plane
   ip access-group ACL-CPP-MGMT vrf MGMT in
policy-map type copp copp-system-policy
   class copp-system-bgp
      shape pps 5000
mac security
   fips restrictions
   profile MACSEC-DCI
      cipher aes256-gcm-xpn
      key 0a 7 0822455D0A16
      mka key-server priority 10
      mka session rekey-period 3600
mac access-list MACL-PROTECT-LEGACY
   10 deny any any vlan 900 0xfff protocol 0x88cc
   20 permit any any
ip dhcp snooping
ip dhcp snooping vlan 900
ip dhcp snooping information option
dot1x dynamic-authorization
vlan 900
interface Ethernet1
   switchport access vlan 900
   mac access-group MACL-PROTECT-LEGACY in
   dot1x authentication failure action traffic allow vlan 900
interface Ethernet2
   no switchport
   ip address 10.1.1.0/31
   mac security profile MACSEC-DCI
"""

IOS = """hostname core1
ip access-list extended ACL-COPP-SSH
 permit tcp 10.0.0.0 0.255.255.255 any eq 22
class-map match-all CM-COPP-SSH
 match access-group name ACL-COPP-SSH
policy-map PM-COPP
 class CM-COPP-SSH
  police cir 64000
control-plane
 service-policy input PM-COPP
key chain KC-DCI macsec
 key 0A
  cryptographic-algorithm aes-256-cmac
  key-string 7 0822455D0A16
mka policy DCI
 key-server priority 10
 sak-rekey interval 3600
 macsec-cipher-suite gcm-aes-256
interface TenGigabitEthernet1/0/1
 no switchport
 ip address 10.1.1.0 255.255.255.254
 macsec network-link
 mka policy DCI
 mka pre-shared-key key-chain KC-DCI
"""


def _no_unparsed(text: str, brand: str) -> None:
    left = [u.text for u in parse(text, brand).unparsed]
    assert left == [], left


def test_eos_security_to_ios() -> None:
    dev = parse(EOS, "eos")
    assert dev.control_plane is not None and dev.control_plane.acls == {"MGMT": "ACL-CPP-MGMT"}
    assert dev.macsec_profiles["MACSEC-DCI"].cipher and dev.macsec_fips
    assert "MACL-PROTECT-LEGACY" in dev.mac_acls and dev.dhcp_option82 and dev.aaa.coa
    assert dev.interfaces["Ethernet1"].dot1x_fail_vlan == 900
    out, report = convert(EOS, "eos", "ios")
    assert "mka policy MACSEC-DCI\n" in out and " macsec network-link\n" in out
    assert "mac access-list extended MACL-PROTECT-LEGACY\n" in out
    assert "ip dhcp snooping information option\n" in out
    assert "aaa server radius dynamic-author\n" in out
    assert "authentication event fail action authorize vlan 900" in out
    text = report.to_text()
    assert "needs review" in text.lower() or "review" in text.lower()
    _no_unparsed(out, "ios")
    back, _ = convert(out, "ios", "eos")
    assert "profile MACSEC-DCI\n" in back and "mac access-list MACL-PROTECT-LEGACY\n" in back
    _no_unparsed(back, "eos")


def test_ios_security_to_eos() -> None:
    dev = parse(IOS, "ios")
    assert dev.control_plane is not None and dev.control_plane.classes
    assert "DCI" in dev.macsec_profiles
    out, report = convert(IOS, "ios", "eos")
    assert "policy-map type copp copp-system-policy\n" in out
    assert "mac security\n" in out and "mac security profile DCI" in out
    _no_unparsed(out, "eos")
    again, _ = convert(out, "eos", "ios")
    assert "control-plane\n service-policy input" in again
    _no_unparsed(again, "ios")


def test_security_is_reported_on_other_targets() -> None:
    out, report = convert(EOS, "eos", "junos")
    assert "not written for" in report.to_text()

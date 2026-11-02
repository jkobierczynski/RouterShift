"""sFlow and sampled NetFlow standing in for each other, SPAN ACL filters, LLDP timers and TWAMP between EOS and
IOS."""
from routershift.convert import convert, parse

EOS = """hostname leaf1
vrf instance MGMT
lldp timer 15
lldp hold-time 60
lldp management-address Management1
lldp management-address vrf MGMT
sflow sample 16384
sflow polling-interval 30
sflow vrf MGMT destination 10.100.0.70 6343
sflow vrf MGMT source-interface Management1
sflow extension bgp
sflow run
ip access-list ACL-SPAN
   10 permit ip 10.0.0.0/8 any
monitor session SPAN-DMZ source Ethernet1 rx
monitor session SPAN-DMZ destination Ethernet2
monitor session SPAN-DMZ ip access-group ACL-SPAN
monitor twamp
   twamp-light
      reflector defaults
         listen port 862
interface Ethernet1
   no switchport
   ip address 10.1.1.0/31
interface Ethernet2
   no sflow enable
interface Management1
   vrf MGMT
   ip address 10.100.10.21/24
"""

IOS = """hostname core1
lldp run
lldp timer 20
lldp holdtime 80
flow exporter FE-1
 destination 10.250.20.10 vrf Mgmt-intf
 transport udp 2055
 export-protocol netflow-v9
flow monitor FM-1
 exporter FE-1
 record netflow ipv4 original-input
sampler SMP
 mode random 1 out-of 100
ip sla server twamp
 port 5000
ip sla responder twamp
monitor session 1 source interface GigabitEthernet1/0/1 both
monitor session 1 destination interface GigabitEthernet1/0/2
monitor session 1 filter ip access-group ACL-SPAN
interface GigabitEthernet1/0/1
 ip flow monitor FM-1 sampler SMP input
interface GigabitEthernet1/0/2
"""


def _clean(text: str, brand: str) -> None:
    left = [u.text for u in parse(text, brand).unparsed]
    assert left == [], left


def test_eos_monitoring_to_ios() -> None:
    dev = parse(EOS, "eos")
    assert dev.sflow is not None and dev.sflow.extensions == ["bgp"] and dev.sflow.source_vrf == "MGMT"
    assert dev.mirror_sessions[0].acl == "ACL-SPAN"
    assert (dev.management.lldp_timer, dev.management.lldp_holdtime) == (15, 60)
    assert (dev.twamp_port, dev.twamp_mode) == (862, "light")
    _clean(EOS, "eos")
    out, report = convert(EOS, "eos", "ios")
    assert "sampler RS-SAMPLER\n mode random 1 out-of 16384\n" in out
    assert " ip flow monitor RS-MONITOR sampler RS-SAMPLER input\n" in out
    assert "monitor session 1 filter ip access-group ACL-SPAN\n" in out
    assert "lldp timer 15\nlldp holdtime 60\n" in out
    assert "ip sla server twamp\nip sla responder twamp\n" in out
    text = report.to_text()
    assert "written as sampled Flexible NetFlow" in text and "TWAMP light" in text
    assert "no global LLDP management address" in text
    _clean(out, "ios")
    back = parse(out, "ios")
    assert back.netflow is not None and back.netflow.sample_rate == 16384
    assert back.interfaces["Ethernet1/0/1"].flow == "input"


def test_ios_monitoring_to_eos() -> None:
    dev = parse(IOS, "ios")
    assert dev.netflow is not None and dev.netflow.sample_rate == 100
    assert (dev.twamp_port, dev.twamp_mode) == (5000, "full")
    _clean(IOS, "ios")
    out, report = convert(IOS, "ios", "eos")
    assert "sflow sample 100\n" in out and "sflow vrf Mgmt-intf destination 10.250.20.10 2055\n" in out
    assert "sflow run\n" in out and "   no sflow enable\n" in out
    assert "monitor session 1 ip access-group ACL-SPAN\n" in out
    assert "lldp timer 20\nlldp hold-time 80\n" in out
    assert "monitor twamp\n   twamp-light\n      reflector defaults\n         listen port 5000\n" in out
    assert "written as sFlow" in report.to_text()
    _clean(out, "eos")
    again, _ = convert(out, "eos", "ios")
    assert "mode random 1 out-of 100" in again and "ip sla server twamp\n port 5000\n" in again


def test_monitoring_on_other_targets() -> None:
    _, report = convert(EOS, "eos", "junos")
    assert "the TWAMP reflector" in report.to_text()

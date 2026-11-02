"""PTP and event handlers (EOS) <-> EEM applets (IOS)."""
from routershift.convert import convert, parse

EOS = """hostname leaf1
ptp mode boundary
ptp priority1 128
ptp priority2 21
ptp domain 24
ptp clock-identity 00:1c:73:ff:fe:00:00:21
ptp message-type event dscp 48 default
event-handler ISP-A-DOWN
   trigger on-intf Ethernet25/1 operstatus
   action bash logger -p local0.warning "ISP-A uplink state change"
   delay 5
event-handler HIGH-CPU
   trigger on-counters
      poll interval 60
      condition cpu.utilization > 85
   action bash logger -p local0.crit "CPU above 85 percent"
event-handler SAVED
   trigger on-startup-config
   action bash /mnt/flash/backup.sh
event-handler LOGS
   trigger on-logging
      regex BGP-5-ADJCHANGE
   action bash
      FastCli -p 15 -c "show ip bgp summary"
      logger -p local0.info "bgp changed"
      EOF
interface Ethernet25/1
   no switchport
   ip address 10.0.0.1/31
   ptp enable
   ptp announce interval 0
   ptp sync-message interval -3
   ptp delay-mechanism e2e
"""

IOS = """hostname core1
ptp mode boundary pdelay-req
ptp domain 0
event manager applet WAN-DOWN
 description Log when the uplink tracking fails
 event track 10 state down
 action 1.0 syslog priority critical msg "uplink lost"
 action 2.0 cli command "enable"
 action 3.0 cli command "show ip route summary"
event manager applet CPU
 event snmp oid 1.3.6.1.4.1.9.9.109.1.1.1.1.6.1 get-type exact entry-op ge entry-val 90 poll-interval 30
 action 1.0 syslog msg "cpu high"
track 10 interface GigabitEthernet1/0/1 line-protocol
interface GigabitEthernet1/0/1
 no switchport
 ip address 10.0.0.1 255.255.255.254
 ptp enable
 ptp sync interval -4
"""


def _clean(text: str, brand: str) -> None:
    left = [u.text for u in parse(text, brand).unparsed]
    assert left == [], left


def test_eos_to_ios() -> None:
    dev = parse(EOS, "eos")
    _clean(EOS, "eos")
    assert dev.ptp is not None and (dev.ptp.mode, dev.ptp.domain, dev.ptp.dscp_event) == ("boundary", 24, 48)
    h = dev.event_handlers
    assert (h["HIGH-CPU"].trigger, h["HIGH-CPU"].pattern, h["HIGH-CPU"].poll_interval) == ("cpu", "> 85", 60)
    assert [a.kind for a in h["LOGS"].actions] == ["cli", "syslog"] and h["ISP-A-DOWN"].delay == 5
    out, report = convert(EOS, "eos", "ios")
    assert "ptp mode boundary delay-req\nptp priority1 128\n" in out
    assert " ptp enable\n ptp announce interval 0\n ptp sync interval -3\n" in out
    assert 'event syslog pattern "Interface GigabitEthernet' in out and " action 1.0 wait 5\n" in out
    assert "entry-op gt entry-val 85 poll-interval 60" in out
    assert 'event syslog pattern "BGP-5-ADJCHANGE"' in out and ' cli command "show ip bgp summary"' in out
    text = report.to_text()
    assert "Catalyst 9000" in text and "event handler SAVED: skipped" in text
    _clean(out, "ios")
    back = parse(out, "ios")
    assert back.event_handlers["ISP-A-DOWN"].trigger == "interface" and back.event_handlers["ISP-A-DOWN"].delay == 5
    assert [i.ptp_delay_mechanism for i in back.interfaces.values() if i.ptp] == ["e2e"]


def test_ios_to_eos() -> None:
    dev = parse(IOS, "ios")
    _clean(IOS, "ios")
    assert dev.interfaces["Ethernet1/0/1"].ptp_delay_mechanism == "p2p"
    out, report = convert(IOS, "ios", "eos")
    assert "ptp mode boundary\n" in out and "   ptp delay-mechanism p2p\n" in out
    assert "   ptp sync-message interval -4\n" in out
    assert "event-handler WAN-DOWN\n   trigger on-intf Ethernet1 operstatus\n" in out
    assert "      FastCli -p 15 -c 'show ip route summary'\n" in out
    assert "condition cpu.utilization >= 90" in out
    assert "not only when it goes down" in report.to_text()
    _clean(out, "eos")
    again, _ = convert(out, "eos", "ios")
    assert "ptp mode boundary pdelay-req\n" in again and "entry-op ge entry-val 90 poll-interval 30" in again


def test_other_targets() -> None:
    _, report = convert(EOS, "eos", "comware")
    assert "event handlers and EEM applets" in report.to_text()

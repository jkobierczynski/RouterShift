from helpers import sample

from routershift import monitor as monitor_text
from routershift.convert import convert, parse


def _sources(text: str, platform: str) -> list:
    return [(s.name, s.sources, s.destination) for s in parse(text, platform).mirror_sessions]


def test_readers() -> None:
    assert _sources(sample("ios_access.cfg"), "ios") == [("1", {"Ethernet1/0/1": "rx"}, "Ethernet1/0/2")]
    assert _sources(sample("aoss_edge.cfg"), "aoss") == [("1", {"Ethernet1": "both", "Ethernet2": "rx"}, "Ethernet3")]
    comware = parse(sample("comware_access.cfg"), "comware")
    assert comware.mirror_sessions[0].sources == {"Ethernet1/0/1": "rx", "Ethernet1/0/2": "both"}
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert eos.sflow is not None and (eos.sflow.sample_rate, eos.sflow.source_interface) == (16384, "Loopback0")
    assert not eos.interfaces["Ethernet49/1"].sflow and eos.interfaces["Ethernet1"].sflow  # no sflow enable
    cx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert cx.sflow is not None and (cx.sflow.collectors[0].vrf, cx.sflow.agent) == ("mgmt", "10.99.0.2")
    assert [i.name for i in monitor_text.sflow_ports(cx)] == ["Ethernet1/1/1", "Ethernet1/1/2"]
    ios = parse(sample("ios_access.cfg"), "ios")
    assert ios.netflow is not None and (ios.netflow.version, ios.netflow.source_interface) == (9, "Vlan99")
    assert [(c.address, c.port) for c in ios.netflow.collectors] == [("10.0.0.9", 2055)]
    assert comware.netflow is not None and comware.interfaces["Ethernet1/0/1"].flow == "input"


def test_ios_port_ranges_and_traditional_netflow() -> None:
    text = ("interface GigabitEthernet1/0/1\ninterface GigabitEthernet1/0/2\ninterface GigabitEthernet1/0/3\n"
            " ip flow ingress\n ip flow egress\n"
            "ip flow-export destination 10.0.0.9 9996\nip flow-export version 5\n"
            "monitor session 2 source interface Gi1/0/1 - 2 tx\nmonitor session 2 destination interface Gi1/0/3\n")
    dev = parse(text, "ios")
    assert dev.mirror_sessions[0].sources == {"Ethernet1/0/1": "tx", "Ethernet1/0/2": "tx"}
    assert dev.netflow is not None and dev.netflow.version == 5 and dev.interfaces["Ethernet1/0/3"].flow == "both"
    assert not dev.unparsed
    out, _ = convert(text, "ios", "ios")
    assert " ip flow monitor RS-MONITOR input\n ip flow monitor RS-MONITOR output\n" in out
    assert " transport udp 9996\n export-protocol netflow-v5\n" in out


def test_writers() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoscx")
    assert "mirror session 1\n    source interface 1/1/1 both\n    destination interface 1/1/2\n    enable\n" in out
    assert "sflow\nsflow collector 10.0.0.10\nsflow agent-ip 10.255.255.1\n" in out
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "eos")
    assert "sflow vrf mgmt destination 10.0.0.10 6343\nsflow source 10.99.0.2\nsflow run\n" in out
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "aoss")
    assert "mirror 1 port 3\n" in out and "   monitor all out mirror 1\n" in out
    assert "sflow 1 sampling 1-2 4096\nsflow 1 polling 1-2 20\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert "mirroring-group 1 mirroring-port GigabitEthernet1/0/1 inbound\n" in out
    assert "ip netstream export host 10.0.0.9 2055\nip netstream export version 9\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "flow exporter RS-EXPORT-1\n destination 10.0.0.9\n source Vlan99\n transport udp 2055\n" in out
    assert "monitor session 1 source interface GigabitEthernet1/0/2\n" in out


def test_reports() -> None:
    _, report = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert "IOS has no sFlow" in report.to_text()
    assert "written as session 1" in report.to_text()
    _, report = convert(sample("comware_access.cfg"), "comware", "aoss")
    assert "AOS-S: NetFlow is not written" in report.to_text()
    text = "flow monitor M\n record CUSTOM\ninterface GigabitEthernet1/0/1\n ip flow monitor M input\n"
    _, report = convert(text, "ios", "ios")
    assert "flow record CUSTOM written as netflow ipv4 original-input" in report.to_text()
    text = "".join(f"monitor session {n} source interface Gi1/0/1\nmonitor session {n} destination interface Gi1/0/2\n"
                   for n in (1, 2, 3, 4, 5)) + "interface GigabitEthernet1/0/1\ninterface GigabitEthernet1/0/2\n"
    out, report = convert(text, "ios", "aoscx")
    assert out.count("mirror session") == 4 and "AOS-CX has 4 mirror sessions" in report.to_text()

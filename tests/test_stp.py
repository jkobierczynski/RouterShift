from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert ios.stp.vlan_priority == {10: 8192, 20: 8192, 99: 8192}
    port = ios.interfaces["Ethernet1/0/2"]
    assert (port.stp_guard, port.stp_cost, port.stp_port_priority) == ("root", 100, 64)
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert (eos.stp.priority, eos.stp.region, eos.stp.revision, eos.stp.instances) == (
        {0: 4096, 1: 8192}, "DC", 2, {1: [100, 200]})
    aoscx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert aoscx.stp.vlan_priority == {10: 8192, 20: 8192}  # a multiplier of 4096
    assert aoscx.interfaces["Ethernet1/1/2"].stp_port_priority == 64  # a multiplier of 16
    aoss = parse(sample("aoss_edge.cfg"), "aoss")
    assert (aoss.stp.priority, aoss.stp.region, aoss.stp.instances) == ({0: 4096, 1: 8192}, "EDGE", {1: [10, 20]})
    comware = parse(sample("comware_access.cfg"), "comware")
    assert comware.stp.priority == {0: 8192}
    assert comware.interfaces["Ethernet1/0/2"].stp_guard == "root"


def test_mst_region_writers() -> None:
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "ios")
    assert ("spanning-tree mst 0 priority 4096\nspanning-tree mst 1 priority 8192\nspanning-tree mst configuration\n"
            " name DC\n revision 2\n instance 1 vlan 100,200\n") in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "comware")
    assert ("stp region-configuration\n region-name DC\n revision-level 2\n instance 1 vlan 100 200\n"
            " active region-configuration\n") in out
    assert " stp instance 1 priority 8192\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoss")
    assert 'spanning-tree config-name "DC"\nspanning-tree config-revision 2\nspanning-tree instance 1 vlan 100 200\n' \
           "spanning-tree priority 1\nspanning-tree instance 1 priority 2\n" in out


def test_mst_to_pvst_writes_each_vlan() -> None:
    text = sample("aoss_edge.cfg").replace("spanning-tree\n", "spanning-tree\nspanning-tree mode rapid-pvst\n", 1)
    assert parse(text, "aoss").stp.region == "EDGE"
    out, report = convert(text, "aoss", "ios")
    assert "spanning-tree vlan 10,20 priority 8192" in out
    assert "the instance priorities are written per VLAN" in report.to_text()
    assert "the MST region is not written" in report.to_text()


def test_different_vlan_priorities_take_the_lowest_for_one_tree() -> None:
    text = "spanning-tree mode rapid-pvst\nvlan 10\nvlan 20\nspanning-tree vlan 10 priority 4096\n" \
           "spanning-tree vlan 20 priority 8192\n"
    out, report = convert(text, "ios", "comware")
    assert " stp vlan 10 priority 4096\n stp vlan 20 priority 8192\n" in out  # Comware PVST keeps them
    text = text.replace("rapid-pvst", "mst")
    out, report = convert(text, "ios", "eos")
    assert "spanning-tree mst 0 priority 4096" in out
    assert "the lowest, 4096, is written for all" in report.to_text()


def test_rstp_keeps_one_tree() -> None:
    out, report = convert(sample("eos_leaf.cfg").replace("spanning-tree mode mstp", "spanning-tree mode rstp"),
                          "eos", "eos")
    assert "spanning-tree priority 4096" in out and "mst 1" not in out
    assert "only the priority of instance 0 is written" in report.to_text()


def test_port_writers() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "    spanning-tree root-guard\n    spanning-tree cost 100\n    spanning-tree port-priority 4\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "aoss")
    assert "spanning-tree 2 root-guard\n" in out and "spanning-tree 2 path-cost 100\n" in out
    assert "spanning-tree 2 priority 4\n" in out
    out, _ = convert(sample("aoscx_access.cfg"), "aoscx", "comware")
    assert " stp port bpdu-filter enable\n stp port priority 64\n" in out
    out, report = convert(sample("eos_leaf.cfg"), "eos", "aoss")
    assert "AOS-S has no spanning tree loop guard" in report.to_text()

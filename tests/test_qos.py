from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert (ios.qos_classes["VOICE"].dscp, ios.qos_classes["VIDEO"].acl) == ([46, 40], "VIDEO")
    assert ios.qos_classes["VIDEO"].match_all and not ios.qos_classes["VOICE"].match_all
    actions = ios.qos_policies["EDGE-IN"].actions
    assert [(a.qos_class, a.set_dscp, a.police_kbps) for a in actions] == [
        ("VOICE", 46, 2000), ("VIDEO", 34, None), ("class-default", 0, None)]
    port = ios.interfaces["Ethernet1/0/1"]
    assert (port.qos_policy_in, port.qos_trust) == ("EDGE-IN", "dscp")
    eos = parse(sample("eos_leaf.cfg"), "eos")
    assert [(a.qos_class, a.set_dscp, a.police_kbps) for a in eos.qos_policies["SERVERS-QOS"].actions] == [
        ("BACKUP", 10, 50000)]
    aoscx = parse(sample("aoscx_access.cfg"), "aoscx")
    assert aoscx.qos_classes["VOICE"].dscp == [46]
    assert aoscx.qos_classes["SIGNALLING"].acl == "SIGNALLING"  # its entries become an ACL of the same name
    assert aoscx.interfaces["Ethernet1/1/1"].qos_policy_in == "DESK-IN"
    aoss = parse(sample("aoss_edge.cfg"), "aoss")
    assert aoss.qos_classes["VOICE"].dscp == [46]  # 0.0.0.0 255.255.255.255 is any
    assert [(a.qos_class, a.set_dscp) for a in aoss.qos_policies["DESK-IN"].actions] == [
        ("VOICE", 46), ("class-default", 0)]
    comware = parse(sample("comware_access.cfg"), "comware")
    assert comware.qos_classes["WEB"].acl == "USERS-IN"
    assert [(a.qos_class, a.set_dscp, a.police_kbps) for a in comware.qos_policies["DESK-IN"].actions] == [
        ("VOICE", 46, 1000), ("WEB", 18, None)]


def test_writers() -> None:
    out, _ = convert(sample("ios_access.cfg"), "ios", "eos")
    assert "class-map type qos match-any VOICE\n   match dscp 46 40\n" in out
    assert "      police rate 2000 kbps burst-size 250 kbytes\n" in out
    out, _ = convert(sample("ios_access.cfg"), "ios", "comware")
    assert "traffic behavior EDGE-IN-VOICE\n remark dscp ef\n car cir 2000 red discard\n" in out
    assert " classifier default-class behavior EDGE-IN-class-default\n" in out
    assert " qos apply policy EDGE-IN inbound\n qos trust dscp\n" in out
    out, _ = convert(sample("comware_access.cfg"), "comware", "ios")
    assert "class-map match-all WEB\n match access-group name USERS-IN\n" in out
    assert "  police cir 1000000 conform-action transmit exceed-action drop\n" in out
    out, _ = convert(sample("eos_leaf.cfg"), "eos", "aoss")
    assert 'class ipv4 "BACKUP"\n   10 match tcp any any eq 10000\n' in out
    assert '   10 class ipv4 "BACKUP" action dscp 10 action rate-limit kbps 50000\n' in out


def test_classes_take_no_remarks_or_logging() -> None:
    out, _ = convert(sample("comware_access.cfg"), "comware", "aoscx")
    block = out.split("class ip WEB\n", 1)[1].split("\npolicy", 1)[0]
    assert "comment" not in block and " log" not in block and "ignore any any any" in block


def test_limits_are_reported() -> None:
    _, report = convert(sample("ios_access.cfg"), "ios", "aoscx")
    assert "AOS-CX has no default class in a policy" in report.to_text()
    text = sample("ios_access.cfg").replace(" service-policy input EDGE-IN\n mls qos trust dscp\n",
                                            " service-policy output EDGE-IN\n mls qos trust cos\n")
    _, report = convert(text, "ios", "eos")
    assert "EOS applies QoS policies inbound only" in report.to_text()
    _, report = convert(text, "ios", "ios")
    assert "a Catalyst 9000 trusts DSCP" in report.to_text()

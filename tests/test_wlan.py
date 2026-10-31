from helpers import sample

from routershift.convert import convert, parse


def test_readers() -> None:
    ios = parse(sample("ios_access.cfg"), "ios")
    assert [(w.name, w.wlan_id, w.ssid, w.vlan, w.security) for w in ios.wlans] == [
        ("CORP", 1, "Corp", 10, "dot1x"), ("GUEST", 2, "Guest", 20, "open")]  # the VLAN through tag and profile
    comware = parse(sample("comware_access.cfg"), "comware")
    [staff] = comware.wlans
    assert (staff.ssid, staff.vlan, staff.security, staff.psk, staff.enabled) == ("Staff", 10, "psk", "", True)


def test_writers() -> None:
    out, report = convert(sample("comware_access.cfg"), "comware", "ios")
    assert ("wlan STAFF 1 Staff\n no security wpa akm dot1x\n security wpa akm psk\n"
            " security wpa psk set-key ascii 0 CHANGE-ME\n no shutdown\n") in out
    assert "wireless profile policy STAFF-POLICY\n vlan 10\n" in out
    assert "wireless tag policy RS-POLICY-TAG\n wlan STAFF policy STAFF-POLICY\n" in out
    text = report.to_text()
    assert "the pre-shared key is stored encrypted" in text and "assign it to the access points" in text
    out, report = convert(sample("ios_access.cfg"), "ios", "comware")
    assert ("wlan service-template CORP\n ssid Corp\n vlan 10\n akm mode dot1x\n"
            " client-security authentication-mode dot1x\n cipher-suite ccmp\n security-ie rsn\n"
            " service-template enable\n") in out
    assert "wlan service-template GUEST\n ssid Guest\n vlan 20\n service-template enable\n" in out
    assert "bind the service templates to the AP radios" in report.to_text()


def test_clear_text_key_carries_over_and_stays_out_of_the_report() -> None:
    text = "sysname wx\nwlan service-template IOT\n ssid IoT\n akm mode psk\n" \
           " preshared-key pass-phrase simple Sup3rS3cret\n mystery-line\n"
    out, report = convert(text, "comware", "ios")
    assert " security wpa psk set-key ascii 0 Sup3rS3cret\n" in out
    assert "Sup3rS3cret" not in report.to_text()


def test_switches_report_it() -> None:
    for target, name in (("eos", "EOS"), ("aoscx", "AOS-CX"), ("aoss", "AOS-S")):
        out, report = convert(sample("ios_access.cfg"), "ios", target)
        assert "Corp" not in out
        assert f"{name} is no wireless controller; this WLAN (VLAN 20, open) is left out" in report.to_text()

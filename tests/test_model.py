import json

from routershift.model import Device, Interface, InterfaceKind, StaticRoute, SwitchportMode, Vlan
from routershift.report import Report, Severity


def test_device_to_json() -> None:
    dev = Device(platform="ios")
    dev.system.hostname = "sw1"
    dev.vlans[10] = Vlan(10, "users")
    dev.interfaces["Ethernet1/0/1"] = Interface(
        "Ethernet1/0/1", InterfaceKind.ETHERNET, source_name="GigabitEthernet1/0/1",
        mode=SwitchportMode.ACCESS, access_vlan=10)
    dev.static_routes.append(StaticRoute("0.0.0.0/0", next_hop="10.0.0.1"))
    data = json.loads(dev.to_json())
    assert data["system"]["hostname"] == "sw1"
    assert data["interfaces"]["Ethernet1/0/1"]["mode"] == "access"
    assert data["vlans"]["10"]["name"] == "users"


def test_report_status() -> None:
    report = Report("ios", "eos")
    report.item("vlan", "10")
    report.add("interface", "Ethernet1/0/1", Severity.APPROX, "speed", "speed 100 has no exact equivalent")
    report.skip("unparsed", "line 42", "unknown", "not understood")
    assert report.counts() == {"exact": 1, "approximated": 1, "skipped": 1}
    assert "needs-review" in report.to_text()
    assert json.loads(report.to_json())["counts"]["exact"] == 1

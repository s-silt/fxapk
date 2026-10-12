"""D3：isolatedProcess / useAppZygote 只认 service 上的显式值。"""

from __future__ import annotations

from apkscan.analyzers.runtime_diagnostics import RuntimeDiagnosticsAnalyzer
from tests.conftest import FakeContext

_NS = "xmlns:android='http://schemas.android.com/apk/res/android'"


def _analyze(xml: str):
    return RuntimeDiagnosticsAnalyzer().analyze(FakeContext(manifest_xml=xml))


def _items(xml: str) -> list[dict[str, object]]:
    meta = _analyze(xml).meta
    diagnostics = meta.get("runtime_diagnostics")
    if not isinstance(diagnostics, dict):
        return []
    items = diagnostics.get("items")
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def test_service_true_records_component_and_enabled_signal() -> None:
    result = _analyze(
        f"<manifest {_NS}><application>"
        "<service android:name='.Isolated' android:isolatedProcess='true' "
        "android:useAppZygote='true'/>"
        "</application></manifest>"
    )
    assert result.endpoints == []
    assert result.findings == []
    items = _items(
        f"<manifest {_NS}><application>"
        "<service android:name='.Isolated' android:isolatedProcess='true' "
        "android:useAppZygote='true'/>"
        "</application></manifest>"
    )
    assert {item["event"] for item in items} == {"isolated_process", "app_zygote"}
    assert {item["class"] for item in items} == {"static-potential"}
    assert {item["component_name"] for item in items} == {".Isolated"}
    assert {item["declared_value"] for item in items} == {True}
    assert result.meta["runtime_diagnostics"]["frida_detection"] == "not_inferred"


def test_service_false_is_not_an_enabled_signal() -> None:
    items = _items(
        f"<manifest {_NS}><application>"
        "<service android:name='.Plain' android:isolatedProcess='false' "
        "android:useAppZygote='false'/>"
        "</application></manifest>"
    )
    assert items
    assert {item["class"] for item in items} != {"static-potential"}
    assert "static-potential" not in {item["class"] for item in items}
    assert {item["declared_value"] for item in items} == {False}
    assert {item["component_name"] for item in items} == {".Plain"}
    assert {item["event"] for item in items} == {"isolated_process", "app_zygote"}


def test_application_attribute_is_not_the_service_signal() -> None:
    application_true = _items(
        f"<manifest {_NS}><application android:isolatedProcess='true' "
        "android:useAppZygote='true'/></manifest>"
    )
    application_false = _items(
        f"<manifest {_NS}><application android:isolatedProcess='false' "
        "android:useAppZygote='false'/></manifest>"
    )
    assert application_true == []
    assert application_false == []
    unknown = _items(
        f"<manifest {_NS}><application><service android:name='.Svc' "
        "android:isolatedProcess='maybe' android:useAppZygote='2'/></application></manifest>"
    )
    assert unknown == []

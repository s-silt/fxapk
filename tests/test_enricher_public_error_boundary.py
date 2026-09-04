"""富化器公开错误出口不得暴露 provider 异常原文。"""

from __future__ import annotations

import json
from pathlib import Path

from apkscan.core.enrichment import enrich_selected_targets, safe_error_type
from apkscan.core.models import Endpoint, EnrichmentResult, Report
from apkscan.core.registry import BaseEnricher
from apkscan.report import json as report_json

_CANARY_URL = "https://user:SECRET@canary.example.test/query?token=TOKEN"
_CANARY_CASE = "/cases/CASE-CANARY"
_CANARY_BODY = "provider response body"
_CANARY_MESSAGE = f"{_CANARY_URL} {_CANARY_CASE} {_CANARY_BODY}"
_CANARY_PARTS = (
    "SECRET",
    "TOKEN",
    "canary.example.test",
    "CASE-CANARY",
    "provider response body",
)


def _canary_exception() -> RuntimeError:
    return RuntimeError(_CANARY_MESSAGE)


def _assert_no_canary(value: object) -> None:
    if isinstance(value, str):
        rendered = value
    else:
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    for marker in _CANARY_PARTS:
        assert marker not in rendered


class _BoundaryFailureEnricher(BaseEnricher):
    """把合成 provider 异常收敛为稳定 error_type。"""

    name = "boundary_probe"
    phase = "attribution"

    def __init__(self) -> None:
        self.result: EnrichmentResult | None = None

    applies_to = ["domain"]

    def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
        del endpoint
        try:
            raise _canary_exception()
        except Exception as exc:  # noqa: BLE001 - 测试任意 provider 异常的公开边界
            error_type = safe_error_type(exc)

        self.result = EnrichmentResult(
            provider=self.name,
            ok=False,
            data={"error_type": error_type},
            error=error_type,
        )
        return self.result


class _FallbackSuccessEnricher(BaseEnricher):
    """主路径异常后由正常 fallback 成功，不应产生失败状态。"""

    name = "fallback_probe"
    phase = "attribution"

    applies_to = ["domain"]

    def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
        del endpoint
        try:
            raise _canary_exception()
        except RuntimeError:
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={
                    "resolved_by": "system_fallback",
                    "addresses": ["203.0.113.10"],
                },
            )


def _run_failure_boundary() -> tuple[
    Endpoint,
    list[dict],
    _BoundaryFailureEnricher,
    str,
]:
    endpoint = Endpoint(value="boundary.example.test", kind="domain")
    enricher = _BoundaryFailureEnricher()
    expected_error_type = safe_error_type(_canary_exception())

    stats = enrich_selected_targets([endpoint], [enricher])

    return endpoint, stats, enricher, expected_error_type


def test_endpoint_and_source_status_keep_only_stable_error_type() -> None:
    """endpoint 与 source_status 只保留稳定 error_type，不含 provider 异常原文。"""
    endpoint, stats, enricher, expected_error_type = _run_failure_boundary()

    assert enricher.result is not None
    assert enricher.result.ok is False
    assert enricher.result.error == expected_error_type
    _assert_no_canary(enricher.result.error)

    assert "boundary_probe" not in endpoint.enrichment
    source_status = endpoint.enrichment["source_status"]
    assert source_status == {
        "boundary_probe": {
            "status": "failed",
            "error_type": expected_error_type,
        }
    }
    _assert_no_canary(endpoint.enrichment)
    _assert_no_canary(source_status)

    assert len(stats) == 1
    assert stats[0]["provider"] == "boundary_probe"
    assert stats[0]["attempted"] == 1
    assert stats[0]["ok"] == 0
    assert stats[0]["failed"] == 1
    assert stats[0]["typical_error"] == expected_error_type
    _assert_no_canary(stats[0]["typical_error"])

    fallback_endpoint = Endpoint(value="fallback.example.test", kind="domain")
    fallback_stats = enrich_selected_targets(
        [fallback_endpoint],
        [_FallbackSuccessEnricher()],
    )

    assert fallback_endpoint.enrichment["fallback_probe"] == {
        "resolved_by": "system_fallback",
        "addresses": ["203.0.113.10"],
    }
    assert fallback_endpoint.enrichment["source_status"] == {
        "fallback_probe": {"status": "hit"}
    }
    assert fallback_stats == [
        {
            "provider": "fallback_probe",
            "attempted": 1,
            "ok": 1,
            "no_record": 0,
            "failed": 0,
            "typical_error": None,
        }
    ]
    _assert_no_canary(fallback_endpoint.enrichment)
    _assert_no_canary(fallback_stats)


def test_report_and_digest_json_do_not_expose_exception_canary(
    tmp_path: Path,
) -> None:
    """报告与摘要的 JSON 出口不含 provider 异常原文。"""
    endpoint, stats, enricher, expected_error_type = _run_failure_boundary()

    assert enricher.result is not None
    assert enricher.result.error == expected_error_type
    assert stats[0]["typical_error"] == expected_error_type

    digest_json = json.dumps(stats, ensure_ascii=False, sort_keys=True)
    _assert_no_canary(digest_json)

    report = Report(
        package_name="test.boundary",
        meta={},
        leads=[],
        endpoints=[endpoint],
        findings=[],
        analyzer_status=[],
        enricher_status=stats,
    )

    payload = report_json.to_dict(report)
    assert payload["enricher_status"][0]["typical_error"] == expected_error_type
    assert payload["endpoints"][0]["enrichment"]["source_status"] == {
        "boundary_probe": {
            "status": "failed",
            "error_type": expected_error_type,
        }
    }
    _assert_no_canary(payload)

    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )
    _assert_no_canary(serialized)

    output_path = tmp_path / "report.json"
    report_json.dump(report, str(output_path))
    dumped_json = output_path.read_text(encoding="utf-8")

    _assert_no_canary(dumped_json)
    assert json.loads(dumped_json) == payload

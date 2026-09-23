from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core import origin_check as oc
from apkscan.core import origin_enrichment as oe
from apkscan.core.models import Endpoint, Report
from apkscan.core.origin_projection import integrate_check, publish_projection
from apkscan.core.report_io import report_from_dict
from apkscan.report.json import to_dict


def base_report() -> dict:
    return to_dict(Report('com.example.fixture', {
        'case_id': 'fixture', 'sample_sha256': 'a' * 64, 'tool_version': '1.14.0', 'ruleset_digest': 'b' * 64},
        [], [Endpoint('cdn.example.test', 'domain')], [], []))


def plan(**kw) -> dict:
    return oc.build_plan('https://cdn.example.test/object', 'https://origin.example.test/object',
                         case_id='fixture', source_note='synthetic evidence', **kw)


def observed(request: dict, ip: str, body: bytes = b'synthetic object') -> dict:
    return {'request': request, 'connected_ip': ip, 'status': 'observed', 'http_status': 200,
            'observed_at': '2026-01-01T00:00:00+00:00', 'body_complete': True,
            'body_bytes': len(body), 'body_sha256': hashlib.sha256(body).hexdigest()}


def receipt(tmp_path: Path, **changes) -> tuple[dict, Path]:
    p = plan()
    ref, cand = observed(p['reference'], '192.0.2.1'), observed(p['candidate'], '192.0.2.2')
    cand.update(changes)
    check = {**p, 'status': 'executed', 'observations': {'reference': ref, 'candidate': cand},
             'assessment': oc.compare_resources(ref, cand)}
    path = tmp_path / 'origin-check.json'
    path.write_text(json.dumps(check), encoding='utf-8')
    return check, path


@pytest.mark.parametrize(('host', 'product', 'scope'), [
    ('bucket.oss-cn-hangzhou.aliyuncs.com', 'aliyun_oss', 'bucket_address'),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket.oss-cn-hangzhou.aliyuncs.com
    ('oss-cn-hangzhou.aliyuncs.com', 'aliyun_oss', 'regional_endpoint_only'),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：oss-cn-hangzhou.aliyuncs.com
    ('bucket-123456.cos.ap-guangzhou.myqcloud.com', 'tencent_cos', 'bucket_address'),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket-123456.cos.ap-guangzhou.myqcloud.com
    ('bucket.obs.cn-north-4.myhuaweicloud.com', 'huawei_obs', 'bucket_address'),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket.obs.cn-north-4.myhuaweicloud.com
    ('bucket.tos-cn-beijing.volces.com', 'volcengine_tos', 'bucket_address'),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket.tos-cn-beijing.volces.com
    ('bucket.bj.bcebos.com', 'baidu_bos', 'bucket_address'),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket.bj.bcebos.com
    ('bucket.ks3-cn-beijing.ksyuncs.com', 'kingsoft_ks3', 'bucket_address'),  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket.ks3-cn-beijing.ksyuncs.com
])
def test_vendor_specific_storage_addresses(host, product, scope) -> None:
    result = oc.storage_address(host.upper() + '.')
    assert result and result['product'] == product and result['scope'] == scope
    assert oc.storage_address(host + '.attacker.test') is None


@pytest.mark.parametrize('host', ['bucket.cdn.bcebos.com', 'bucket.b0.aicdn.com', 'cdn.qiniudns.com',  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket.b0.aicdn.com, bucket.cdn.bcebos.com, cdn.qiniudns.com
                                 'custom.example.test', 'bucket.oss-cn-beijing-internal.aliyuncs.com'])  # leak-scan: allow 合成且不联网的产品边界夹具；须保留厂商字面以检验后缀识别与误判：bucket.oss-cn-beijing-internal.aliyuncs.com
def test_cdn_custom_or_private_domains_not_called_storage_origins(host) -> None:
    assert oc.storage_address(host) is None


@pytest.mark.parametrize('url', ['ftp://example.test/a', 'https://u:p@example.test/a',
                                'https://example.test/a#fragment', 'https://example.test/a\nInjected:yes'])
def test_bad_request_rejected_before_network(url) -> None:
    with pytest.raises(ValueError):
        oc.build_plan(url, 'https://other.test/a', case_id='fixture', source_note='fixture')


def test_ip_override_keeps_virtual_host_and_sni() -> None:
    p = plan(candidate_ip='192.0.2.10')
    assert p['candidate']['host_header'] == 'origin.example.test'
    assert p['candidate']['sni'] == 'origin.example.test'
    assert p['candidate']['connect_ip'] == '192.0.2.10'


@pytest.mark.parametrize('address', ['127.0.0.1', '169.254.169.254', '10.0.0.1', '::1', '::ffff:127.0.0.1'])
def test_nonpublic_connections_rejected(address) -> None:
    with pytest.raises(ValueError):
        oc._resolve({'connect_ip': address})


@pytest.mark.parametrize('changes', [
    {'http_status': 403}, {'http_status': 302}, {'http_status': 206}, {'body_complete': False},
    {'status': 'failed'}, {'body_bytes': 0}, {'body_sha256': None},
])
def test_errors_truncation_empty_and_partial_content_never_match(tmp_path, changes) -> None:
    check, _ = receipt(tmp_path, **changes)
    assert check['assessment']['status'] == 'inconclusive'
    assert check['assessment']['origin_status'] == 'not_confirmed'


def test_same_resource_is_not_origin_confirmation_and_different_is_not_exclusion(tmp_path) -> None:
    check, _ = receipt(tmp_path)
    assert check['assessment']['status'] == 'resource_match'
    assert check['assessment']['origin_status'] == 'not_confirmed'
    cand = check['observations']['candidate']
    cand['body_sha256'] = 'b' * 64
    assert oc.compare_resources(check['observations']['reference'], cand)['status'] == 'content_differs'
    cand['request'] = check['observations']['reference']['request']
    cand['connected_ip'] = '192.0.2.1'
    assert oc.compare_resources(check['observations']['reference'], cand)['status'] == 'inconclusive'


def test_body_cap_retains_partial_and_no_redirect_follow(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(oc, 'MAX_BYTES', 4)
    monkeypatch.setattr(oc, '_resolve', lambda _: '192.0.2.1')
    class Response:
        status = 302
        def getheaders(self):
            return [('Location', 'http://127.0.0.1/private')]
        def getheader(self, _):
            return None
        def read1(self, n):
            return b'abcde'[:n]
    calls = []
    class Connection:
        def __init__(self, request, address):
            calls.append(address)
        def request(self, *args, **kw):
            assert kw['headers']['Host'] == 'origin.example.test'
        def getresponse(self):
            return Response()
        def close(self):
            pass
    monkeypatch.setattr(oc, '_PinnedConnection', Connection)
    result = oc.fetch_resource(plan()['candidate'], tmp_path, 'candidate')
    assert calls == ['192.0.2.1'] and result['http_status'] == 302
    assert result['body_bytes'] == 4 and not result['body_complete']
    assert (tmp_path / 'candidate.body').read_bytes() == b'abcd'


def test_projection_survives_all_existing_public_consumers(tmp_path, monkeypatch) -> None:
    from apkscan.report import html, pdf, ioc
    from apkscan.report.digest import build_digest
    check, path = receipt(tmp_path)
    original = base_report()
    merged = integrate_check(original, check, path)
    assert original['leads'] == []
    assert integrate_check(merged, check, path) == merged
    roundtrip = to_dict(report_from_dict(merged))
    assert roundtrip['meta']['origin_checks'][0]['status'] == 'resource_match'
    assert roundtrip['leads'][0]['advice'] == '待核'
    assert not roundtrip['leads'][0]['is_runtime_contact']
    assert '源站未确认' in html.render_to_string(report_from_dict(roundtrip))
    assert '资源内容匹配' in ioc.leads_to_ioc_rows(roundtrip)[0]['origin_check_summary']
    assert build_digest(roundtrip)['origin_checks'][0]['origin_status'] == 'not_confirmed'
    monkeypatch.setattr(pdf, 'render', lambda *a, **kw: False)
    status = publish_projection(original, path)
    assert status['pdf'] == 'failed' and (tmp_path / 'report.json').is_file()
    assert '源站未确认' in (tmp_path / 'ioc.csv').read_text(encoding='utf-8-sig')


def test_mismatch_binding_blocks_execution(tmp_path, monkeypatch) -> None:
    report = tmp_path / 'report.json'
    original = base_report()
    original['meta']['case_id'] = 'other'
    report.write_text(json.dumps(original))
    monkeypatch.setattr(oc, '_resolve', lambda _: pytest.fail('network must not run'))
    result = CliRunner().invoke(app, ['origin-check', '--reference-url', 'https://cdn.example.test/a',
        '--candidate-url', 'https://other.test/a', '--case-id', 'fixture', '--source-note', 'fixture',
        '--report', str(report), '--mode', 'authorized-active'])
    assert result.exit_code == 2


def test_plan_does_not_resolve_fetch_or_enrich(tmp_path, monkeypatch) -> None:
    report = tmp_path / 'report.json'
    report.write_text(json.dumps(base_report()))
    monkeypatch.setattr(oc, '_resolve', lambda _: pytest.fail('no network in plan'))
    result = CliRunner().invoke(app, ['origin-check', '--reference-url', 'https://cdn.example.test/a',
        '--candidate-url', 'https://other.test/a', '--case-id', 'fixture', '--source-note', 'fixture', '--report', str(report)])
    assert result.exit_code == 0 and json.loads(result.stdout)['status'] == 'planned'


def test_existing_batch_disabled_status_reaches_report_and_summary(tmp_path, monkeypatch) -> None:
    from apkscan.core import registry
    monkeypatch.setattr(registry, 'discover_enrichers', lambda: [SimpleNamespace(
        name='fofa', active=False, applies_to=['domain', 'ip'], required_env=('ORIGIN_TEST_UNSET',))])
    monkeypatch.delenv('ORIGIN_TEST_UNSET', raising=False)
    check, path = receipt(tmp_path)
    enrichment = oe.enrich_origin_candidates(check, tmp_path, 'fofa')
    assert enrichment['status'] == 'partial'
    assert enrichment['coverage']['source_outcomes'] == {'disabled': 4}
    check['provider_enrichment'] = enrichment
    path.write_text(json.dumps(check))
    merged = integrate_check(base_report(), check, path)
    item = merged['meta']['origin_checks'][0]
    assert item['source_outcomes'] == {'disabled': 4}
    assert 'disabled' in item['detail']
    assert merged['endpoints'][0]['enrichment']['source_status']['fofa']['status'] == 'disabled'


def test_five_layer_provider_results_reach_projection_without_operator_claim(tmp_path) -> None:
    check, path = receipt(tmp_path)
    check['provider_enrichment'] = {'status': 'partial', 'records': [{
        'target': 'origin.example.test', 'enrichment': {'dns': {'ips': ['192.0.2.10'],
        'hosting': [{'ip': '192.0.2.10', 'asn': 64500, 'org': 'Tencent cloud'}]}}}],
        'coverage': {'targets': [{'target': 'origin.example.test', 'kind': 'domain',
        'source_status': {'dns': {'status': 'hit'}, 'fofa': {'status': 'failed'}}}],
        'source_outcomes': {'hit': 1, 'failed': 1}}}
    path.write_text(json.dumps(check))
    merged = integrate_check(base_report(), check, path)
    item = merged['meta']['origin_checks'][0]
    assert any('Tencent' in role for role in item['provider_roles'])
    assert '网络机构' in item['detail'] and 'failed' in item['detail']
    assert item['origin_status'] == 'not_confirmed'


def test_captured_edge_headers_reach_report_without_cross_ip_contamination(tmp_path) -> None:
    check, path = receipt(tmp_path)
    check['observations']['reference']['response_headers'] = [('Server', 'ESA'), ('EagleId', 'fixture'),
                                                             ('Via', 'ens-cache1.example[1,0]')]
    path.write_text(json.dumps(check))
    merged = integrate_check(base_report(), check, path)
    assert '阿里云 ESA' in merged['meta']['origin_checks'][0]['detail']
    reference = next(ep for ep in merged['endpoints'] if ep['value'] == 'cdn.example.test')
    assert reference['enrichment']['origin_check_edges'][0]['connected_ip'] == '192.0.2.1'
    assert reference['enrichment']['origin_check_edges'][0]['edge_provider']['tier'] == 'probable'
    candidate = next(ep for ep in merged['endpoints'] if ep['value'] == 'origin.example.test')
    assert 'origin_check_edges' not in candidate['enrichment']


def test_response_archive_gap_survives_batch_and_projection(tmp_path, monkeypatch) -> None:
    from apkscan.core import registry
    from apkscan.core.models import EnrichmentResult

    class SyntheticProvider:
        name = "synthetic"
        active = False
        applies_to = ["domain", "ip"]
        required_env = ()

        def enrich(self, endpoint):
            return EnrichmentResult(provider=self.name, ok=True, data={"record": "fixture"})

    monkeypatch.setattr(registry, "discover_enrichers", lambda: [SyntheticProvider()])
    check, path = receipt(tmp_path)
    enrichment = oe.enrich_origin_candidates(check, tmp_path, "synthetic")
    assert enrichment["coverage"]["coverage_complete"] is True
    assert enrichment["coverage"]["response_archive_complete"] is False
    assert enrichment["status"] == "partial"
    check["provider_enrichment"] = enrichment
    path.write_text(json.dumps(check), encoding="utf-8")
    projected = integrate_check(base_report(), check, path)
    assert projected["meta"]["origin_checks"][0]["enrichment_status"] == "partial"
    import importlib
    command = importlib.import_module("apkscan.commands.origin_check")
    monkeypatch.setattr(command, "run_check", lambda *a: path)
    monkeypatch.setattr(command, "enrich_origin_candidates", lambda *a: enrichment)
    monkeypatch.setattr(command, "publish_projection", lambda *a: {"pdf": "written"})
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(base_report()), encoding="utf-8")
    result = CliRunner().invoke(app, ["origin-check", "--reference-url", "https://cdn.example.test/object",
        "--candidate-url", "https://origin.example.test/object", "--case-id", "fixture",
        "--source-note", "synthetic", "--report", str(baseline), "--mode", "authorized-active"])
    assert result.exit_code == 1
    assert json.loads(result.stdout)["enrichment_status"] == "partial"


def test_chained_projection_rejected_before_any_network(tmp_path, monkeypatch):
    check, path = receipt(tmp_path)
    merged = integrate_check(base_report(), check, path)
    baseline = tmp_path / "derived.json"
    baseline.write_text(json.dumps(merged), encoding="utf-8")
    import importlib
    command = importlib.import_module("apkscan.commands.origin_check")
    monkeypatch.setattr(command, "run_check", lambda *a: pytest.fail("must reject before network"))
    result = CliRunner().invoke(app, ["origin-check", "--reference-url", "https://cdn.example.test/a",
        "--candidate-url", "https://other.test/a", "--case-id", "fixture", "--source-note", "fixture",
        "--report", str(baseline), "--mode", "authorized-active"])
    assert result.exit_code == 2
    assert "baseline" in result.output


def test_slow_response_headers_obey_total_deadline(tmp_path, monkeypatch):
    import socket
    import threading
    import time
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(2)
    port = listener.getsockname()[1]
    def serve():
        try:
            client, _ = listener.accept()
            with client:
                client.recv(4096)
                for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 80:
                    client.sendall(bytes([byte]))
                    time.sleep(0.01)
        except OSError:
            pass
        finally:
            listener.close()
    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    monkeypatch.setattr(oc, "TIMEOUT", 0.15)
    monkeypatch.setattr(oc, "_resolve", lambda _: "127.0.0.1")
    started = time.monotonic()
    result = oc.fetch_resource(oc._url(f"http://example.test:{port}/a"), tmp_path, "slow")
    elapsed = time.monotonic() - started
    worker.join(2)
    assert result["status"] == "failed"
    assert elapsed < 0.7, elapsed

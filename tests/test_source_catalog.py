import json

from typer.testing import CliRunner

from apkscan.cli import app
from apkscan.core.source_catalog import source_catalog, source_access_summary


def test_catalog_has_verified_dates_and_never_claims_account_access():
    catalog = source_catalog()
    assert len(catalog["sources"]) == 21
    assert catalog["network_requests"] == 0
    assert catalog["account_entitlements_verified"] is False
    for row in catalog["sources"]:
        assert row["official_urls"]
        assert row["verified_on"] == catalog["verified_on"]
        assert row["account_live_health"] == "not_checked"
        assert row["api_access_caveat"] and row["usage_terms_caveat"]


def test_free_web_membership_is_not_treated_as_free_api_permission():
    rows = {r["provider_key"]: r for r in source_catalog()["sources"]}
    assert rows["fofa"]["access_tiers"][0]["api_access"] == "not_confirmed_for_free_search_api"
    assert "lookup_only" in rows["censys"]["access_tiers"][0]["api_access"]
    assert source_access_summary("unknown-source")["status"] == "not_catalogued"


def test_catalog_results_are_isolated_from_caller_mutation():
    first = source_catalog()
    first["sources"].clear()
    assert len(source_catalog()["sources"]) == 21


def test_cli_catalog_is_read_only_and_filters_categories():
    result = CliRunner().invoke(app, ["case", "source-catalog", "--category", "free"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["sources"]
    assert all(any(t["category"] == "free" for t in r["access_tiers"]) for r in payload["sources"])
    assert CliRunner().invoke(app, ["case", "source-catalog", "--category", "bad"]).exit_code == 2


def test_safe_yaml_loader_variants_have_identical_catalog_data():
    from importlib.resources import files
    import yaml
    raw = files("apkscan").joinpath("rules/source_access.yaml").read_text(encoding="utf-8")
    assert yaml.load(raw, Loader=getattr(yaml, "CSafeLoader", yaml.SafeLoader)) == yaml.safe_load(raw)

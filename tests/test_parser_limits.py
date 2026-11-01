from __future__ import annotations

import pytest

from apkscan.core.parser_limits import ParserConfigurationError, ParserLimits


def test_parser_limits_require_explicit_time_and_memory():
    assert ParserLimits.from_environment({}) is None
    limits = ParserLimits.from_environment({
        "FXAPK_PARSER_TIMEOUT_SEC": "2.5",
        "FXAPK_PARSER_MEMORY_MB": "256",
    })
    assert limits == ParserLimits(2.5, 256 * 1024 * 1024)
    assert limits is not None
    assert ParserLimits(**limits.to_dict()) == limits


@pytest.mark.parametrize("env", [
    {"FXAPK_PARSER_TIMEOUT_SEC": "5"},
    {"FXAPK_PARSER_MEMORY_MB": "256"},
    {"FXAPK_PARSER_OUTPUT_MB": "64"},
    {"FXAPK_PARSER_TIMEOUT_SEC": "nan", "FXAPK_PARSER_MEMORY_MB": "256"},
    {"FXAPK_PARSER_TIMEOUT_SEC": "inf", "FXAPK_PARSER_MEMORY_MB": "256"},
    {"FXAPK_PARSER_TIMEOUT_SEC": "0", "FXAPK_PARSER_MEMORY_MB": "256"},
    {"FXAPK_PARSER_TIMEOUT_SEC": "5", "FXAPK_PARSER_MEMORY_MB": "-1"},
    {"FXAPK_PARSER_TIMEOUT_SEC": "5", "FXAPK_PARSER_MEMORY_MB": "1.5"},
    {"FXAPK_PARSER_TIMEOUT_SEC": "5", "FXAPK_PARSER_MEMORY_MB": "256", "FXAPK_PARSER_OUTPUT_MB": ""},
])
def test_invalid_parser_configuration_never_disables_limits(env):
    with pytest.raises(ParserConfigurationError, match="parser_limits_invalid"):
        ParserLimits.from_environment(env)


@pytest.mark.parametrize("timeout,memory", [(True, 1024), (1.0, True), (float("nan"), 1024), (1.0, 0)])
def test_parser_limits_validate_programmatic_values(timeout, memory):
    with pytest.raises(ParserConfigurationError):
        ParserLimits(timeout, memory)

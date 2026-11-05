"""Carry acquisition/reanalysis terminal states into the same report projection."""
from .common import json_value, result


def review(data: bytes, options: dict) -> dict:
    receipt = json_value(data)
    if not isinstance(receipt, dict) or receipt.get("schema_version") != "fxapk.runtime-recovery-result.v1":
        raise ValueError("acquisition_receipt_schema_invalid")
    rows = receipt.get("stages")
    if not isinstance(rows, list) or not rows:
        raise ValueError("acquisition_stages_missing")
    reasons = {code for row in rows for code in row.get("reason_codes", [])}
    if any(row.get("state") != "ok" for row in rows):
        reasons.add("acquisition_chain_incomplete")
    if receipt.get("source_binding_verified") is not True:
        reasons.add("runtime_sample_binding_unverified")
    state = "failed" if any(row.get("state") == "failed" for row in rows) else "partial" if reasons else "ok"
    return result(state, sorted(reasons), stages=rows,
                  source_binding_verified=False, observation_scope="declared_pid_and_ranges")

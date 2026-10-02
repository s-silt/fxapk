"""Admission-bound tests using deferred futures; no threads, sleep or network."""
from concurrent.futures import Future

import pytest

from apkscan.core import enrichment
from apkscan.core.models import Endpoint


@pytest.mark.parametrize("entrypoint", ["_enrich_endpoints", "_run_enrichment"])
def test_dispatch_window_is_bounded_and_every_endpoint_runs_once(monkeypatch, entrypoint) -> None:
    calls = []
    queued = {}
    peak = 0
    workers = 3

    class DeferredPool:
        def __init__(self, *, max_workers, thread_name_prefix):
            assert max_workers == workers

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def submit(self, fn, *args):
            nonlocal peak
            future = Future()
            queued[future] = (fn, args)
            peak = max(peak, len(queued))
            assert len(queued) <= workers * 2
            return future

    def complete_one(pending, *, return_when):
        assert return_when == enrichment.FIRST_COMPLETED
        # Finish the newest task first to exercise out-of-order completion.
        future = next(reversed(queued))
        fn, args = queued.pop(future)
        future.set_result(fn(*args))
        return {future}, set(pending) - {future}

    monkeypatch.setattr(enrichment, "ThreadPoolExecutor", DeferredPool)
    monkeypatch.setattr(enrichment, "wait", complete_one)
    monkeypatch.setattr(enrichment, "ENRICH_MAX_WORKERS", workers)
    monkeypatch.setattr(enrichment, "_run_enrichers_on_endpoint",
                        lambda ep, *args: calls.append(ep.value))
    endpoints = [Endpoint(kind="domain", value=f"item-{i}.invalid") for i in range(1000)]
    identities = [id(ep) for ep in endpoints]
    assert getattr(enrichment, entrypoint)(endpoints, []) == []
    assert peak == workers * 2
    assert len(calls) == len(set(calls)) == len(endpoints)
    assert set(calls) == {ep.value for ep in endpoints}
    assert [id(ep) for ep in endpoints] == identities
    assert not queued


def test_unexpected_gate_error_is_not_suppressed() -> None:
    from apkscan.core.registry import BaseEnricher

    class NeverEnricher(BaseEnricher):
        name = "never"
        applies_to = ["domain"]

        def enrich(self, endpoint):
            raise AssertionError("gate must run first")

    def bad_gate(*args):
        raise RuntimeError("synthetic gate failure")

    with pytest.raises(RuntimeError, match="synthetic gate failure"):
        enrichment._enrich_endpoints(
            [Endpoint(kind="domain", value="example.invalid")], [NeverEnricher()], gate=bad_gate,
        )

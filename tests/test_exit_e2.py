"""E2：取消必须停掉已准入的阻塞 provider，并结束它拉起的子进程。"""

from __future__ import annotations

import subprocess
import sys
import threading
import time

import psutil
import pytest

from apkscan.core.enrichment import enrich_selected_targets
from apkscan.core.enrichment_budget import EnrichmentBudget
from apkscan.core.models import Endpoint, EnrichmentResult
from apkscan.core.registry import BaseEnricher


class _Blocking(BaseEnricher):
    name = "blocking-provider"
    applies_to = ["domain"]

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.pid: int | None = None
        self.started = threading.Event()

    def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
        self.calls.append(endpoint.value)
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
        self.pid = proc.pid
        self.started.set()
        time.sleep(6)
        return EnrichmentResult(
            provider=self.name, ok=True, data={"org": "SYNTHETIC-LATE", "_source_status": "hit"},
        )


class _Following(BaseEnricher):
    name = "following-provider"
    applies_to = ["domain"]

    def __init__(self) -> None:
        self.calls: list[str] = []

    def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
        self.calls.append(endpoint.value)
        return EnrichmentResult(
            provider=self.name, ok=True, data={"org": "SYNTHETIC-FOLLOWING", "_source_status": "hit"},
        )


def _reap(pid: int | None) -> None:
    if pid is None or not psutil.pid_exists(pid):
        return
    proc = psutil.Process(pid)
    proc.kill()
    proc.wait(timeout=2)


def test_cancel_stops_blocking_provider_and_its_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.core.enrichment.ENRICH_MAX_WORKERS", 1)
    blocking = _Blocking()
    following = _Following()
    endpoints = [Endpoint(kind="domain", value=f"target-{index}.example.invalid") for index in range(2)]
    budget = EnrichmentBudget(total=6)

    def interrupt() -> None:
        assert blocking.started.wait(timeout=10)
        time.sleep(0.1)
        import _thread
        _thread.interrupt_main()

    threading.Thread(target=interrupt, daemon=True).start()
    status = "returned"
    t0 = time.monotonic()
    try:
        enrich_selected_targets(
            endpoints, [blocking, following], include_case_close=True, budget=budget,
        )
    except KeyboardInterrupt:
        status = "keyboard_interrupt"
    elapsed = time.monotonic() - t0
    child_alive = blocking.pid is not None and psutil.pid_exists(blocking.pid)
    try:
        assert status == "keyboard_interrupt"
        assert elapsed <= 5
        assert blocking.calls == ["target-0.example.invalid"]
        assert following.calls == []
        assert child_alive is False
        assert all("SYNTHETIC-LATE" not in str(item.enrichment) for item in endpoints)
        assert budget.snapshot()["admitted"] == 1
        assert endpoints[0].enrichment["source_status"]["blocking-provider"] == {
            "status": "failed", "reason": "cancelled",
        }
        assert endpoints[0].enrichment["source_status"]["following-provider"]["status"] == "skipped"
        assert endpoints[1].enrichment["source_status"]["blocking-provider"]["reason"] == "cancelled"
        assert "blocking-provider" not in endpoints[0].enrichment
    finally:
        _reap(blocking.pid)


def test_parallel_cancel_stops_each_blocking_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.core.enrichment.ENRICH_MAX_WORKERS", 2)
    pids: list[int] = []
    lock = threading.Lock()
    ready = threading.Event()

    class _Parallel(BaseEnricher):
        name = "blocking-provider"
        applies_to = ["domain"]

        def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
            proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            with lock:
                pids.append(proc.pid)
                if len(pids) >= 2:
                    ready.set()
            time.sleep(6)
            return EnrichmentResult(
                provider=self.name, ok=True, data={"org": "SYNTHETIC-LATE", "_source_status": "hit"},
            )

    endpoints = [Endpoint(kind="domain", value=f"target-{index}.example.invalid") for index in range(2)]
    budget = EnrichmentBudget(total=6)

    def interrupt() -> None:
        assert ready.wait(timeout=10)
        time.sleep(0.1)
        import _thread
        _thread.interrupt_main()

    threading.Thread(target=interrupt, daemon=True).start()
    t0 = time.monotonic()
    try:
        enrich_selected_targets(endpoints, [_Parallel()], include_case_close=True, budget=budget)
        status = "returned"
    except KeyboardInterrupt:
        status = "keyboard_interrupt"
    elapsed = time.monotonic() - t0
    try:
        assert status == "keyboard_interrupt"
        assert elapsed <= 5
        assert len(pids) == 2
        assert [psutil.pid_exists(pid) for pid in pids] == [False, False]
        assert all("SYNTHETIC-LATE" not in str(item.enrichment) for item in endpoints)
    finally:
        for pid in pids:
            _reap(pid)


def test_without_cancel_both_providers_run_and_budget_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.core.enrichment.ENRICH_MAX_WORKERS", 1)

    class _Quick(BaseEnricher):
        name = "quick-provider"
        applies_to = ["domain"]

        def __init__(self) -> None:
            self.calls: list[str] = []

        def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
            self.calls.append(endpoint.value)
            return EnrichmentResult(
                provider=self.name, ok=True, data={"org": "SYNTHETIC-OK", "_source_status": "hit"},
            )

    first, second = _Quick(), _Quick()
    second.name = "quick-following"
    endpoint = Endpoint(kind="domain", value="target-0.example.invalid")
    budget = EnrichmentBudget(total=6)
    enrich_selected_targets([endpoint], [first, second], include_case_close=True, budget=budget)
    assert first.calls == [endpoint.value]
    assert second.calls == [endpoint.value]
    assert budget.snapshot()["admitted"] == 2
    assert endpoint.enrichment["quick-provider"]["org"] == "SYNTHETIC-OK"


def _no_enrich_threads() -> None:
    names = [item.name for item in threading.enumerate() if item.name.startswith("enrich") and item.is_alive()]
    assert names == []


def test_late_blocking_result_is_cancelled_not_published(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("apkscan.core.enrichment.ENRICH_MAX_WORKERS", 2)
    from apkscan.core import enrichment

    release = threading.Event()
    started = threading.Event()

    class _Wait(BaseEnricher):
        name = "blocking-provider"
        applies_to = ["domain"]

        def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
            del endpoint
            started.set()
            release.wait(timeout=10)
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={"org": "SYNTHETIC-LATE", "_source_status": "hit"},
            )

    class _Next(BaseEnricher):
        name = "following-provider"
        applies_to = ["domain"]

        def __init__(self) -> None:
            self.calls: list[str] = []

        def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
            self.calls.append(endpoint.value)
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={"org": "SYNTHETIC-FOLLOWING", "_source_status": "hit"},
            )

    def _interrupt(_pending: set) -> tuple:
        assert started.wait(timeout=10)
        raise KeyboardInterrupt

    monkeypatch.setattr(enrichment, "_wait_bounded", _interrupt)
    helper = threading.Thread(
        target=lambda: (enrichment._cancel_sleep.wait(timeout=10), release.set()),
        daemon=True,
    )
    helper.start()
    blocking = _Wait()
    following = _Next()
    endpoints = [Endpoint(kind="domain", value=f"target-{index}.example.invalid") for index in range(2)]
    status = "returned"
    try:
        enrich_selected_targets(
            endpoints, [blocking, following], include_case_close=True, budget=EnrichmentBudget(total=6),
        )
    except KeyboardInterrupt:
        status = "keyboard_interrupt"
    finally:
        release.set()
        helper.join(timeout=5)
    assert status == "keyboard_interrupt"
    assert following.calls == []
    assert all("SYNTHETIC-LATE" not in str(item.enrichment) for item in endpoints)
    for endpoint in endpoints:
        assert endpoint.enrichment["source_status"]["blocking-provider"] == {
            "status": "failed",
            "reason": "cancelled",
        }
        assert endpoint.enrichment["source_status"]["following-provider"]["status"] == "skipped"
    _no_enrich_threads()


def test_cancel_during_payload_normalization_does_not_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("apkscan.core.enrichment.ENRICH_MAX_WORKERS", 1)
    from apkscan.core import enrichment

    def _strict(payload: dict) -> dict:
        enrichment._cancel_sleep.set()
        return payload

    monkeypatch.setattr(enrichment, "_strict_provider_payload", _strict)

    class _Hit(BaseEnricher):
        name = "blocking-provider"
        applies_to = ["domain"]

        def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
            del endpoint
            return EnrichmentResult(
                provider=self.name,
                ok=True,
                data={"org": "SYNTHETIC-LATE", "_source_status": "hit"},
            )

    class _Next(BaseEnricher):
        name = "following-provider"
        applies_to = ["domain"]

        def __init__(self) -> None:
            self.calls: list[str] = []

        def enrich(self, endpoint: Endpoint) -> EnrichmentResult:
            self.calls.append(endpoint.value)
            return EnrichmentResult(
                provider=self.name, ok=True, data={"org": "SYNTHETIC-FOLLOWING", "_source_status": "hit"},
            )

    following = _Next()
    endpoint = Endpoint(kind="domain", value="target-0.example.invalid")
    status = "returned"
    try:
        enrich_selected_targets(
            [endpoint], [_Hit(), following], include_case_close=True, budget=EnrichmentBudget(total=6),
        )
    except KeyboardInterrupt:
        status = "keyboard_interrupt"
    assert status == "keyboard_interrupt"
    assert following.calls == []
    assert "SYNTHETIC-LATE" not in str(endpoint.enrichment)
    assert endpoint.enrichment["source_status"]["blocking-provider"] == {
        "status": "failed",
        "reason": "cancelled",
    }
    assert endpoint.enrichment["source_status"]["following-provider"]["status"] == "skipped"


def test_custom_sleep_keyboard_interrupt_is_not_swallowed() -> None:
    from apkscan.core import enrichment

    original = time.sleep

    def _custom(_seconds: float) -> None:
        raise KeyboardInterrupt

    time.sleep = _custom
    raised = False
    try:
        with enrichment._interruptible_sleep():
            time.sleep(1)
    except KeyboardInterrupt:
        raised = True
    finally:
        current = time.sleep
        time.sleep = original
    assert raised is True
    assert current is _custom

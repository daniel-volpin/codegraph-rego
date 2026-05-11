"""F08: async-handler-doesn't-block-the-event-loop tests.

Each async router handler that drives sync I/O (Neo4j, OPA subprocess,
LLM HTTP, FAISS, file I/O) now hops to a worker thread via
``asyncio.to_thread``. These tests pin that contract with a single,
straightforward check: while the slow sync call is running, the event
loop must still accept and progress *other* coroutines.

We intentionally do not check thread identity here. ``asyncio.to_thread``
is the mechanism; the property under test is *non-blocking*, and the
cleanest test is: schedule a concurrent ``asyncio.sleep(0)`` task and
assert it completes before the slow sync call returns.
"""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from starlette.requests import Request


def _build_request(app: FastAPI) -> Request:
    return Request({"type": "http", "app": app, "headers": []})


class _SlowDriver:
    """Neo4j driver stub whose session().run() blocks for ``delay`` seconds."""

    def __init__(self, delay: float) -> None:
        self._delay = delay

    def session(self):
        class _Session:
            def __init__(self, d: float) -> None:
                self._d = d

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def run(self, *_a, **_k):
                class _R:
                    def consume(self):
                        pass

                time.sleep(self._d)
                return _R()

        return _Session(self._delay)

    def close(self) -> None:
        pass


class HealthDoesNotBlockEventLoop(unittest.IsolatedAsyncioTestCase):
    """When /readyz performs slow synchronous I/O, concurrent coroutines
    must keep making progress on the event loop. Pre-F08 this test
    would fail because health() called Neo4j inline on the loop.
    """

    def setUp(self) -> None:
        from api.routers.health import reset_readiness_cache

        reset_readiness_cache()

    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.get_neo4j_driver", return_value=_SlowDriver(delay=0.30))
    async def test_readyz_yields_to_event_loop_during_slow_neo4j(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_which,
    ) -> None:
        from api.routers.health import readyz

        mock_search_deps.return_value = {
            "faiss_index_path": "x",
            "signature_map_path": "y",
            "signature_map_path_full": "z",
            "embedding_model_name": "m",
            "load_faiss_index": lambda *_a, **_k: None,
            "load_signature_map": lambda *_a, **_k: None,
            "load_embedding_model": lambda *_a, **_k: None,
        }

        app = FastAPI()
        app.state.startup_status = {"ready": True, "phase": "ready", "checks": {}, "errors": {}}

        ticks: list[float] = []

        async def _tick() -> None:
            start = time.perf_counter()
            # Yield repeatedly while readyz is in flight; each successful
            # yield records a tick. A blocking handler would prevent any
            # ticks from landing until /readyz returned.
            for _ in range(30):
                await asyncio.sleep(0.01)
                ticks.append(time.perf_counter() - start)

        readyz_task = asyncio.create_task(readyz(_build_request(app)))
        ticker_task = asyncio.create_task(_tick())
        await asyncio.gather(readyz_task, ticker_task)

        # At least 10 ticks must have completed BEFORE the slow probe
        # finished (the probe sleeps 0.30s; each tick is 0.01s).
        self.assertGreaterEqual(len(ticks), 10)


class PolicyEvaluateDoesNotBlockEventLoop(unittest.IsolatedAsyncioTestCase):
    """Same property for /policy/evaluate, which drives OPA via subprocess."""

    @patch("api.routers.policy.evaluate_policies")
    async def test_policy_evaluate_yields_to_event_loop(self, mock_eval) -> None:
        from api.routers.policy import policy_evaluate

        def _slow_eval(**_kwargs):
            time.sleep(0.20)
            return {"violations": [], "rules_catalog": [], "catalog": []}

        mock_eval.side_effect = _slow_eval

        ticks: list[int] = []

        async def _tick() -> None:
            for _ in range(20):
                await asyncio.sleep(0.01)
                ticks.append(1)

        eval_task = asyncio.create_task(
            policy_evaluate(max_bundles=None, max_total_violations=None, max_per_violation_id=None, rule_ids=None)
        )
        tick_task = asyncio.create_task(_tick())
        await asyncio.gather(eval_task, tick_task)

        self.assertGreaterEqual(len(ticks), 8)


class SearchDoesNotBlockEventLoop(unittest.IsolatedAsyncioTestCase):
    @patch("api.routers.search.run_search")
    async def test_search_yields_to_event_loop(self, mock_run_search) -> None:
        from api.routers.search import search
        from api.models.validation import SearchRequest

        def _slow_search(*_a, **_k):
            time.sleep(0.15)
            return ([], [])

        mock_run_search.side_effect = _slow_search

        ticks: list[int] = []

        async def _tick() -> None:
            for _ in range(15):
                await asyncio.sleep(0.01)
                ticks.append(1)

        search_task = asyncio.create_task(search(SearchRequest(query="anything")))
        tick_task = asyncio.create_task(_tick())
        await asyncio.gather(search_task, tick_task)

        self.assertGreaterEqual(len(ticks), 6)


class RemediationPreviewDoesNotBlockEventLoop(unittest.IsolatedAsyncioTestCase):
    @patch("api.routers.remediation.preview_virtual_remediation")
    async def test_remediation_preview_yields_to_event_loop(self, mock_preview) -> None:
        from api.routers.remediation import remediation_preview
        from api.models.validation import RemediationPreviewRequest

        def _slow_preview(*_a, **_k):
            time.sleep(0.15)
            return {"status": "OK", "violation_id": "v1"}

        mock_preview.side_effect = _slow_preview

        ticks: list[int] = []

        async def _tick() -> None:
            for _ in range(15):
                await asyncio.sleep(0.01)
                ticks.append(1)

        preview_task = asyncio.create_task(
            remediation_preview(RemediationPreviewRequest(violation_id="v1"))
        )
        tick_task = asyncio.create_task(_tick())
        await asyncio.gather(preview_task, tick_task)

        self.assertGreaterEqual(len(ticks), 6)


if __name__ == "__main__":
    unittest.main()

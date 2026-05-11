"""F13: per-request progress isolation tests.

Pre-F13 the module held a single global ProgressState — two concurrent
uploads silently overwrote each other. F13 keys progress by ``request_id``
(returned from ``start_progress``), uses a ``contextvars.ContextVar`` so
callbacks deep in worker threads target the right slot, and exposes a
back-compat path on ``get_progress(request_id=None)``.
"""

from __future__ import annotations

import asyncio
import unittest

from codegraph.common import progress as progress_module


class StartProgressReturnsRequestIdTests(unittest.TestCase):
    def setUp(self) -> None:
        progress_module.reset_progress()

    def test_start_progress_returns_unique_request_id(self) -> None:
        a = progress_module.start_progress()
        b = progress_module.start_progress()
        self.assertNotEqual(a, b)
        self.assertEqual(len(a), 32)
        self.assertEqual(len(b), 32)

    def test_start_progress_honors_explicit_request_id(self) -> None:
        rid = progress_module.start_progress(request_id="caller-supplied-abc")
        self.assertEqual(rid, "caller-supplied-abc")
        self.assertEqual(progress_module.get_progress(request_id=rid)["request_id"], rid)


class ConcurrentJobsAreIsolatedTests(unittest.TestCase):
    def setUp(self) -> None:
        progress_module.reset_progress()

    def test_two_jobs_do_not_overwrite_each_other(self) -> None:
        rid_a = progress_module.start_progress("upload", "A starting", 5.0)
        rid_b = progress_module.start_progress("upload", "B starting", 5.0)

        # Without context-var management, updates target whichever was
        # started most recently (rid_b). The caller can recover rid_a's
        # state explicitly via get_progress(request_id=rid_a).
        state_a = progress_module.get_progress(request_id=rid_a)
        state_b = progress_module.get_progress(request_id=rid_b)

        self.assertEqual(state_a["request_id"], rid_a)
        self.assertEqual(state_a["message"], "A starting")
        self.assertEqual(state_b["request_id"], rid_b)
        self.assertEqual(state_b["message"], "B starting")

    def test_back_compat_returns_latest_started_job(self) -> None:
        progress_module.start_progress("upload", "A starting", 5.0)
        rid_b = progress_module.start_progress("upload", "B starting", 5.0)

        # Pre-F13 clients call get_progress() with no argument; they get
        # the most recent job, which is the next-best behavior.
        state = progress_module.get_progress()
        self.assertEqual(state["request_id"], rid_b)
        self.assertEqual(state["message"], "B starting")

    def test_get_progress_for_unknown_id_returns_idle(self) -> None:
        state = progress_module.get_progress(request_id="never-started-xyz")
        self.assertEqual(state["phase"], "idle")
        self.assertTrue(state["complete"])
        self.assertIsNone(state["request_id"])

    def test_get_progress_with_no_jobs_returns_idle(self) -> None:
        state = progress_module.get_progress()
        self.assertEqual(state["phase"], "idle")
        self.assertTrue(state["complete"])


class ContextVarRoutesUpdatesTests(unittest.IsolatedAsyncioTestCase):
    """Updates inside an async task target that task's start_progress slot
    even when another task starts its own slot concurrently. The
    ContextVar isolation is what gives us per-request progress without
    threading a request_id through every layer.
    """

    def setUp(self) -> None:
        progress_module.reset_progress()

    async def test_each_async_task_updates_its_own_slot(self) -> None:
        captured: dict[str, str] = {}

        async def _job(label: str) -> None:
            rid = progress_module.start_progress("upload", f"{label} start", 0.0)
            captured[label + "_rid"] = rid
            await asyncio.sleep(0.02)
            # The implicit "current request_id" is set on start_progress,
            # so this update lands on the right slot for THIS task.
            progress_module.update_progress("upload", f"{label} mid", 50.0)
            await asyncio.sleep(0.02)
            progress_module.complete_progress(f"{label} done")

        await asyncio.gather(_job("A"), _job("B"))

        rid_a = captured["A_rid"]
        rid_b = captured["B_rid"]
        state_a = progress_module.get_progress(request_id=rid_a)
        state_b = progress_module.get_progress(request_id=rid_b)

        self.assertEqual(state_a["message"], "A done")
        self.assertTrue(state_a["complete"])
        self.assertEqual(state_b["message"], "B done")
        self.assertTrue(state_b["complete"])

    async def test_context_var_propagates_through_to_thread(self) -> None:
        """The progress context var must survive asyncio.to_thread, so
        sync callbacks invoked from inside a worker thread target the
        right slot. This is the property that makes F08 + F13 compose
        cleanly without threading request_id through every helper.
        """

        def _sync_workload() -> None:
            progress_module.update_progress("upload", "from worker", 75.0)

        rid = progress_module.start_progress("upload", "starting", 0.0)
        await asyncio.to_thread(_sync_workload)
        state = progress_module.get_progress(request_id=rid)
        self.assertEqual(state["message"], "from worker")
        self.assertEqual(state["progress"], 75.0)


class ErrorAndCompleteHonorContextVarTests(unittest.TestCase):
    def setUp(self) -> None:
        progress_module.reset_progress()

    def test_complete_progress_marks_slot_complete(self) -> None:
        rid = progress_module.start_progress("upload", "running", 30.0)
        progress_module.complete_progress("all done")
        state = progress_module.get_progress(request_id=rid)
        self.assertEqual(state["phase"], "complete")
        self.assertEqual(state["progress"], 100.0)
        self.assertTrue(state["complete"])
        self.assertIsNone(state["error"])

    def test_error_progress_marks_slot_error(self) -> None:
        rid = progress_module.start_progress("upload", "running", 30.0)
        progress_module.error_progress("upstream went away")
        state = progress_module.get_progress(request_id=rid)
        self.assertEqual(state["phase"], "error")
        self.assertEqual(state["error"], "upstream went away")
        self.assertTrue(state["complete"])


class JobMapBoundedTests(unittest.TestCase):
    def setUp(self) -> None:
        progress_module.reset_progress()

    def test_oldest_entries_are_evicted_when_cap_is_exceeded(self) -> None:
        # Allocate one more than the cap. The oldest must fall off.
        cap = progress_module._MAX_TRACKED_JOBS
        first = progress_module.start_progress(request_id="job-0000")
        for i in range(1, cap + 1):
            progress_module.start_progress(request_id=f"job-{i:04d}")
        # The first id should no longer be tracked.
        state = progress_module.get_progress(request_id=first)
        self.assertEqual(state["phase"], "idle")
        # The most recent id should still be live.
        last = f"job-{cap:04d}"
        state_last = progress_module.get_progress(request_id=last)
        self.assertEqual(state_last["request_id"], last)


if __name__ == "__main__":
    unittest.main()

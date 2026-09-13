"""Parallel extraction must stay order-deterministic.

Parses run concurrently, so completion order varies between runs. Results are
placed by submission index and the revision id sorts by relative_path, so the
graph revision must not depend on scheduling.
"""

from __future__ import annotations

import random

from codegraph.common.concurrency import bounded_futures


def test_results_land_at_submission_index_regardless_of_completion_order() -> None:
    values = list(range(50))

    def shuffled_work(value: int) -> int:
        random.seed(value)
        return value * 10

    out: list[int | None] = [None] * len(values)
    for index, future in bounded_futures(shuffled_work, values, max_workers=8):
        out[index] = future.result()

    assert out == [v * 10 for v in values]


def test_a_worker_failure_propagates_rather_than_yielding_a_partial_graph() -> None:
    def sometimes_fails(value: int) -> int:
        if value == 7:
            raise RuntimeError("parser failed")
        return value

    raised = False
    try:
        for _index, future in bounded_futures(sometimes_fails, range(20), max_workers=4):
            future.result()
    except RuntimeError:
        raised = True
    assert raised, "a failed parse must not be silently skipped"

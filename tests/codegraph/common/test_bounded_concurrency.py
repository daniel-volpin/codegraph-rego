import pytest

from codegraph.common.concurrency import bounded_futures


def test_submission_does_not_eagerly_consume_all_inputs() -> None:
    consumed = []

    def inputs():
        for value in range(100):
            consumed.append(value)
            yield value

    results = bounded_futures(lambda value: value * 2, inputs(), max_workers=2)
    first_index, first_future = next(results)
    assert len(consumed) <= 4
    completed = {first_index: first_future.result()}
    completed.update({index: future.result() for index, future in results})
    assert completed == {value: value * 2 for value in range(100)}


def test_task_errors_are_available_without_discarding_other_results() -> None:
    def work(value):
        if value == 1:
            raise RuntimeError("failed item")
        return value

    results = dict(bounded_futures(work, [0, 1, 2], max_workers=1))
    assert results[0].result() == 0
    assert results[2].result() == 2
    with pytest.raises(RuntimeError, match="failed item"):
        results[1].result()


def test_invalid_worker_budget_is_rejected() -> None:
    with pytest.raises(ValueError, match="positive"):
        list(bounded_futures(str, [1], max_workers=0))

"""Bounded submission for blocking analysis work."""

from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from itertools import islice
from typing import TypeVar

T = TypeVar("T")
U = TypeVar("U")


def bounded_futures(
    function: Callable[[T], U], values: Iterable[T], *, max_workers: int,
) -> Iterator[tuple[int, Future[U]]]:
    if max_workers < 1:
        raise ValueError("Worker count must be positive")
    items = enumerate(values)
    pending: dict[Future[U], int] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        try:
            while True:
                for index, value in islice(items, max_workers * 2 - len(pending)):
                    pending[pool.submit(function, value)] = index
                if not pending:
                    return
                completed, _ = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    yield pending.pop(future), future
        finally:
            for future in pending:
                future.cancel()

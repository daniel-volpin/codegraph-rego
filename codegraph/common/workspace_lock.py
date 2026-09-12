"""Process-local serialization for mutations of the published workspace."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager, contextmanager
from threading import Lock

_WORKSPACE_MUTATION_LOCK = Lock()


@contextmanager
def workspace_mutation_guard() -> Iterator[None]:
    """Serialize synchronous workspace, graph, and search-index publication."""
    with _WORKSPACE_MUTATION_LOCK:
        yield


@asynccontextmanager
async def async_workspace_mutation_guard() -> AsyncIterator[None]:
    """Async adapter that does not block the event loop while waiting."""
    while not _WORKSPACE_MUTATION_LOCK.acquire(blocking=False):
        await asyncio.sleep(0.05)
    try:
        yield
    finally:
        _WORKSPACE_MUTATION_LOCK.release()

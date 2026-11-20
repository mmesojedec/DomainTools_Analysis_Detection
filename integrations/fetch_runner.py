"""
Shared helpers of the collection stages: a fetcher call that never raises, an ordered parallel map that counts each
lookup on the collection progress, and small frame / status helpers.
"""
from concurrent.futures import ThreadPoolExecutor, wait

import pandas as pd

from config import (
    MAX_WORKERS,
)
from integrations import progress
from integrations.http import FetchResult


def _safe_call(func, source, target, *args, **kwargs):
    """Runs a fetcher, converting unexpected exceptions into an error FetchResult."""
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # defensive: one failing lookup must not abort the whole run
        return FetchResult(source, str(target), error=f"Unexpected error: {type(exc).__name__}: {exc}"[:300])


def _parallel(items, func, max_workers=MAX_WORKERS, key=None):
    """
    Ordered parallel map for I/O-bound fetchers. With `key`, each lookup is counted on that row of the current
    collection progress, which this (the calling) thread redraws while it waits.
    """
    if not items:
        return []
    func, tracker = progress.counted(key, func), progress.current()
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(items)))) as executor:
        futures = [executor.submit(func, item) for item in items]
        pending = set(futures)
        while pending and tracker is not None:
            _, pending = wait(pending, timeout=progress.TICK_SECONDS)
            tracker.tick()
        return [future.result() for future in futures]


def _concat(frames):
    frames = [f for f in frames if f is not None and not f.empty]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _record_all(log, results):
    for result in results:
        log.record(result)
    return results

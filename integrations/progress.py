"""
Live progress of a collection run, one row per lookup of the run's query plan (core.use_cases.query_plan).

Worker threads count finished lookups (thread-safe); the thread that runs the collection calls `tick()` while it
waits for them, and only that thread draws (Streamlit elements must not be updated from worker threads): a tick from
any other thread, such as a collection stage running in the background, does nothing.
"""
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from integrations.cache import FROM_CACHE

WAITING, RUNNING, DONE, SKIPPED = "waiting", "running", "done", "skipped"
TICK_SECONDS = 0.3   # how often the waiting thread redraws while lookups run
CLOCK_SECONDS = 1.0  # how often running rows are redrawn for their elapsed time alone

_current = ContextVar("collection_progress", default=None)


@dataclass
class LookupRow:
    key: str
    source: str
    lookup: str
    state: str = WAITING
    total: int = 0       # lookups this row makes in this run
    started: int = 0
    done: int = 0
    cached: int = 0      # answered from the lookup cache (no API call)
    failed: int = 0
    records: int = 0
    cache_hits: list = field(default_factory=list)   # (target, epoch seconds it was fetched) of each cached result
    cache_lifetime: float = None   # how long this row's source keeps cached results (seconds), when it had a hit
    note: str = ""
    began: float = None  # time.monotonic() when the row first started running (orders the running rows)
    ended: float = None  # ... and when it was done or skipped (orders the finished rows)
    busy: float = 0.0    # seconds spent running: a row started again later (certificate events) skips the pause
    since: float = None  # start of the current running spell

    def took(self, now=None):
        """Seconds this row has been running, up to `now` (time.monotonic()) while it still runs."""
        running = self.since is not None and self.state == RUNNING
        return self.busy + ((time.monotonic() if now is None else now) - self.since if running else 0.0)


class CollectionProgress:
    """Rows keyed like the query plan ("iris", "history", "risk", "certs", "pdns", "TXT", "CAA", "CNAME", ...)."""

    def __init__(self, plan, render=None):
        self.rows = {row["Key"]: LookupRow(row["Key"], row["Source"], row["Lookup"]) for row in plan}
        self._render = render
        self._owner = threading.get_ident()   # the drawing thread
        self._lock = threading.Lock()
        self._changed = True
        self._last = 0.0

    def _row(self, key):
        return self.rows.get(key)

    def start(self, key, total, note=""):
        row = self._row(key)
        if row is None:
            return
        with self._lock:
            now = time.monotonic()
            if row.state != RUNNING:
                row.since = now
            row.state, row.note = RUNNING, note
            row.total += total
            row.began, row.ended = row.began or now, None
            self._changed = True
        self.tick(force=True)

    def begin(self, key):
        row = self._row(key)
        if row is not None:
            with self._lock:
                row.started += 1
                self._changed = True

    def advance(self, key, result):
        """One lookup of `key` finished with FetchResult `result` (called from any thread)."""
        row = self._row(key)
        if row is None:
            return
        with self._lock:
            row.done += 1
            row.cached += FROM_CACHE in str(getattr(result, "note", "") or "")
            if getattr(result, "cached_at", None) is not None:
                row.cache_hits.append((result.target, result.cached_at))
                row.cache_lifetime = getattr(result, "cache_lifetime", None) or row.cache_lifetime
            row.failed += getattr(result, "error", None) is not None
            row.records += getattr(result, "record_count", 0) or 0
            self._changed = True

    def note(self, key, text):
        row = self._row(key)
        if row is not None:
            with self._lock:
                row.note = text
                self._changed = True
            self.tick(force=True)

    def recovered(self, key, count):
        """`count` failed lookups of `key` succeeded when retried."""
        row = self._row(key)
        if row is not None and count:
            with self._lock:
                row.failed = max(0, row.failed - count)
                self._changed = True

    def finish(self, key, note=None):
        row = self._row(key)
        if row is None:
            return
        with self._lock:
            if row.state == RUNNING:
                row.state, row.ended = DONE, time.monotonic()
                row.busy += row.ended - row.since
            if note is not None:
                row.note = note
            self._changed = True
        self.tick(force=True)

    def skip(self, key, note):
        row = self._row(key)
        if row is None:
            return
        with self._lock:
            if row.state == WAITING:
                row.state, row.note, row.ended = SKIPPED, note, time.monotonic()
            self._changed = True
        self.tick(force=True)

    def close(self):
        """End of the run: rows never reached were not needed."""
        now = time.monotonic()
        for row in self.rows.values():
            if row.state == RUNNING:
                row.state, row.ended = DONE, now
                row.busy += now - row.since
            elif row.state == WAITING:
                row.state, row.note, row.ended = SKIPPED, row.note or "Not run", now
        self._changed = True
        self.tick(force=True)

    def snapshot(self):
        with self._lock:
            return [LookupRow(**{**vars(row), "cache_hits": list(row.cache_hits)}) for row in self.rows.values()]

    def tick(self, force=False):
        """Redraws when something changed (at most every TICK_SECONDS unless forced), and every CLOCK_SECONDS while a
        row runs so its elapsed time moves; call from the drawing thread."""
        if threading.get_ident() != self._owner:
            return
        since = time.monotonic() - self._last
        clock = since >= CLOCK_SECONDS and any(row.state == RUNNING for row in self.rows.values())
        if self._render is None or not (self._changed or clock) or (not force and since < TICK_SECONDS):
            return
        self._changed, self._last = False, time.monotonic()
        self._render(self)


@contextmanager
def tracking(progress):
    """Makes `progress` the tracker the collector's lookups report to, in this thread."""
    token = _current.set(progress)
    try:
        yield progress
    finally:
        _current.reset(token)


def current():
    return _current.get()


def start(key, total, note=""):
    if current() is not None:
        current().start(key, total, note)


def finish(key, note=None):
    if current() is not None:
        current().finish(key, note)


def skip(key, note):
    if current() is not None:
        current().skip(key, note)


def note(key, text):
    if current() is not None and key is not None:
        current().note(key, text)


def recovered(key, count):
    if current() is not None and key is not None:
        current().recovered(key, count)


def tick():
    if current() is not None:
        current().tick(force=True)


def counted(key, func):
    """`func` wrapped to report each call's start and FetchResult to the current tracker under `key`."""
    progress = current()
    if progress is None or key is None:
        return func

    def run(item):
        progress.begin(key)
        result = func(item)
        progress.advance(key, result)
        return result
    return run

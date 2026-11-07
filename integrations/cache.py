"""
Thread-safe TTL cache of successful FetchResults, in memory and on disk (CACHE_DIR, local and git-ignored), so a
domain, name or certificate looked up again within the cache lifetime costs no API query, also after an app restart.
The lifetime is the analyst's (Settings → Lookup cache, set_cache_ttl); 0 turns the cache off. Each source group
(CACHE_GROUPS: passive DNS, Iris Investigate, Domain History, certificates, VPNDB) can keep its results for its own
lifetime instead (set_group_ttl); with the cache off, every group is off.
"""
import functools
import gzip
import hashlib
import pickle
import threading
import time
from contextlib import contextmanager
from dataclasses import replace

from config import CACHE_DIR, CACHE_GROUP_DEFAULTS, FETCH_CACHE_TTL_SECONDS
from integrations.http import metered

_registry = []
_ttl = [FETCH_CACHE_TTL_SECONDS]
_group_ttl = dict(CACHE_GROUP_DEFAULTS)   # source group -> its own lifetime (seconds); absent: the cache lifetime
_lifetimes = {}   # cache folder name -> function returning that fetcher's lifetime (prune_cache)
_refreshing = [0]   # > 0 inside refreshing(): cached results are looked up again
FROM_CACHE = "From cache"


def set_cache_ttl(seconds):
    _ttl[0] = max(0, int(seconds))


def cache_ttl():
    return _ttl[0]


def set_group_ttl(group, seconds):
    """`group`'s own lifetime in seconds; None makes it follow the cache lifetime."""
    if seconds is None:
        _group_ttl.pop(group, None)
    else:
        _group_ttl[group] = max(0, int(seconds))


def group_ttl(group=None):
    """The lifetime of `group`'s cached results: its own, else the cache lifetime; 0 while the cache is off."""
    if _ttl[0] <= 0:
        return 0
    return _group_ttl.get(group, _ttl[0]) if group else _ttl[0]


@contextmanager
def refreshing():
    """Inside it, every cached fetch queries again (fresh results replace the cached ones), as for a re-chase."""
    _refreshing[0] += 1
    try:
        yield
    finally:
        _refreshing[0] -= 1


def age_text(seconds):
    """A duration as "2 h", "15 min", "40 s"."""
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size:
            return f"{seconds / size:.0f} {unit}"
    return f"{seconds:.0f} s"


def _from_cache(result, saved, lifetime=None):
    """The cached result marked in its note, so Data Source Status shows it cost no query."""
    mark = f"{FROM_CACHE} ({age_text(time.time() - saved)} old)"
    return replace(result, note=f"{result.note}; {mark}" if result.note else mark, cached_at=saved, queries=0,
                   cache_lifetime=lifetime)


def _disk_path(name, key):
    digest = hashlib.sha256(repr(key).encode()).hexdigest()
    return CACHE_DIR / name / f"{digest}.pkl.gz"


def _read(path):
    try:
        with gzip.open(path, "rb") as fh:
            return pickle.load(fh)
    except (OSError, EOFError, pickle.UnpicklingError, AttributeError, ImportError):
        return None


def _write(path, entry):
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with gzip.open(tmp, "wb") as fh:
            pickle.dump(entry, fh)
        tmp.replace(path)
    except OSError:
        pass   # the disk cache is an optimization; a read-only or full disk only costs repeat queries


def cached_fetch(ttl=None, group=None):
    """
    Caches a fetch function returning a FetchResult, keyed by its (hashable) arguments; `ttl` (seconds) overrides the
    analyst's cache lifetime, else `group`'s lifetime applies (group_ttl). Failed results (error set) are never cached,
    so transient errors are retried on the next run. Hits come back with "From cache (age old)" in their note and
    no queries; fresh results carry the API queries they made (http.metered).
    """
    def decorator(func):
        store = {}
        lock = threading.Lock()
        name = f"{func.__module__}.{func.__qualname__}"
        func = metered(func)

        def lifetime_now():
            return group_ttl(group) if ttl is None else ttl

        _lifetimes[name] = lifetime_now

        def lookup(key):
            """The valid cached (saved, result) for `key`, or None."""
            lifetime = lifetime_now()
            if lifetime <= 0 or _refreshing[0]:
                return None
            with lock:
                hit = store.get(key)
            if hit is None:
                hit = _read(_disk_path(name, key))
                if hit is not None:
                    with lock:
                        store[key] = hit
            return hit if hit and time.time() - hit[0] < lifetime else None

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            hit = lookup(key)
            if hit:
                return _from_cache(hit[1], hit[0], lifetime_now())
            lifetime = lifetime_now()
            now = time.time()
            result = func(*args, **kwargs)
            if getattr(result, "ok", False) and lifetime > 0:
                entry = (now, replace(result))   # a copy: callers may adjust the result they get
                with lock:
                    store[key] = entry
                _write(_disk_path(name, key), entry)
            return result

        def clear():
            with lock:
                store.clear()

        def peek(*args, **kwargs):
            """Whether a call would be answered from the cache, from the file's age alone (fast: nothing is read)."""
            lifetime = lifetime_now()
            if lifetime <= 0 or _refreshing[0]:
                return False
            key = (args, tuple(sorted(kwargs.items())))
            with lock:
                hit = store.get(key)
            if hit is not None:
                return time.time() - hit[0] < lifetime
            try:
                return time.time() - _disk_path(name, key).stat().st_mtime < lifetime
            except OSError:
                return False

        wrapper.cache_clear = clear
        wrapper.is_cached = lambda *args, **kwargs: lookup((args, tuple(sorted(kwargs.items())))) is not None
        wrapper.peek = peek
        _registry.append(clear)
        return wrapper
    return decorator


def clear_all_caches():
    """Forgets every cached result, in memory and on disk (Force refresh, Clear cache); returns how many files went."""
    for clear in _registry:
        clear()
    files = list(CACHE_DIR.glob("*/*.pkl.gz")) if CACHE_DIR.exists() else []
    for path in files:
        path.unlink(missing_ok=True)
    return len(files)


def prune_cache(max_age=None):
    """Deletes cached results older than `max_age` seconds (by default the lifetime of the fetcher that saved them)."""
    now = time.time()
    for path in CACHE_DIR.glob("*/*.pkl.gz") if CACHE_DIR.exists() else []:
        if max_age is not None:
            age_limit = max_age
        else:
            lifetime = _lifetimes.get(path.parent.name)
            age_limit = lifetime() if lifetime else max([cache_ttl(), *_group_ttl.values()])
        try:
            if path.stat().st_mtime < now - age_limit:
                path.unlink(missing_ok=True)
        except OSError:
            pass


def cache_usage():
    """(cached results on disk, total bytes)."""
    files = list(CACHE_DIR.glob("*/*.pkl.gz")) if CACHE_DIR.exists() else []
    return len(files), sum(f.stat().st_size for f in files if f.exists())

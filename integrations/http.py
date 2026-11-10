"""
Shared HTTP session (retries/backoff), DomainTools SDK retries, the per-lookup API query count, fetch results, and
error classification for all integrations.
"""
import functools
import threading
import time
from dataclasses import dataclass, field, replace

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.helpers import lookup_name

USER_AGENT = "DT-Analytics-Detection/2.0"
_thread_local = threading.local()
SDK_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})   # DomainTools SDK errors worth another try
SDK_ATTEMPTS = 3
SDK_BACKOFF_SECONDS = 2.0   # waits 2 s, then 4 s


def count_query(n=1):
    """Counts `n` API queries made by this thread (each HTTP request that reached an API)."""
    _thread_local.queries = getattr(_thread_local, "queries", 0) + n


def queries_made():
    """API queries this thread has made so far (see metered)."""
    return getattr(_thread_local, "queries", 0)


def metered(func):
    """
    Wraps a fetcher so its FetchResult carries `queries`: the API queries the call made in this thread (requests
    through get_session or a VPNDB session, SDK calls through sdk_call), unless it set them itself.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        before = queries_made()
        result = func(*args, **kwargs)
        if isinstance(result, FetchResult) and result.queries is None:
            result = replace(result, queries=queries_made() - before)
        return result
    return wrapper


def count_response(response, *args, **kwargs):
    """requests response hook: one API query per response."""
    count_query()
    return response


def sdk_call(request, attempts=SDK_ATTEMPTS, backoff=SDK_BACKOFF_SECONDS, sleep=time.sleep):
    """
    `request()` (one DomainTools SDK call, e.g. `lambda: api.iris_investigate(...).response()`), tried again after
    2 s and 4 s when it fails with HTTP 429 / 5xx or a connection error; other errors (401, 404, ...) are raised at once.
    Each attempt counts as one API query.
    """
    for attempt in range(1, attempts + 1):
        count_query()
        try:
            return request()
        except Exception as exc:
            if attempt == attempts or not _transient(exc):
                raise
            sleep(backoff * 2 ** (attempt - 1))


def _transient(exc):
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        return code in SDK_RETRY_STATUSES
    try:
        import httpx
    except ImportError:   # pragma: no cover - installed with the DomainTools SDK
        return False
    return isinstance(exc, httpx.TransportError)


def get_session():
    """Returns a per-thread requests.Session with retry/backoff on 429 and transient 5xx errors."""
    session = getattr(_thread_local, "session", None)
    if session is None:
        retry = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET", "POST"}),  # all POSTs used here are read-only searches
            respect_retry_after_header=True,
            raise_on_status=False,
        )
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers["User-Agent"] = USER_AGENT
        session.hooks["response"].append(count_response)
        _thread_local.session = session
    return session


@dataclass
class FetchResult:
    """Outcome of one source lookup: data plus an error message and/or truncation notice."""
    source: str
    target: str
    data: object = None
    error: str = None
    truncated: bool = False
    note: str = None
    record_count: int = 0
    extras: dict = field(default_factory=dict)  # supplemental results gathered in the same session (e.g. {"TXT": FetchResult})
    cached_at: float = None   # served from the cache: when (epoch seconds) the result was originally fetched
    queries: int = None       # API queries this lookup made (0 when served from the cache); see metered
    cache_lifetime: float = None   # served from the cache: how long (seconds) its source keeps cached results

    @property
    def ok(self):
        return self.error is None

    def status_row(self):
        detail = self.error or self.note or ""
        if self.error and self.record_count:
            status = "Partial"  # records were collected before the failure; keep them but flag the gap
            detail = f"Incomplete - {self.error} after {self.record_count} record(s)"
        elif self.error:
            status = "Error"
        elif self.truncated:
            status = "Partial"
        elif self.record_count == 0:
            status = "No data"
        else:
            status = "OK"
        return {
            "Source": lookup_name(self.source),
            "Target": self.target,
            "Status": status,
            "Records": self.record_count,
            "Detail": detail,
            # served from the lookup cache: when the result was originally fetched (UTC), else empty
            "Cached At": pd.to_datetime(self.cached_at, unit="s") if self.cached_at is not None else pd.NaT,
            "Queries": 0 if self.cached_at is not None else int(self.queries or 0),
        }


@dataclass
class StatusLog:
    """Thread-safe collector of per-source fetch outcomes (rendered by the UI on the main thread)."""
    rows: list = field(default_factory=list)
    raw: list = field(default_factory=list)   # answers kept as received, with the request that got them (VPNDB)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, result, request=None, keep_raw=False):
        """Logs `result`; `request` ({"method", "endpoint", "path", "params", "body"}) is kept on its status row so the
        lookup can be rebuilt as a query, and `keep_raw` also keeps the answer itself."""
        row = result.status_row()
        if request:
            row["Request"] = request
        with self._lock:
            self.rows.append(row)
            if keep_raw:
                self.raw.append({**row, "Response": result.data})
        return result

    def add(self, source, target, status, detail="", records=0):
        with self._lock:
            self.rows.append({"Source": source, "Target": target, "Status": status, "Records": records, "Detail": detail})


def describe_http_status(status_code):
    if status_code in (401, 403):
        return f"Authentication/authorization failed (HTTP {status_code}) - check the API key"
    if status_code == 429:
        return "Rate limited (HTTP 429) - retries exhausted"
    if status_code == 404:
        return "Not found (HTTP 404)"
    if 500 <= status_code < 600:
        return f"Server error (HTTP {status_code})"
    return f"HTTP {status_code}"


def describe_exception(exc):
    """Short human-readable description of a request/SDK exception."""
    if isinstance(exc, requests.exceptions.Timeout):
        return "Request timed out"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Connection error"
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None:
        return describe_http_status(exc.response.status_code)
    name = type(exc).__name__
    if name in ("ReadTimeout", "ConnectTimeout", "WriteTimeout", "PoolTimeout", "TimeoutException"):
        return "Request timed out"   # httpx (DomainTools SDK)
    if name in ("ConnectError", "RemoteProtocolError", "ReadError"):
        return "Connection error"
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        detail = describe_http_status(code)
        reason = getattr(exc, "reason", None)
        if isinstance(reason, dict):
            reason = reason.get("error", {}).get("message") if isinstance(reason.get("error"), dict) else reason.get("message")
        return f"{detail}: {reason}" if reason and code not in (401, 403) else detail
    return f"{type(exc).__name__}: {exc}"[:300]

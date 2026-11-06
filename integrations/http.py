"""Shared HTTP session (retries/backoff), fetch results, and error classification for all integrations."""
import threading
from dataclasses import dataclass, field

import pandas as pd
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

USER_AGENT = "DT-Analytics-Detection/2.0"
_thread_local = threading.local()


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
            "Source": self.source,
            "Target": self.target,
            "Status": status,
            "Records": self.record_count,
            "Detail": detail,
            # served from the lookup cache: when the result was originally fetched (UTC), else empty
            "Cached At": pd.to_datetime(self.cached_at, unit="s") if self.cached_at is not None else pd.NaT,
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
    code = getattr(exc, "code", None)
    if isinstance(code, int):
        detail = describe_http_status(code)
        reason = getattr(exc, "reason", None)
        if isinstance(reason, dict):
            reason = reason.get("error", {}).get("message") if isinstance(reason.get("error"), dict) else reason.get("message")
        return f"{detail}: {reason}" if reason and code not in (401, 403) else detail
    return f"{type(exc).__name__}: {exc}"[:300]

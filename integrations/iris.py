"""
Playwright-automated Iris Investigate passive DNS client and CSRF token manager.

A run checks the saved session once (opening the login window when it no longer works), then queries the targets
with up to IRIS_PDNS_WORKERS at a time, each worker through Playwright's HTTP client with the browser session's
cookies. Successful lookups are kept in the lookup cache like every other source.
"""
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

from config import IRIS_PDNS_LIMIT, IRIS_PDNS_WORKERS, IRIS_SUPPLEMENT_FETCH_LIMIT, SESSION_DIR, TOKEN_FILE
from core.helpers import is_ip_address
from core.pdns_features import build_pdns_frame
from integrations.cache import cached_fetch
from integrations.http import FetchResult, count_query, describe_http_status

SOURCE = "Iris pDNS"
IRIS_PDNS_URL = "https://iris.domaintools.com/product-api/iris-investigate/pdns/"
IRIS_LOGIN_URL = "https://iris.domaintools.com/iris-investigate/"
STATE_FILE = SESSION_DIR / "run_state.json"   # the session's cookies while a run's workers use them (deleted after)
PLAYWRIGHT_MISSING = "Playwright is not installed (pip install playwright && playwright install chromium)"
_local = threading.local()   # this thread's (Playwright request context, CSRF token) during a run


def load_token():
    """Loads the saved CSRF token from dt_token.json."""
    try:
        with open(TOKEN_FILE, "r") as f:
            return json.load(f).get("csrf_token")
    except (OSError, ValueError):
        return None


def save_token(token):
    """Saves the CSRF token with 0600 permissions. Raises OSError rather than writing a world-readable file."""
    fd = os.open(TOKEN_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)  # enforce even if the file pre-existed with looser permissions
    with os.fdopen(fd, "w") as f:
        json.dump({"csrf_token": token}, f)


def build_pdns_payload(target, rrtype=""):
    """Iris pDNS search payload. `rrtype` (e.g. "TXT", "CAA") restricts a domain query to one record type, newest first."""
    target_clean = str(target).strip()
    common = {
        "rrtype": "", "source": "", "limit": IRIS_PDNS_LIMIT, "time_first": "", "time_last": "",
        "strict_time": False, "auto": False, "sort_descending": True, "separate_by_source": True,
    }
    if is_ip_address(target_clean):
        return {**common, "depth": "apex", "query": target_clean, "search_type": "rdata", "sort_on": "time_first"}
    payload = {**common, "depth": "all", "query": f"*.{target_clean}", "search_type": "rrname", "sort_on": "rrname"}
    if rrtype:
        payload.update(rrtype=rrtype, limit=IRIS_SUPPLEMENT_FETCH_LIMIT, sort_on="time_first")
    return payload


def _query(request, token, target, rrtype=""):
    """Sends the pDNS POST with the session's cookies (`request`: a Playwright APIRequestContext). Returns
    (records or None, error or None)."""
    count_query()
    try:
        resp = request.post(
            IRIS_PDNS_URL,
            headers={"content-type": "application/json", "x-csrftoken": token},
            data=build_pdns_payload(target, rrtype),
            timeout=60000,
        )
    except Exception as exc:
        return None, f"Request failed: {type(exc).__name__}"
    if not resp.ok:
        return None, describe_http_status(resp.status)
    try:
        return resp.json().get("data", {}).get("results", []), None
    except Exception:
        return None, "Invalid JSON response"


def _result(target, records):
    truncated = len(records) >= IRIS_PDNS_LIMIT
    return FetchResult(SOURCE, target, data=records, truncated=truncated, record_count=len(records),
                       note=f"Iris pDNS returns at most {IRIS_PDNS_LIMIT} records per query; results may be incomplete"
                       if truncated else None)


def _capture_token_interactively(playwright):
    """Opens a visible browser for login and captures the x-csrftoken header from Iris requests."""
    browser = playwright.chromium.launch_persistent_context(user_data_dir=str(SESSION_DIR), headless=False)
    csrf_token = None
    try:
        page = browser.new_page()

        def intercept_request(request):
            nonlocal csrf_token
            if csrf_token:
                return
            try:
                for key, value in request.all_headers().items():
                    if key.lower() == "x-csrftoken":
                        csrf_token = value
                        break
            except Exception:
                pass

        page.on("request", intercept_request)
        page.goto(IRIS_LOGIN_URL)
        while not page.is_closed():
            try:
                page.wait_for_timeout(1000)
            except Exception:
                break
    finally:
        try:
            browser.close()
        except Exception:
            pass
    return csrf_token


def after_limit(records, rrtypes):
    """`rrtypes` when a main query hit its limit (it then holds only some of their records), none when complete."""
    return tuple(rrtypes) if records is not None and len(records) >= IRIS_PDNS_LIMIT else ()


def _bundle(target, outcomes):
    result = _result(target, outcomes[""][0])
    for rrtype, (records, error) in outcomes.items():
        if rrtype:
            result.extras[rrtype] = FetchResult(f"Iris pDNS {rrtype} Lookup", target, data=records or [], error=error,
                                                record_count=len(records or []))
    return result


def lookup_args(target, extra_rrtypes=(), if_capped_rrtypes=()):
    """The (target, extra rrtypes, if-capped rrtypes) a target is looked up (and cached) with: IPs get no supplements."""
    if is_ip_address(target):
        return target, (), ()
    return target, tuple(extra_rrtypes), tuple(if_capped_rrtypes)


@cached_fetch(group="pdns")
def iris_pdns_lookup(target, extra_rrtypes=(), if_capped_rrtypes=()):
    """
    The main pDNS query of `target` plus its supplemental rrtype queries (`if_capped_rrtypes` only when the main query
    hit its limit), through this thread's Iris session (see fetch_iris_pdns_many); supplements are in `.extras`.
    """
    request, token = getattr(_local, "session", (None, None))
    if request is None:
        return FetchResult(SOURCE, target, data=[], error="No Iris session")
    outcomes = {"": _query(request, token, target)}
    if outcomes[""][0] is None:
        return FetchResult(SOURCE, target, data=[], error=outcomes[""][1])
    for rrtype in tuple(extra_rrtypes) + after_limit(outcomes[""][0], if_capped_rrtypes):
        outcomes[rrtype] = _query(request, token, target, rrtype)
    return _bundle(target, outcomes)


def _first_lookup(playwright, token, args):
    """Looks up `args` in the persistent (logged-in) browser profile and saves its cookies to STATE_FILE for the
    workers. Returns the FetchResult."""
    browser = playwright.chromium.launch_persistent_context(user_data_dir=str(SESSION_DIR), headless=True)
    try:
        browser.storage_state(path=str(STATE_FILE))
        os.chmod(STATE_FILE, 0o600)
        _local.session = (browser.request, token)
        return iris_pdns_lookup(*args)
    finally:
        _local.session = (None, None)
        browser.close()


def _worker(token, jobs, on_result):
    """One worker thread: its own Playwright HTTP client with the session's cookies, looking up `jobs` in turn."""
    from playwright.sync_api import sync_playwright
    results = {}
    with sync_playwright() as playwright:
        context = playwright.request.new_context(storage_state=str(STATE_FILE))
        _local.session = (context, token)
        try:
            for args in jobs:
                results[args[0]] = _done(args[0], iris_pdns_lookup(*args), on_result)
        finally:
            _local.session = (None, None)
            context.dispose()
    return results


def _done(target, result, on_result):
    if on_result:
        on_result(target, result)
    return result


def fetch_iris_pdns_many(targets, on_auth_required=None, on_auth_done=None, extra_rrtypes=(), if_capped_rrtypes=(),
                         on_result=None, workers=IRIS_PDNS_WORKERS):
    """
    {target: FetchResult} of every target's Iris pDNS lookup (see iris_pdns_lookup). Cached results cost nothing; the
    first lookup that needs Iris checks the saved session, and when it fails `on_auth_required(target)` is called, a
    browser window opens for the login and `on_auth_done()` follows. The rest run `workers` at a time.
    `on_result(target, result)` is called as each lookup finishes (from any thread).
    """
    jobs = [lookup_args(t, extra_rrtypes, if_capped_rrtypes) for t in dict.fromkeys(targets)]
    results = {args[0]: _done(args[0], iris_pdns_lookup(*args), on_result)
               for args in jobs if iris_pdns_lookup.is_cached(*args)}
    todo = [args for args in jobs if args[0] not in results]
    if not todo:
        return results
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {**results, **{a[0]: _done(a[0], FetchResult(SOURCE, a[0], data=[], error=PLAYWRIGHT_MISSING), on_result)
                              for a in todo}}

    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    token, note, first = load_token(), None, todo[0]
    try:
        with sync_playwright() as playwright:
            result = _first_lookup(playwright, token, first) if token else None
            if result is None or not result.ok:
                if on_auth_required:
                    on_auth_required(first[0])
                token = _capture_token_interactively(playwright)
                if on_auth_done:
                    on_auth_done()
                if not token:
                    error = "Browser closed before an Iris session token was captured"
                    return {**results, **{a[0]: _done(a[0], FetchResult(SOURCE, a[0], data=[], error=error), on_result)
                                          for a in todo}}
                try:
                    save_token(token)
                except OSError as exc:
                    note = f"Token not saved securely ({exc}); you will be asked to log in again"
                result = _first_lookup(playwright, token, first)
                if not result.ok:
                    result = FetchResult(SOURCE, first[0], data=[], error=f"Post-login query failed: {result.error}")
            if note and not result.note:
                result.note = note
            results[first[0]] = _done(first[0], result, on_result)

        rest = todo[1:]
        shares = [rest[i::workers] for i in range(max(1, min(workers, len(rest))))]
        with ThreadPoolExecutor(max_workers=len(shares)) as executor:
            for share in executor.map(lambda jobs: _worker(token, jobs, on_result), [s for s in shares if s]):
                results.update(share)
    finally:
        STATE_FILE.unlink(missing_ok=True)
    return results


def parse_iris_json_to_dataframe(records, target_name):
    """Parses raw Iris pDNS JSON records into the standardized passive DNS DataFrame schema."""
    rows = []
    for obj in records or []:
        rows.append({
            "Domain": target_name,
            "RRName": str(obj.get("rrname", target_name)).rstrip("."),
            "Field": str(obj.get("rrtype", "Unknown")).upper(),
            "Value": str(obj.get("rdata", "")),
            "Count": obj.get("count") if obj.get("count") is not None else 1,
            "Source": obj.get("source", ""),
            "Bailiwick": obj.get("bailiwick", ""),
            "First Seen": obj.get("first_seen") or obj.get("time_first_iso"),
            "Last Seen": obj.get("last_seen") or obj.get("time_last_iso"),
        })
    if not rows:
        return build_pdns_frame(rows)
    frame = pd.DataFrame(rows)
    for col in ("First Seen", "Last Seen"):
        frame[col] = pd.to_datetime(frame[col], errors="coerce", utc=True).dt.tz_localize(None)
    return build_pdns_frame(frame.to_dict("records"))

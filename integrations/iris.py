"""Playwright-automated Iris Investigate passive DNS client and CSRF token manager."""
import json
import os

import pandas as pd

from config import IRIS_PDNS_LIMIT, IRIS_SUPPLEMENT_FETCH_LIMIT, SESSION_DIR, TOKEN_FILE
from core.helpers import is_ip_address
from core.pdns_features import build_pdns_frame
from integrations.http import FetchResult, describe_http_status

SOURCE = "Iris pDNS"
IRIS_PDNS_URL = "https://iris.domaintools.com/product-api/iris-investigate/pdns/"
IRIS_LOGIN_URL = "https://iris.domaintools.com/iris-investigate/"


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


def _query(page, token, target, rrtype=""):
    """Sends the pDNS POST using the browser session's cookies. Returns (records or None, error or None)."""
    try:
        resp = page.request.post(
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


def _run_queries(playwright, token, target, rrtypes, if_capped=()):
    """
    Runs the main query plus any supplemental rrtype queries in one headless browser session. `if_capped` rrtypes are
    queried only when the main query hit its limit.
    """
    browser = playwright.chromium.launch_persistent_context(user_data_dir=str(SESSION_DIR), headless=True)
    try:
        page = browser.new_page()
        outcomes = {"": _query(page, token, target)}
        for rrtype in tuple(rrtypes) + after_limit(outcomes[""][0], if_capped):
            outcomes[rrtype] = _query(page, token, target, rrtype)
        return outcomes
    finally:
        browser.close()


def _bundle(target, outcomes):
    result = _result(target, outcomes[""][0])
    for rrtype, (records, error) in outcomes.items():
        if rrtype:
            result.extras[rrtype] = FetchResult(f"Iris pDNS {rrtype} Supplement", target, data=records or [], error=error,
                                                record_count=len(records or []))
    return result


def fetch_iris_pdns(target, on_auth_required=None, on_auth_done=None, extra_rrtypes=(), if_capped_rrtypes=()):
    """
    Fetches pDNS records through the authenticated Iris browser session.
    `extra_rrtypes` (e.g. ("TXT",)) adds record-type-specific queries in the same session; their results are in `.extras`.
    `if_capped_rrtypes` (e.g. ("CNAME",)) are queried only when the main query hit its limit.
    `on_auth_required(target)` / `on_auth_done()` let the UI show login instructions.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return FetchResult(SOURCE, target, data=[], error="Playwright is not installed (pip install playwright && playwright install chromium)")

    rrtypes = () if is_ip_address(target) else tuple(extra_rrtypes)
    if_capped = () if is_ip_address(target) else tuple(if_capped_rrtypes)
    SESSION_DIR.mkdir(parents=True, exist_ok=True)
    saved_token = load_token()
    token_note = None

    with sync_playwright() as p:
        if saved_token:
            outcomes = _run_queries(p, saved_token, target, rrtypes, if_capped)
            if outcomes[""][0] is not None:
                return _bundle(target, outcomes)

        if on_auth_required:
            on_auth_required(target)
        csrf_token = _capture_token_interactively(p)
        if on_auth_done:
            on_auth_done()
        if not csrf_token:
            return FetchResult(SOURCE, target, data=[], error="Browser closed before an Iris session token was captured")

        try:
            save_token(csrf_token)
        except OSError as exc:
            token_note = f"Token not saved securely ({exc}); you will be asked to log in again"

        outcomes = _run_queries(p, csrf_token, target, rrtypes, if_capped)
        if outcomes[""][0] is None:
            return FetchResult(SOURCE, target, data=[], error=f"Post-login query failed: {outcomes[''][1]}")
        result = _bundle(target, outcomes)
        if token_note and not result.note:
            result.note = token_note
        return result


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

"""DomainTools DNSDB v2 REST API integration (SAF/NDJSON streaming) and parser."""
import json
import time
import urllib.parse
from dataclasses import replace

import pandas as pd
import requests

from core.cname import QUERY_LIMIT, classify_target
from core.helpers import is_ip_address, refang_domain
from core.pdns_features import build_pdns_frame
from integrations.cache import FROM_CACHE, cached_fetch
from integrations.credentials import DNSDB_MISSING, load_dnsdb_key
from integrations.http import FetchResult, describe_exception, describe_http_status, get_session

DNSDB_BASE_URL = "https://api.dnsdb.info/dnsdb/v2/lookup"
MAX_BATCH_SIZE = 100000
CLIENT_PARAMS = {"swclient": "DT_Analytics", "version": "2.0.0", "aggr": "f"}   # sent with every lookup
# Record types looked up aggregated (one record per name and value, first and last seen across all time) instead of
# one per time slice: CNAME supplements, chases and reverse CNAME lookups need many names, not daily repeats of a few
# (a 5,000-record nytimes.com CNAME lookup holds ~10 names non-aggregated, ~5,000 aggregated).
AGGREGATED_TYPES = ("CNAME", "A", "AAAA")


def client_params(rrtype="ANY"):
    """Query parameters of a lookup of `rrtype` (aggregated for AGGREGATED_TYPES)."""
    return {**CLIENT_PARAMS, "aggr": "t"} if rrtype in AGGREGATED_TYPES else CLIENT_PARAMS
REQUEST_TIMEOUT = 60
SOURCE = "DNSDB Scout"


def _dedup_key(obj):
    rdata = obj.get("rdata", [])
    rdata_tuple = tuple(rdata) if isinstance(rdata, list) else (rdata,)
    return (obj.get("rrname"), obj.get("rrtype"), rdata_tuple, obj.get("time_first"), obj.get("time_last"),
            obj.get("zone_time_first"), obj.get("zone_time_last"))


def parse_saf_lines(lines):
    """
    Parses DNSDB Streaming API Framing lines.
    Returns (objects, condition, message) where condition is begin/ongoing/succeeded/limited/failed or None.
    """
    objects, condition, message = [], None, None
    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        if not line or not line.strip():
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "obj" in data:
            objects.append(data["obj"])
        if "cond" in data:
            condition = data["cond"]
            message = data.get("msg", message)
    return objects, condition, message


def _lookup_urls(clean_target, rrtype="ANY", include_wildcard=True):
    """
    Lookup URLs in the order they are tried. A wildcard lookup (`*.example.com`) also returns the apex's own records,
    so the exact name second is only requested when the wildcard lookup stops at its limit (see fetch_dnsdb_history).
    """
    if is_ip_address(clean_target):
        return [f"{DNSDB_BASE_URL}/rdata/ip/{urllib.parse.quote(clean_target, safe='')}"]
    wildcard = include_wildcard and not clean_target.startswith("*")
    names = [f"*.{clean_target}", clean_target] if wildcard else [clean_target]
    return [f"{DNSDB_BASE_URL}/rrset/name/{urllib.parse.quote(name, safe='*')}/{rrtype}" for name in names]


def _fetch(source, clean_target, urls, limit, api_key, rrtype="ANY", since=None):
    """Pages through `urls` in order (the next one only when the previous stopped at its limit); one FetchResult.
    `since` (epoch seconds) keeps only records last seen after it (DNSDB time fencing)."""
    headers = {"Accept": "application/x-ndjson", "X-API-Key": api_key}
    records, seen, notes, truncated = [], set(), [], False

    for position, url in enumerate(urls):
        if position and not truncated:
            break   # the wildcard lookup was complete and already holds the apex's records
        fetched = 0
        while fetched < limit:
            batch_limit = min(MAX_BATCH_SIZE, limit - fetched)
            params = {"limit": batch_limit, **client_params(rrtype)}
            if since:
                params["time_last_after"] = int(since)
            if fetched:
                params["offset"] = fetched
            try:
                with get_session().get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT, stream=True) as resp:
                    if resp.status_code == 404:
                        break
                    if not resp.ok:
                        return FetchResult(source, clean_target, data=records, error=describe_http_status(resp.status_code),
                                           record_count=len(records))
                    objects, condition, message = parse_saf_lines(resp.iter_lines())
            except Exception as exc:
                return FetchResult(source, clean_target, data=records, error=describe_exception(exc), record_count=len(records))

            if condition == "failed":
                return FetchResult(source, clean_target, data=records, error=f"DNSDB query failed: {message or 'unknown error'}",
                                   record_count=len(records))
            for obj in objects:
                key = _dedup_key(obj)
                if key not in seen:
                    seen.add(key)
                    records.append(obj)
            fetched += len(objects)

            if condition == "limited":
                truncated = True
                notes.append(message or "DNSDB result limit reached")
                break
            if len(objects) < batch_limit:
                break
        else:
            truncated = True
            notes.append(f"Stopped at the configured limit of {limit} records per name")

    return FetchResult(source, clean_target, data=records, truncated=truncated, record_count=len(records),
                       note="; ".join(dict.fromkeys(notes)) or None)


@cached_fetch(group="pdns")
def fetch_dnsdb_history(target, limit=5000, rrtype="ANY", include_wildcard=True, since=None):
    """
    Fetches passive DNS records from DNSDB v2. IP targets query rdata/ip/{ip}; domain targets query
    rrset/name/*.{domain}/{rrtype}, which includes the domain's own records, and rrset/name/{domain}/{rrtype} only when
    the wildcard lookup stops at its limit (so the apex's records are complete even on busy domains).
    A specific `rrtype` (e.g. "TXT", "CAA") is used for supplemental lookups and does not apply to IP targets;
    `include_wildcard=False` queries only the name itself (CAA policy applies to the apex name). `since` (epoch
    seconds) returns only records last seen after it, for an incremental lookup (collect_pdns `base`).
    """
    api_key = load_dnsdb_key()
    clean_target = str(target).strip() if is_ip_address(target) else refang_domain(target)
    source = SOURCE if rrtype == "ANY" else f"DNSDB {rrtype} Supplement"
    if rrtype != "ANY" and is_ip_address(clean_target):
        return FetchResult(source, clean_target, data=[], note=f"{rrtype} lookups do not apply to IP targets")
    if not api_key:
        return FetchResult(source, clean_target, data=[], error=DNSDB_MISSING)
    if not clean_target:
        return FetchResult(source, str(target), data=[], error="Empty target")

    return _fetch(source, clean_target, _lookup_urls(clean_target, rrtype, include_wildcard), limit, api_key, rrtype,
                  since)


RATE_LIMIT_URL = "https://api.dnsdb.info/dnsdb/v2/rate_limit"


def fetch_dnsdb_rate_limit():
    """
    DNSDB's quota of the key (GET /dnsdb/v2/rate_limit, which does not count against it): data = the `rate` object
    (limit, remaining, reset and expires as epoch seconds, or "n/a" / "unlimited"; burst size and window when set).
    """
    api_key = load_dnsdb_key()
    if not api_key:
        return FetchResult("DNSDB rate limit", "key", error=DNSDB_MISSING)
    try:
        resp = requests.get(RATE_LIMIT_URL, headers={"Accept": "application/x-ndjson", "X-API-Key": api_key},
                            timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        return FetchResult("DNSDB rate limit", "key", error=describe_exception(exc))
    if not resp.ok:
        return FetchResult("DNSDB rate limit", "key", error=describe_http_status(resp.status_code))
    try:   # one JSON object on its own line (the API answers JSON only as x-ndjson)
        rate = json.loads(next((line for line in resp.text.splitlines() if line.strip()), "{}")).get("rate") or {}
    except ValueError:
        return FetchResult("DNSDB rate limit", "key", error="Invalid JSON response")
    return FetchResult("DNSDB rate limit", "key", data=rate, record_count=1)


def parse_dnsdb_to_dataframe(records, target_name):
    """Parses raw DNSDB v2 records into the standardized passive DNS DataFrame schema."""
    rows = []
    for obj in records or []:
        rdata = obj.get("rdata", [])
        t_first = obj.get("time_first") or obj.get("zone_time_first")
        t_last = obj.get("time_last") or obj.get("zone_time_last")
        rows.append({
            "Domain": target_name,
            "RRName": str(obj.get("rrname", target_name)).rstrip("."),
            "Field": str(obj.get("rrtype", "Unknown")).upper(),
            "Value": "\n".join(str(r) for r in rdata) if isinstance(rdata, list) else str(rdata),
            "Count": obj.get("count") if obj.get("count") is not None else 1,
            "Source": SOURCE,
            "Bailiwick": str(obj.get("bailiwick", "")).rstrip("."),
            "First Seen": _epoch_to_naive(t_first),
            "Last Seen": _epoch_to_naive(t_last),
        })
    return build_pdns_frame(rows)


def _epoch_to_naive(value):
    if not value:
        return pd.NaT
    parsed = pd.to_datetime(value, unit="s", errors="coerce", utc=True)
    return parsed.tz_localize(None) if pd.notna(parsed) else pd.NaT


CHASE_SOURCE = "DNSDB CNAME Chase"
CHASE_OUTCOMES = {
    "Resolves": "The chain ends at A / AAAA records",
    "Dead end": "A name in the chain has no CNAME, A or AAAA record in DNSDB: it never resolved, or stopped long ago "
                "(possible dangling CNAME)",
    "Incomplete": "The chain ends at a CDN name DNSDB has no address for (CDN edges answer per client and passive DNS "
                  "often misses them): where it finally resolves is unknown, not a sign of a dangling CNAME",
    "Loop": "The chain returns to a name it already passed",
    "Step limit": "Stopped after the maximum number of steps",
    "Lookup failed": "A DNSDB lookup failed; see Data Source Status",
    QUERY_LIMIT: "The chase reached its domain's query limit for this click; chase again to continue",
}


def _latest(records, rrtypes):
    """(latest time_last as a naive timestamp, values seen within a day of it) for records of these types."""
    rows = [(_epoch_to_naive(r.get("time_last") or r.get("zone_time_last")), r.get("rdata"))
            for r in records if str(r.get("rrtype", "")).upper() in rrtypes]
    rows = [(t, v) for t, v in rows if pd.notna(t)]
    if not rows:
        return pd.NaT, []
    newest = max(t for t, _ in rows)
    values = []
    for seen, rdata in rows:
        if newest - seen <= pd.Timedelta(days=1):
            values += [str(v).rstrip(".") for v in (rdata if isinstance(rdata, list) else [rdata])]
    return newest, list(dict.fromkeys(values))


class _BudgetSpent(Exception):
    pass


class QueryBudget:
    """DNSDB queries one domain may spend on chases; lookups served from the cache are free."""

    def __init__(self, limit):
        self.left = limit

    def allows(self, target, limit, rrtype):
        is_cached = getattr(fetch_dnsdb_history, "is_cached", lambda *args: False)
        return self.left > 0 or is_cached(target, limit, rrtype, False)

    def spend(self, result):
        if FROM_CACHE not in str(result.note or ""):
            self.left -= 1


def chase_cname(name, max_steps=10, limit=500, budget=None):
    """
    CNAME chasing as in DNSDB Scout: from `name`, follows the most recent CNAME one name at a time until a name has no
    CNAME; that name's A records (AAAA when it has none) end the chain. Lookups are per record type (name/CNAME, then
    name/A and name/AAAA at the end), so a busy name's other records cannot crowd the CNAME out of a capped result.
    Returns (chase dict, FetchResults with source "DNSDB CNAME Chase (<type>)").
    The chase dict has Start, Path (names joined by " → "), Hops (CNAMEs followed), Outcome (CHASE_OUTCOMES), Final
    (the last name's addresses), Final Last Seen and Note. With a `budget` (QueryBudget), the chase stops with
    Outcome QUERY_LIMIT before a lookup the budget no longer allows.
    """
    path, results = [str(name).strip().lower().rstrip(".")], []

    def lookup(target, rrtype):
        if budget is not None and not budget.allows(target, limit, rrtype):
            raise _BudgetSpent
        result = replace(fetch_dnsdb_history(target, limit, rrtype, False), source=f"{CHASE_SOURCE} ({rrtype})")
        results.append(result)
        if budget is not None:
            budget.spend(result)
        return result

    try:
        outcome, final, final_seen, note = _follow(path, max_steps, lookup)
    except _BudgetSpent:
        outcome, final, final_seen, note = QUERY_LIMIT, [], pd.NaT, f"Stopped at {path[-1]}: query limit reached"
    fetched = [r.cached_at if r.cached_at is not None else time.time() for r in results]
    chase = {"Start": path[0], "Path": " → ".join(path), "Hops": len(path) - 1, "Outcome": outcome,
             "Final": ", ".join(final), "Final Last Seen": final_seen, "Note": note,
             "Chased At": pd.to_datetime(min(fetched), unit="s") if fetched else pd.NaT,
             "From Cache": bool(results) and all(r.cached_at is not None for r in results)}
    return chase, results


def _follow(path, max_steps, lookup):
    """Extends `path` CNAME by CNAME through `lookup`; returns (outcome, final addresses, final last seen, note)."""
    outcome, final, final_seen, note = "Step limit", [], pd.NaT, ""
    for _ in range(max_steps):
        current = path[-1]
        result = lookup(current, "CNAME")
        if not result.ok:
            outcome, note = "Lookup failed", result.error or ""
            break
        _, cnames = _latest(result.data or [], {"CNAME"})
        if cnames:
            target = cnames[0].lower()
            if target in path:
                outcome, note = "Loop", f"{current} points back to {target}"
                break
            path.append(target)
            continue
        for rrtype in ("A", "AAAA"):
            result = lookup(current, rrtype)
            if not result.ok:
                outcome, note = "Lookup failed", result.error or ""
                break
            final_seen, final = _latest(result.data or [], {rrtype})
            if final:
                outcome = "Resolves"
                break
        else:
            cdn = classify_target(current)
            outcome, note = ("Incomplete", f"No A or AAAA record in DNSDB for the {cdn[1]} name {current}") \
                if cdn[0] == "CDN" else ("Dead end", f"No CNAME, A or AAAA record for {current}")
        break
    return outcome, final, final_seen, note


RDATA_SOURCE = "DNSDB CNAME RDATA"


def rdata_url(name, rrtype="CNAME"):
    return f"{DNSDB_BASE_URL}/rdata/name/{urllib.parse.quote(name, safe='')}/{rrtype}"


@cached_fetch(group="pdns")
def fetch_cname_rdata(name, limit=5000):
    """Reverse CNAME lookup (rdata/name/{name}/CNAME): every name DNSDB saw pointing to `name` by CNAME."""
    api_key = load_dnsdb_key()
    clean = refang_domain(name)
    if not api_key:
        return FetchResult(RDATA_SOURCE, clean, data=[], error=DNSDB_MISSING)
    if not clean:
        return FetchResult(RDATA_SOURCE, str(name), data=[], error="Empty target")
    return _fetch(RDATA_SOURCE, clean, [rdata_url(clean)], limit, api_key, "CNAME")

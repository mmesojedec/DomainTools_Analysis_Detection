"""
VPNDB REST API (vpndb.io): which VPN, residential proxy or Tor operator is behind an IP, prefix or ASN, with what
weight, confidence and evidence. Every operation of the API has one function here, each returning a FetchResult whose
`data` is the parsed answer (a dict; text for the CSV relay list and the specification).

- A miss is an answer, not an error: 404 `{"observed": false, "reason": ...}` comes back as data with status "No data"
  and the reason in the note (`not_collected` for every IPv6 address). It never means the address is clean.
- Paged lists (`nextCursor`) are followed up to `max_pages` pages and merged into one answer; `nextCursor` is kept when
  more pages are left, and the result is marked truncated.
- 429 is reported, not retried: `rate_limited` (600 requests per 5 minutes per account) and a demo account's
  `quota_exceeded` both say when to try again. The quota headers of every metered answer are in extras["quota"].
"""
import threading
import time
import urllib.parse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from integrations.cache import cached_fetch
from integrations.credentials import VPNDB_MISSING, load_vpndb_key, vpndb_base_url
from integrations.http import USER_AGENT, FetchResult, count_query, count_response, describe_exception, describe_http_status

SOURCE = "VPNDB"
VPNDB_RATE_LIMIT = "600 requests per 5 minutes, shared by all keys of the account"
REQUEST_TIMEOUT = 60
BULK_LIMIT = 10000          # addresses per bulk request
DEFAULT_MAX_PAGES = 5       # pages followed per paged list call
QUOTA_HEADERS = {"X-Quota-Remaining": "remaining", "X-Quota-Remaining-Day": "remaining_day",
                 "X-Quota-Remaining-Lists": "remaining_lists", "X-Quota-Notice": "notice"}
MISS_REASONS = {
    "not_observed": "not observed by VPNDB (not an all-clear)",
    "not_collected": "not collected (VPNDB does not gather IPv6)",
    "out_of_scope": "out of VPNDB's scope",
}
_thread_local = threading.local()
# Metered paths: a demo account's answers to these carry the quota headers; a customer account's never do.
METERED_PREFIXES = ("/ip/", "/bulk", "/prefix/", "/asn/", "/org/", "/service/", "/country/", "/search")
_last_quota = {}   # the quota headers of the last metered answer, with "at" (epoch seconds): the Account page
_quota_lock = threading.Lock()


def last_quota():
    """
    The quota VPNDB reported on its last metered answer this session ({"remaining", ..., "at"}); {"no_quota": True,
    "at"} when that answer had no quota headers (a customer account: only demo accounts have a quota); {} before any.
    """
    with _quota_lock:
        return dict(_last_quota)


def _session():
    """A per-thread session retrying transient 5xx errors only: a 429 can ask to wait until a quota resets."""
    session = getattr(_thread_local, "session", None)
    if session is None:
        retry = Retry(total=3, backoff_factor=1.0, status_forcelist=(500, 502, 503, 504),
                      allowed_methods=frozenset({"GET", "POST"}), raise_on_status=False)   # the bulk POST only reads
        session = requests.Session()
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        session.headers["User-Agent"] = USER_AGENT
        session.hooks["response"].append(count_response)
        _thread_local.session = session
    return session


def _segment(value):
    return urllib.parse.quote(str(value).strip(), safe="")


def _params(**values):
    """Query parameters without the unset ones; booleans as true / false."""
    return {key: str(value).lower() if isinstance(value, bool) else value
            for key, value in values.items() if value is not None and value != ""}


def _json(response):
    try:
        return response.json()
    except ValueError:
        return {}


def _quota(response):
    return {name: response.headers[header] for header, name in QUOTA_HEADERS.items() if header in response.headers}


def _error_text(response, body):
    """The API's own error note where it gives one (it says what to do), else the HTTP description."""
    code, note = body.get("error"), body.get("note")
    if response.status_code == 429:
        wait = response.headers.get("Retry-After")
        kind = "Demo quota exhausted" if code == "quota_exceeded" else "Rate limited (600 requests per 5 minutes)"
        return f"{kind}" + (f", retry after {wait} s" if wait else "") + (f": {note}" if note else "")
    if response.status_code in (401, 403):
        return describe_http_status(response.status_code) + (f": {note}" if note else "")
    return f"{describe_http_status(response.status_code)}" + (f" ({code}): {note}" if code or note else "")


def _request(target, path, params=None, body=None, auth=True, text=False):
    """
    One call: (FetchResult, response or None). 200 → data; 404 with `observed: false` → the miss as data, "No data";
    anything else → error.
    """
    api_key = load_vpndb_key()
    if auth and not api_key:
        return FetchResult(SOURCE, target, error=VPNDB_MISSING), None
    headers = {"Accept": "text/csv" if text == "csv" else "application/yaml" if text else "application/json"}
    if auth:
        headers["Authorization"] = f"Bearer {api_key}"
    url = f"{vpndb_base_url()}{path}"
    try:
        if body is None:
            response = _session().get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        else:
            response = _session().post(url, params=params, json=body, headers=headers, timeout=REQUEST_TIMEOUT)
    except Exception as exc:
        return FetchResult(SOURCE, target, error=describe_exception(exc)), None
    extras = {"quota": quota} if (quota := _quota(response)) else {}
    if quota or (auth and response.status_code in (200, 404) and path.startswith(METERED_PREFIXES)):
        with _quota_lock:
            _last_quota.clear()
            _last_quota.update(quota or {"no_quota": True}, at=time.time())
    if response.status_code == 200:
        data = response.text if text else _json(response)
        result = FetchResult(SOURCE, target, data=data, record_count=1, extras=extras)
        if isinstance(data, dict) and data.get("degraded"):
            result.note = f"Degraded: {data['degraded']}"
        return result, response
    body_json = _json(response)
    if response.status_code == 404 and body_json.get("observed") is False:
        reason = body_json.get("reason", "not_observed")
        return FetchResult(SOURCE, target, data=body_json, note=MISS_REASONS.get(reason, reason), extras=extras), response
    return FetchResult(SOURCE, target, data=body_json or None, error=_error_text(response, body_json), extras=extras), None


def _get(target, path, auth=True, **params):
    return _request(target, path, params=_params(**params), auth=auth)[0]


def _paged(target, path, items_key, max_pages=DEFAULT_MAX_PAGES, **params):
    """Follows `nextCursor` for up to `max_pages` pages; one answer with every page's `items_key` rows."""
    merged, cursor, pages = None, None, 0
    while True:
        result, _ = _request(target, path, params=_params(**params, cursor=cursor))
        if not result.ok or not isinstance(result.data, dict) or items_key not in result.data:
            if merged is None:
                return result
            merged.data["nextCursor"] = cursor   # resume from the page that failed
            merged.error, merged.record_count = result.error, len(merged.data[items_key])
            return merged
        pages += 1
        if merged is None:
            merged = result
        else:
            merged.data[items_key].extend(result.data[items_key])
            merged.extras.update(result.extras)
        cursor = result.data.get("nextCursor")
        merged.data["nextCursor"] = cursor
        if not cursor or pages >= max_pages:
            break
    merged.record_count = len(merged.data[items_key])
    if cursor:
        merged.truncated = True
        merged.note = f"Stopped after {pages} page(s); more are available (nextCursor)"
    else:
        merged.data.pop("nextCursor", None)
    return merged


# ---- lookup -----------------------------------------------------------------------------------------------------

@cached_fetch(group="vpndb")
def lookup_ip(ip):
    """GET /ip/{ip}: the verdict for one IPv4 address (attribution, evidence, sharing, tunnel, ASN, location, Tor)."""
    return _get(ip, f"/ip/{_segment(ip)}")


@cached_fetch(group="vpndb")
def ip_history(ip):
    """GET /ip/{ip}/history: every week since probing began, with the strongest evidence of each week."""
    return _get(ip, f"/ip/{_segment(ip)}/history")


@cached_fetch(group="vpndb")
def lookup_prefix(cidr):
    """GET /prefix/{cidr}: the providers inside any CIDR range and their shares."""
    return _get(cidr, f"/prefix/{_segment(cidr)}")


@cached_fetch(group="vpndb")
def prefix_addresses(cidr, date_from=None, date_to=None, provider=None, method=None, pool=None, size=50,
                     max_pages=DEFAULT_MAX_PAGES):
    """
    GET /prefix/{cidr}/addresses: every address of the prefix probing reached between `date_from` and `date_to`
    (dates; default the last 30 days), filtered by `provider`, `method` (tunnel protocol, proxy, interpolated,
    observed; comma-separated) and `pool` (residential / datacenter). Prefixes broader than /12 are refused.
    """
    return _paged(cidr, f"/prefix/{_segment(cidr)}/addresses", "addresses", max_pages, size=size, provider=provider,
                  method=method, pool=pool, **{"from": date_from, "to": date_to})


@cached_fetch(group="vpndb")
def prefix_timeline(cidr):
    """GET /prefix/{cidr}/timeline: probe events and distinct addresses per day over the prefix's history."""
    return _get(cidr, f"/prefix/{_segment(cidr)}/timeline")


@cached_fetch(group="vpndb")
def lookup_asn(asn):
    """GET /asn/{asn}: the providers on an ASN and their shares (one tenant, or many: the collateral of a block)."""
    return _get(f"AS{asn}", f"/asn/{int(str(asn).upper().removeprefix('AS'))}")


@cached_fetch(group="vpndb")
def asn_networks(asn, provider=None, q=None, shared=None, sort="tenancy", size=50, max_pages=DEFAULT_MAX_PAGES):
    """GET /asn/{asn}/networks: every prefix of the ASN holding a known exit address."""
    number = int(str(asn).upper().removeprefix("AS"))
    return _paged(f"AS{number}", f"/asn/{number}/networks", "networks", max_pages, provider=provider, q=q,
                  shared=shared, sort=sort, size=size)


@cached_fetch(group="vpndb")
def lookup_service(tag):
    """GET /service/{tag}: a provider's profile (category, status, addresses, networks, countries, protocols)."""
    return _get(tag, f"/service/{_segment(tag)}")


@cached_fetch(group="vpndb")
def list_services():
    """GET /services: every provider at a glance (addresses, last 30 days, prefixes, ASNs, countries)."""
    return _get("services", "/services")


@cached_fetch(group="vpndb")
def tor_overview():
    """GET /tor: where Tor traffic leaves the internet and who runs it."""
    return _get("tor", "/tor")


@cached_fetch(group="vpndb")
def tor_relays(role=None, size=200, max_pages=DEFAULT_MAX_PAGES, fmt="json"):
    """
    GET /tor/relays: every running relay's address and OR port, exits first; `role` exit, guard or middle. With
    fmt="csv" the data is the CSV text of the first page (its continuation in extras["next_cursor"]).
    """
    target = f"tor relays{f' ({role})' if role else ''}"
    if fmt == "csv":
        result, response = _request(target, "/tor/relays", params=_params(role=role, size=size, format="csv"),
                                    text="csv")
        if response is not None and response.headers.get("X-Next-Cursor"):
            result.extras["next_cursor"] = response.headers["X-Next-Cursor"]
            result.truncated = True
        return result
    return _paged(target, "/tor/relays", "relays", max_pages, role=role, size=size)


# ---- hunting ----------------------------------------------------------------------------------------------------

@cached_fetch(group="vpndb")
def service_networks(tag, min_confidence=1, current=None, size=200, max_pages=DEFAULT_MAX_PAGES):
    """
    GET /service/{tag}/networks: every network of a provider (reverse lookup for retro-hunting). `current` True for
    the networks it is in now, False for the ones it left, None for both.
    """
    return _paged(tag, f"/service/{_segment(tag)}/networks", "networks", max_pages, min_confidence=min_confidence,
                  current=current, size=size)


@cached_fetch(group="vpndb")
def bulk_lookup(ips, as_of=None):
    """
    POST /bulk: up to 10,000 addresses per request (more are sent in several), each summarised, plus counts by
    provider and ASN. `ips` is a tuple (hashable, for the cache); `as_of` a date for the state on that day.
    """
    ips = list(dict.fromkeys(str(ip).strip() for ip in ips if str(ip).strip()))
    target = f"{len(ips)} IP(s)"
    merged = None
    for start in range(0, len(ips), BULK_LIMIT):
        chunk = ips[start:start + BULK_LIMIT]
        result, _ = _request(target, "/bulk", body=_params(ips=chunk, as_of=as_of))
        count_query(len(chunk) - 1)   # VPNDB counts each address of a bulk request as one query
        if not result.ok:
            if merged is None:
                return result
            merged.error = f"{result.error} (after {start:,} of {len(ips):,} addresses)"
            break
        if merged is None:
            merged = result
            continue
        data, more = merged.data, result.data
        data["results"] = data.get("results", []) + more.get("results", [])
        for key in ("total", "anonymous"):
            data[key] = data.get(key, 0) + more.get(key, 0)
        for key in ("byProvider", "byAsn", "unknown"):   # {name: count}, lists or counts, as the API sends them
            if isinstance(data.get(key), dict):
                counts = dict(data[key])
                for name, count in (more.get(key) or {}).items():
                    counts[name] = counts.get(name, 0) + count
                data[key] = counts
            elif isinstance(data.get(key), list):
                data[key] = data[key] + list(more.get(key) or [])
            elif isinstance(data.get(key), (int, float)):
                data[key] = data[key] + (more.get(key) or 0)
        merged.extras.update(result.extras)
    if merged is None:
        return FetchResult(SOURCE, target, data={"total": 0, "results": []})
    merged.record_count = len(merged.data.get("results", []))
    return merged


# ---- search -----------------------------------------------------------------------------------------------------

@cached_fetch(group="vpndb")
def search(q):
    """GET /search: resolves free text (an IP, prefix, `AS9009`, a service tag, a country) to what it names."""
    return _get(q, "/search", q=q)


@cached_fetch(group="vpndb")
def suggest(q, limit=10):
    """GET /suggest: completions for a partial provider or organisation name (and any literal IP, prefix or ASN)."""
    return _get(q, "/suggest", q=q, limit=limit)


@cached_fetch(group="vpndb")
def lookup_org(org_id):
    """GET /org/{id}: one ASN organisation (CAIDA id from suggest, or an exact name) and every network it holds."""
    return _get(org_id, f"/org/{_segment(org_id)}")


@cached_fetch(group="vpndb")
def org_networks(org_id, provider=None, q=None, shared=None, sort="tenancy", size=50, max_pages=DEFAULT_MAX_PAGES):
    """GET /org/{id}/networks: every prefix of the organisation's networks holding a known exit address."""
    return _paged(org_id, f"/org/{_segment(org_id)}/networks", "networks", max_pages, provider=provider, q=q,
                  shared=shared, sort=sort, size=size)


@cached_fetch(group="vpndb")
def list_countries():
    """GET /countries: every country with a known exit address, with its VPN and residential proxy figures."""
    return _get("countries", "/countries")


@cached_fetch(group="vpndb")
def lookup_country(cc):
    """GET /country/{cc}: one country's VPN and residential proxy exits, by network and provider."""
    return _get(cc.upper(), f"/country/{_segment(cc.upper())}")


# ---- meta and admin -----------------------------------------------------------------------------------------------

@cached_fetch(ttl=3600)
def meta():
    """GET /meta (no key needed): dataset version, coverage and known gaps."""
    return _get("meta", "/meta", auth=False)


def openapi_spec():
    """GET /openapi.yaml (no key needed): the API's specification as YAML text."""
    return _request("openapi.yaml", "/openapi.yaml", auth=False, text=True)[0]


def sources():
    """GET /sources: provenance and health of every source; administrators only (403 for anyone else)."""
    return _get("sources", "/sources")


OPERATIONS = {   # operationId in the specification -> function
    "getIp": lookup_ip, "getIpHistory": ip_history, "getPrefix": lookup_prefix,
    "getPrefixAddresses": prefix_addresses, "getPrefixTimeline": prefix_timeline, "getAsn": lookup_asn,
    "getAsnNetworks": asn_networks, "getService": lookup_service, "getServiceNetworks": service_networks,
    "search": search, "bulkLookup": bulk_lookup, "listServices": list_services, "getTor": tor_overview,
    "listTorRelays": tor_relays, "getMeta": meta, "getOpenApi": openapi_spec, "getSuggest": suggest,
    "getOrg": lookup_org, "getCountries": list_countries, "getCountry": lookup_country,
    "getOrgNetworks": org_networks, "getSources": sources,
}

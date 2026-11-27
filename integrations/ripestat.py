"""
RIPEstat Data API (RIPE NCC, public, no key): BGP routing seen by the RIPE RIS route collectors and registry data
from all five RIRs. Each data call is a GET of `https://stat.ripe.net/data/{call}/data.json?resource=…` answered with
JSON (`status`, `messages`, `data`). The calls used:

- `routing-history`         every prefix covering an address and each origin AS that announced it, with the periods
                            it was seen (years back) and how many RIS full-feed peers saw it
- `routing-status`          a prefix now: first seen, visibility, origins with their IRR route objects, the
                            more-specific prefixes announced inside it
- `rpki-validation`         RPKI validity of an origin AS for a prefix, and the ROAs deciding it
- `looking-glass`           the AS paths RIS peers see towards a prefix now
- `as-overview`             an AS's registered name
- `asn-neighbours`          an AS's neighbour counts (left: upstreams and peers; right: downstreams)
- `rir-stats-country`       the country of a prefix or AS in the RIR statistics
- `whois`                   the registry object of an address, prefix or AS: its RIR, net name, organisation, type,
                            registration date
- `abuse-contact-finder`    where to report abuse of an address

RIPE NCC asks callers to name their application (`sourceapp`) and to keep their request rate reasonable: results are
cached (group "ripestat"), and a run stops calling after several unanswered requests in a row (Breaker). The
addresses and networks looked up are sent to RIPE NCC.
"""
import json
import threading
import urllib.parse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from integrations.cache import cached_fetch
from integrations.http import USER_AGENT, FetchResult, count_response, describe_exception, describe_http_status

SOURCE = "RIPEstat"
BASE_URL = "https://stat.ripe.net/data"
SOURCEAPP = "dt-analytics"
HISTORY_START = "1990-01-01"   # `rir` from this day: the first time the resource appeared in the RIR statistics
CALLS = ("routing-history", "routing-status", "rpki-validation", "looking-glass", "as-overview", "asn-neighbours",
         "rir", "rir-stats-country", "whois", "abuse-contact-finder")
CONNECT_TIMEOUT, READ_TIMEOUT = 10, 90
STOP_AFTER_FAILURES = 3
UNREACHABLE = "unreachable"
STOPPED = ("RIPEstat stopped: it did not answer {count} requests in a row (no internet connection, or the service is "
           "down); the remaining lookups were skipped")
_thread_local = threading.local()


class Breaker:
    """Stops a run's RIPEstat calls once STOP_AFTER_FAILURES in a row got no answer. Thread-safe."""

    def __init__(self, limit=STOP_AFTER_FAILURES):
        self.limit, self.failures, self.tripped = limit, 0, False
        self._lock = threading.Lock()

    def call(self, lookup, target, *args):
        if self.tripped:
            return FetchResult(SOURCE, target, error=STOPPED.format(count=self.limit))
        result = lookup(*args)
        with self._lock:
            if (getattr(result, "extras", None) or {}).get(UNREACHABLE):
                self.failures += 1
                self.tripped = self.tripped or self.failures >= self.limit
            else:
                self.failures = 0
        return result


def _session():
    session = getattr(_thread_local, "session", None)
    if session is None:
        retry = Retry(total=2, connect=0, backoff_factor=1.0, status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=frozenset({"GET"}), raise_on_status=False)
        session = requests.Session()
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers["User-Agent"] = USER_AGENT
        session.hooks["response"].append(count_response)
        _thread_local.session = session
    return session


def _params(resource, **extra):
    """The call's query parameters in a fixed order (resource first, sourceapp last)."""
    params = {"resource": str(resource).strip()}
    params.update({key: value for key, value in extra.items() if value not in (None, "")})
    params["sourceapp"] = SOURCEAPP
    return params


def request_url(call, resource, **extra):
    """The URL a data call sends (the resource stays readable: `/` and `:` are not escaped)."""
    query = urllib.parse.urlencode(_params(resource, **extra), safe="/:")
    return f"{BASE_URL}/{call}/data.json?{query}"


def target_of(call, resource, **extra):
    """How a call is logged in Data sources: "routing-history 1.2.3.4", "rpki-validation AS3333 193.0.0.0/21"."""
    return " ".join([call, str(resource).strip(), *(str(v) for k, v in extra.items() if k == "prefix" and v)])


def parse_target(target):
    """(call, resource, extra params) back from target_of's text, or None."""
    parts = str(target or "").split()
    if len(parts) < 2 or parts[0] not in CALLS:
        return None
    extra = {"prefix": parts[2]} if parts[0] == "rpki-validation" and len(parts) > 2 else {}
    if parts[0] == "rir":
        extra["starttime"] = HISTORY_START
    return parts[0], parts[1], extra


def curl_command(call, resource, **extra):
    """The same request as a curl command (no credential: RIPEstat needs none)."""
    return f"curl -s '{request_url(call, resource, **extra)}' | jq .data"


def _trim(call, data):
    """The answer as kept in the run: looking-glass without its community descriptions (most of its size)."""
    if call != "looking-glass" or not isinstance(data, dict):
        return data
    rrcs = []
    for rrc in data.get("rrcs") or []:
        peers = [{k: v for k, v in peer.items() if k not in ("community_info", "community", "largeCommunity",
                                                             "extendedCommunity")} for peer in rrc.get("peers") or []]
        rrcs.append({**{k: v for k, v in rrc.items() if k != "peers"}, "peers": peers})
    return {**data, "rrcs": rrcs}


def _query(call, resource, **extra):
    """One data call as a FetchResult: data = the answer's `data` object; record_count = 1 with data."""
    target = target_of(call, resource, **extra)
    if call not in CALLS:
        return FetchResult(SOURCE, target, error=f"Unknown RIPEstat data call {call!r}")
    url = request_url(call, resource, **extra)
    try:
        response = _session().get(url, headers={"Accept": "application/json"}, timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    except (requests.ConnectionError, requests.Timeout) as exc:
        return FetchResult(SOURCE, target, error=describe_exception(exc), extras={UNREACHABLE: True, "url": url})
    except Exception as exc:
        return FetchResult(SOURCE, target, error=describe_exception(exc), extras={"url": url})
    try:
        body = response.json()
    except ValueError:
        body = {}
    messages = "; ".join(str(m[1]) for m in body.get("messages") or [] if isinstance(m, list) and len(m) > 1
                         and m[0] == "error")
    if response.status_code != 200 or body.get("status") == "error":
        return FetchResult(SOURCE, target, error=describe_http_status(response.status_code)
                           + (f": {messages}" if messages else ""), extras={"url": url})
    data = _trim(call, body.get("data") or {})
    result = FetchResult(SOURCE, target, data=data, record_count=1 if data else 0,
                         extras={"url": url, "raw": json.dumps(data, separators=(",", ":"))})
    if not data:
        result.note = "no data"
    return result


@cached_fetch(group="ripestat")
def routing_history(ip):
    return _query("routing-history", ip)


@cached_fetch(group="ripestat")
def routing_status(prefix):
    return _query("routing-status", prefix)


@cached_fetch(group="ripestat")
def rpki_validation(asn, prefix):
    number = str(asn).strip().upper().removeprefix("AS")
    return _query("rpki-validation", f"AS{number}", prefix=prefix)


@cached_fetch(group="ripestat")
def looking_glass(prefix):
    return _query("looking-glass", prefix)


@cached_fetch(group="ripestat")
def as_overview(asn):
    return _query("as-overview", f"AS{str(asn).strip().upper().removeprefix('AS')}")


@cached_fetch(group="ripestat")
def asn_neighbours(asn):
    return _query("asn-neighbours", f"AS{str(asn).strip().upper().removeprefix('AS')}")


@cached_fetch(group="ripestat")
def rir(resource):
    return _query("rir", resource, starttime=HISTORY_START)


@cached_fetch(group="ripestat")
def rir_country(resource):
    return _query("rir-stats-country", resource)


@cached_fetch(group="ripestat")
def whois(resource):
    """An address, prefix or AS (`AS3333`)."""
    return _query("whois", resource)


@cached_fetch(group="ripestat")
def abuse_contact(ip):
    return _query("abuse-contact-finder", ip)

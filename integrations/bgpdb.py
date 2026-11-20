"""
BGPDB (an internal DomainTools service): the BGP routing table history of the last ~30 days, as the bgpdbq tool
queries it. Each command is a GET of `{host}/v1/{command}/{argument}` answered with NDJSON, one object per line:

- `ip/{address}`      every announced prefix covering the address and each network (origin AS) that announced it:
                      first / last seen, update count, route collectors, IRR / RPKI validity, RIR allocation, score
- `prefix/{cidr}`     the same for a prefix and every more-specific prefix inside it
- `asn/{asn}`         an AS: RIR registration, name, visibility, upstream / downstream neighbour counts
- `route/{ip|cidr}`   every AS path seen towards the prefix, with dates, collectors and peers

The stream ends with `{"info": "end of results"}` or `{"info": "no results"}`; `{"warn": ...}` says the result limit
(`?limit=N`) cut it short and `{"error": ...}` that the argument was refused. The host, an optional API key
(X-API-Key), HTTP auth and certificate checking come from integrations.credentials (Settings → API credentials, or
the bgpdbq tool's ~/.bgpdbq.conf). Without a host nothing is queried.
"""
import json
import threading
import urllib.parse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from integrations.cache import cached_fetch
from integrations.credentials import BGPDB_MISSING, bgpdb_base_url, bgpdb_options, load_bgpdb_host
from integrations.http import USER_AGENT, FetchResult, count_response, describe_exception, describe_http_status

SOURCE = "BGPDB"
COMMANDS = ("ip", "prefix", "asn", "route")
CONNECT_TIMEOUT, READ_TIMEOUT = 10, 60
_thread_local = threading.local()


def _session():
    """A per-thread session retrying transient 5xx errors (BGPDB only reads)."""
    session = getattr(_thread_local, "session", None)
    if session is None:
        retry = Retry(total=2, backoff_factor=1.0, status_forcelist=(500, 502, 503, 504),
                      allowed_methods=frozenset({"GET"}), raise_on_status=False)
        session = requests.Session()
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.mount("http://", HTTPAdapter(max_retries=retry))
        session.headers["User-Agent"] = f"{USER_AGENT} (bgpdbq-compatible)"
        session.hooks["response"].append(count_response)
        _thread_local.session = session
    return session


def parse_ndjson(text):
    """
    (records, info) from a BGPDB answer: the data objects, and {"info", "warn", "error"} from its control lines (the
    last of each kind). Lines that are not JSON objects are skipped.
    """
    records, info = [], {}
    for line in str(text or "").splitlines():
        line = line.strip()
        if not line or line in ("[", "]", "[]"):
            continue
        try:
            item = json.loads(line.rstrip(","))
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        control = {key: item[key] for key in ("info", "warn", "error") if key in item}
        if control and len(item) == len(control):
            info.update(control)
        else:
            records.append(item)
    return records, info


def request_url(command, argument, limit=None):
    """The URL a lookup sends (None without a host): the argument stays readable (a CIDR's slash is a path part)."""
    base = bgpdb_base_url()
    if not base:
        return None
    url = f"{base}/{command}/{urllib.parse.quote(str(argument).strip(), safe='/:')}"
    return url + (f"?limit={int(limit)}" if limit else "")


def _query(command, argument, limit=None):
    """One BGPDB lookup as a FetchResult: data = the list of records; truncated when the limit cut it short."""
    target = f"{command} {argument}"
    host = load_bgpdb_host()
    if not host:
        return FetchResult(SOURCE, target, error=BGPDB_MISSING)
    if command not in COMMANDS:
        return FetchResult(SOURCE, target, error=f"Unknown BGPDB command {command!r}")
    options = bgpdb_options()
    headers = {"Accept": "application/x-ndjson, application/json"}
    if options["api_key"]:
        headers["X-API-Key"] = options["api_key"]
    auth = (options["user"], options["password"]) if options["user"] else None
    url = request_url(command, argument, limit)
    try:
        response = _session().get(url, headers=headers, auth=auth, verify=not options["insecure"],
                                  timeout=(CONNECT_TIMEOUT, READ_TIMEOUT))
    except Exception as exc:
        return FetchResult(SOURCE, target, error=describe_exception(exc))
    if response.status_code != 200:
        detail = response.text.strip()[:200]
        return FetchResult(SOURCE, target, error=describe_http_status(response.status_code)
                           + (f": {detail}" if detail else ""))
    records, info = parse_ndjson(response.text)
    result = FetchResult(SOURCE, target, data=records, record_count=len(records),
                         extras={"url": url, "info": info, "raw": response.text})
    if info.get("error"):
        result.error = f"BGPDB refused {argument!r}: {info['error']}"
    elif info.get("warn"):
        result.truncated = True
        result.note = f"{info['warn']} ({len(records)} kept)"
    elif not records:
        result.note = info.get("info") or "no results"
    return result


@cached_fetch(group="bgpdb")
def lookup_ip(ip):
    """`ip/{ip}`: each prefix covering the address and each origin AS that announced it (IPv4 or IPv6)."""
    return _query("ip", ip)


@cached_fetch(group="bgpdb")
def lookup_prefix(cidr, limit=None):
    """`prefix/{cidr}`: the prefix and every more-specific prefix inside it, with their origins."""
    return _query("prefix", cidr, limit)


@cached_fetch(group="bgpdb")
def lookup_asn(asn):
    """`asn/{asn}`: registration, name, visibility and neighbour counts of one AS (`AS13335` or `13335`)."""
    number = str(asn).strip().upper().removeprefix("AS")
    return _query("asn", f"AS{number}")


@cached_fetch(group="bgpdb")
def lookup_route(target, limit=None):
    """`route/{ip|cidr}`: every AS path seen towards the prefix."""
    return _query("route", target, limit)


def curl_command(command, argument, limit=None):
    """The same lookup as a curl command (no credential values: the key and HTTP auth come from the environment)."""
    url = request_url(command, argument, limit) or f"https://$BGPDB_HOST/v1/{command}/{argument}"
    options = bgpdb_options()
    parts = [f"curl -s '{url}'"]
    if options["api_key"]:
        parts.append('-H "X-API-Key: $BGPDB_API_KEY"')
    if options["user"]:
        parts.append('-u "$BGPDB_USER:$BGPDB_PASS"')
    if options["insecure"]:
        parts.append("-k")
    return " ".join(parts) + " | jq ."

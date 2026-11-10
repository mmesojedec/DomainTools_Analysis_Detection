"""
The lookups a run made, rebuilt as queries an analyst can paste into the DomainTools and DNSDB tools: CertsQL for
certificate search, names and record types for DNSDB Scout, domain lists for Iris Investigate, the IrisQL
search a run's targets were picked from, plus the
matching `domaintools` CLI command (installed with the DomainTools Python SDK) or curl command. Built from the run's
Data Source Status rows with the same query builders the lookups use, so saved and offline runs get the same list.
"""
import json
import re
import shlex
from urllib.parse import quote, unquote, urlencode

import pandas as pd

from config import (
    CAA_SUPPLEMENT_FETCH_LIMIT,
    CERT_CTL_LIMIT,
    CERT_EVENTS_LOOKBACK_DAYS,
    CERTSQL_PAGE_SIZE,
    CNAME_CHASE_RECORD_LIMIT,
    CNAME_RDATA_RECORD_LIMIT,
    CNAME_SUPPLEMENT_FETCH_LIMIT,
    DNSDB_DEFAULT_LIMIT,
    IRISQL_PAGE_SIZE,
    PIVOT_IP_RECORD_LIMIT,
    TXT_SUPPLEMENT_FETCH_LIMIT,
)
from core.cert_inputs import hostname_search_query
from core.certsql import commands as certsql_commands
from core.helpers import is_ip_address
from core.irisql import commands as irisql_commands
from integrations.cache import FROM_CACHE
from integrations.certificates import CERT_API_BASE_URL, build_search_queries, events_start_time
from integrations.collector import ct_hashes
from integrations.credentials import vpndb_base_url
from integrations.dnsdb import CHASE_SOURCE, MAX_BATCH_SIZE, RDATA_SOURCE, _lookup_urls, client_params, rdata_url
from integrations.enrichment import iris_batches

LOOKUP_SUFFIXES = (" Lookup", " Supplement")   # record-type lookups (" Supplement": saved before the rename)

QUERY_COLUMNS = ["Source", "Target", "Tool", "Search", "Query", "Command", "Status", "Records", "Cached", "Cached At",
                 "Pages"]
TOOLS = ["IrisQL", "CertsQL", "Iris Investigate", "DomainTools API", "DomainTools Certificates", "DNSDB Scout", "VPNDB"]
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
COUNT = re.compile(r"^(\d+) certificates$")
COUNT_IPS = re.compile(r"^\d+ IP\(s\)$")


def _cert_curl(endpoint, payload):
    return (f"curl -s -X POST {CERT_API_BASE_URL}/{endpoint} -H \"x-api-key: $DT_CERT_API_KEY\" "
            f"-H 'Content-Type: application/json' -d {shlex.quote(json.dumps(payload))}")


def _dt_cli(command, option, value):
    """`domaintools` CLI command; without $DT_API_USERNAME / $DT_API_KEY set, the CLI reads ~/.dtapi."""
    return f'domaintools {command} {option} {shlex.quote(value)} -u "$DT_API_USERNAME" -k "$DT_API_KEY"'


def _dnsdb(target, rrtype="ANY", include_wildcard=True, limit=DNSDB_DEFAULT_LIMIT, capped=False):
    """
    (search, names one per line, curl commands) for a DNSDB lookup, one request per URL it made: the exact-name
    request after a wildcard one only runs when the wildcard lookup was `capped`.
    """
    urls = _lookup_urls(target, rrtype, include_wildcard)
    urls = urls if capped else urls[:1]
    query = urlencode({"limit": min(MAX_BATCH_SIZE, limit), **client_params(rrtype)})
    curl = "\n".join(f'curl -s -H "X-API-Key: $DNSDB_API_KEY" -H \'Accept: application/x-ndjson\' '
                     f'{shlex.quote(f"{url}?{query}")}' for url in urls)
    if is_ip_address(target):
        return "Rdata IP", target, curl
    names = [unquote(url.split("/lookup/", 1)[1].split("/")[2]) for url in urls]
    return f"RRset, type {rrtype}", "\n".join(names), curl


def _events(kind, payload, start):
    body = {"start_time": start, **payload}
    return f"Certificate Events: {kind}", json.dumps(body, indent=2), _cert_curl(f"events/{kind}", body)


def _vpndb_request(status):
    """The request a VPNDB lookup made: from its status row, or, for runs saved before requests were kept, read back
    from the target (an IP is a verdict, a range a prefix verdict, AS… a network; a bulk request's list is unknown)."""
    request, target = status.get("Request"), str(status["Target"])
    if isinstance(request, dict) and request.get("endpoint"):
        return request
    if COUNT_IPS.match(target):
        return {"method": "POST", "endpoint": "/bulk", "params": {}, "body": None}
    if target.upper().startswith("AS") and target[2:].isdigit():
        return {"method": "GET", "endpoint": "/asn/{asn}", "params": {}}
    if "/" in target:
        return {"method": "GET", "endpoint": "/prefix/{cidr}", "params": {}}
    if is_ip_address(target):
        return {"method": "GET", "endpoint": "/ip/{ip}", "params": {}}
    return None


def _vpndb(status, base_url):
    """(search, query, curl) for a VPNDB lookup: the endpoint, the path (or a bulk request's IPs, one per line), and the
    curl command with the key from $VPNDB_API_KEY."""
    request = _vpndb_request(status)
    if request is None:
        return None
    target = str(status["Target"])
    value = target.upper().removeprefix("AS") if "{asn}" in request["endpoint"] else target

    def fill(text):
        return request["endpoint"].replace("{ip}", text).replace("{cidr}", text).replace("{asn}", text)

    path = fill(value)                       # readable, for the Query column
    params = {k: v for k, v in (request.get("params") or {}).items() if v not in (None, "")}
    url = f"{base_url}{fill(quote(value, safe=''))}" + (f"?{urlencode(params)}" if params else "")   # as sent
    auth = '-H "Authorization: Bearer $VPNDB_API_KEY"'
    search = f"{request['method']} {request['endpoint']}"
    if request["method"] == "POST":
        ips = (request.get("body") or {}).get("ips")
        query = "\n".join(ips) if ips else f"{target} (the list was not recorded in this run)"
        body = json.dumps({"ips": ips or ["..."]})
        return search, query, (f"curl -s -X POST {auth} -H 'Content-Type: application/json' {shlex.quote(url)} "
                               f"-d {shlex.quote(body)}")
    return search, path + (f"?{urlencode(params)}" if params else ""), f"curl -s {auth} {shlex.quote(url)}"


def _row(status, tool, search, query, command, target=None, pages=None):
    return {"Pages": pages, "Source": status["Source"], "Target": target or status["Target"], "Tool": tool, "Search": search,
            "Query": query, "Command": command, "Status": status["Status"], "Records": status.get("Records", 0),
            "Cached": FROM_CACHE in str(status.get("Detail") or ""),
            "Cached At": pd.to_datetime(status.get("Cached At"), errors="coerce")}


def build_lookup_queries(collected, created=None):
    """One row (QUERY_COLUMNS) per lookup the run made; summary-only status rows are left out."""
    statuses = list(getattr(collected, "statuses", None) or [])
    start = events_start_time(CERT_EVENTS_LOOKBACK_DAYS, created)
    seeds = getattr(collected, "seeds", None)
    seed_queries = dict(zip(seeds["Seed"], seeds["Query"])) if seeds is not None and not seeds.empty else {}
    focus = getattr(collected, "host_focus", None) or {}
    batches = iter(iris_batches(getattr(collected, "domain_targets", None) or []))
    hashes = ct_hashes(getattr(collected, "ssl", None))
    listed = {(s["Source"], s["Target"]) for s in statuses}
    dnsdb_limit = getattr(collected, "dnsdb_limit", 0) or DNSDB_DEFAULT_LIMIT   # older saved runs did not record it
    targets = set(getattr(collected, "targets", None) or [])
    vpndb_url = vpndb_base_url()

    rows = []
    for status in statuses:
        source, target = status["Source"], str(status["Target"])
        if source == "Domain History":
            command = _dt_cli("domain_history", "--query", target) + " --page-size 100"
            rows.append(_row(status, "DomainTools API", source, target, command))
        elif source == "Risk Evidence":
            rows.append(_row(status, "DomainTools API", source, target, _dt_cli("risk_evidence", "--domain", target)))
        elif source == "Iris Investigate":
            batch = next(batches, None)
            if batch:
                rows.append(_row(status, "Iris Investigate", "Domain list", "\n".join(batch),
                                 _dt_cli("iris_investigate", "--domains", ",".join(batch)), target=", ".join(batch)))
        elif source.startswith("Certificate Search"):
            if target in seed_queries:
                query = seed_queries[target]
            elif "Gap-Fill" in source:
                query = hostname_search_query(focus.get(target, [target]))
            else:
                query = dict(build_search_queries([target])).get(target)
            if query:
                rows.append(_row(status, "DomainTools Certificates", "CertsQL search", query.strip(),
                                 _cert_curl("search", {"query_string": query, "limit": 500})))
        elif source.startswith("Cert Events (Hostname"):
            payload = {"hostname": target, "include_subdomains": "Gap-Fill" not in source}
            rows.append(_row(status, "DomainTools Certificates", *_events("hostname", payload, start)))
        elif source == "Cert Events (IP)":
            rows.append(_row(status, "DomainTools Certificates", *_events("ip", {"ip": target}, start)))
        elif source in ("Cert Events (SHA256)", "CT Log Events"):
            if SHA256.match(target):
                todo = [(target, status)]
            elif COUNT.match(target):   # one summary row stands for a lookup per certificate
                todo = [(h, status) for h in hashes[:int(COUNT.match(target).group(1))] if (source, h) not in listed]
            else:
                todo = []
            for sha, row_status in todo:
                if source == "CT Log Events":
                    payload = {"sha256": sha, "limit": CERT_CTL_LIMIT}
                    built = ("Certificate Events: ctl", json.dumps(payload, indent=2), _cert_curl("events/ctl", payload))
                else:
                    built = _events("sha256", {"sha256": sha}, start)
                rows.append(_row(row_status, "DomainTools Certificates", *built, target=sha))
        elif source in ("DNSDB Scout", "DNSDB IP Pivot", "DNSDB Hostname Gap-Fill") or source.startswith(CHASE_SOURCE) or \
                (source.startswith("DNSDB ") and source.endswith(LOOKUP_SUFFIXES)):
            if not target or target == "-" or " " in target:
                continue
            chase = source.startswith(CHASE_SOURCE)
            rrtype = source.split()[1] if source.endswith(LOOKUP_SUFFIXES) else \
                source.rpartition("(")[2].rstrip(")") if chase else "ANY"
            wildcard = rrtype != "CAA" and source != "DNSDB Hostname Gap-Fill" and not chase
            if chase:
                limit = CNAME_CHASE_RECORD_LIMIT
            elif rrtype != "ANY":
                limit = {"TXT": TXT_SUPPLEMENT_FETCH_LIMIT, "CAA": CAA_SUPPLEMENT_FETCH_LIMIT,
                         "CNAME": CNAME_SUPPLEMENT_FETCH_LIMIT}.get(rrtype, dnsdb_limit)
            elif is_ip_address(target) and target not in targets:   # IP pivots are logged as DNSDB Scout lookups
                limit = PIVOT_IP_RECORD_LIMIT
            else:
                limit = dnsdb_limit
            capped = status["Status"] == "Partial"
            rows.append(_row(status, "DNSDB Scout", *_dnsdb(target, rrtype, wildcard, limit, capped)))
        elif source == RDATA_SOURCE:
            query = urlencode({"limit": min(MAX_BATCH_SIZE, CNAME_RDATA_RECORD_LIMIT), **client_params("CNAME")})
            curl = (f'curl -s -H "X-API-Key: $DNSDB_API_KEY" -H \'Accept: application/x-ndjson\' '
                    f'{shlex.quote(f"{rdata_url(target)}?{query}")}')
            rows.append(_row(status, "DNSDB Scout", "Rdata name, type CNAME", target, curl))
        elif source == "IrisQL":
            request = status.get("Request") or {}
            if request.get("query"):
                page_size = min(int(request.get("max_results") or IRISQL_PAGE_SIZE), IRISQL_PAGE_SIZE)
                built = irisql_commands(request["query"], page_size, request.get("sort_by") or "")
                rows.append(_row(status, "IrisQL", "IrisQL query", request["query"],
                                 built["DomainTools CLI"] + "\n" + built["curl"], pages=request.get("pages")))
        elif source == "CertsQL":
            request = status.get("Request") or {}
            if request.get("query"):
                limit = min(int(request.get("max_results") or CERTSQL_PAGE_SIZE), CERTSQL_PAGE_SIZE)
                rows.append(_row(status, "CertsQL", "CertsQL query", request["query"],
                                 certsql_commands(request["query"], limit, request.get("sort"))["curl"],
                                 pages=request.get("pages")))
        elif source == "VPNDB":
            built = _vpndb(status, vpndb_url) if not status.get("Detail", "").startswith("No VPNDB key") else None
            if built:
                rows.append(_row(status, "VPNDB", *built))
    return pd.DataFrame(rows, columns=QUERY_COLUMNS)


def request_counts(queries):
    """
    Requests each lookup row stands for: one, except a DNSDB name lookup that hit its limit, which also ran the
    exact-name request and so holds two names and two curl commands; none for a lookup reused from the cache.
    """
    counts = queries["Command"].map(lambda command: str(command).count("curl ")).clip(lower=1)
    if "Pages" in queries:   # an IrisQL / CertsQL search: one request per page of results
        pages = pd.to_numeric(queries["Pages"], errors="coerce")
        counts = counts.where(pages.isna(), pages).astype(int)
    return counts.where(~queries["Cached"].fillna(False).astype(bool), 0) if "Cached" in queries else counts


def one_line(query):
    """
    A query on one line for tables: JSON bodies as `key=value` pairs (start_time last, it is the same for every row), CertsQL without its version line, other
    multi-line queries (name lists, domain lists) joined with ` · `.
    """
    text = str(query or "")
    try:
        body = json.loads(text) if text.lstrip().startswith("{") else None
    except ValueError:
        body = None
    if isinstance(body, dict):
        items = sorted(body.items(), key=lambda item: item[0] == "start_time")
        return ", ".join(f"{key}={value if isinstance(value, str) else json.dumps(value)}" for key, value in items)
    return " · ".join(line.strip() for line in text.splitlines() if line.strip() and not line.startswith("# CertsQL"))


def tool_bundle(queries, tool):
    """
    All queries of one tool as one copyable text block: a blank line between queries, and a `# <search>` heading per
    search type when the tool's queries use more than one (e.g. DNSDB type ANY and CAA).
    """
    shown = queries[queries["Tool"] == tool]
    if tool == "Iris Investigate":   # one domain list for every batch
        return "\n".join(dict.fromkeys(n for q in shown["Query"] for n in q.split("\n")))
    groups = list(dict.fromkeys(shown["Search"]))
    blocks = []
    for search in groups:
        body = "\n\n".join(dict.fromkeys(shown.loc[shown["Search"] == search, "Query"]))
        blocks.append(f"# {search}\n{body}" if len(groups) > 1 else body)
    return "\n\n".join(blocks)

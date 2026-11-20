"""
BGPDB collection stage: the announced prefixes and origin networks of the run's hosting IPs, their AS paths, the
origin and upstream networks and the prefixes around them (core.bgp reads them). Stops early when the host does not
answer (bgpdb.Breaker).
"""
import json

import pandas as pd

from config import (
    BGPDB_ASN_MAX,
    BGPDB_MAX_IPS,
    BGPDB_NEIGHBOUR_LIMIT,
    BGPDB_NEIGHBOUR_MAX,
    BGPDB_ROUTE_LIMIT,
    BGPDB_ROUTE_MAX,
)
from core import bgp
from integrations import bgpdb, progress
from integrations.fetch_runner import _parallel, _safe_call
from integrations.http import FetchResult


def _bgp_logged(log, raw, result, command, argument, limit=None):
    """
    Logs a BGPDB lookup (Data sources) and keeps its answer as received (the BGP page's Responses). A lookup skipped
    after the host stopped answering is not logged one by one: collect_bgp adds one row for all of them.
    """
    if str(result.error or "").startswith("BGPDB stopped"):
        return result
    log.record(result)
    raw.append({"Command": command, "Argument": argument, "Status": result.status_row()["Status"],
                "Records": result.record_count, "Detail": result.error or result.note or "",
                "URL": (result.extras or {}).get("url") or bgpdb.request_url(command, argument, limit) or "",
                "Response": (result.extras or {}).get("raw") or json.dumps(result.data, default=str)})
    return result


def collect_bgp(domains, ip_targets, pdns, enrichment, log, max_ips=BGPDB_MAX_IPS, context=True):
    """
    BGPDB: the announced prefixes and origin networks of the run's hosting IPs (one `ip` lookup each, core.bgp.select_ips),
    then the AS paths of the prefixes (`route`), the origin and upstream networks (`asn`) and, with `context`, the
    prefixes announced in the range around them (`prefix`). Skipped without a BGPDB host. Returns
    (origins, asns, routes, neighbours, raw) frames.
    """
    empty = (pd.DataFrame(columns=bgp.ORIGIN_COLUMNS), pd.DataFrame(columns=bgp.ASN_COLUMNS),
             pd.DataFrame(columns=bgp.ROUTE_COLUMNS), pd.DataFrame(columns=bgp.NEIGHBOUR_COLUMNS),
             pd.DataFrame(columns=bgp.RAW_COLUMNS))
    if not bgpdb.load_bgpdb_host():
        progress.skip("bgpdb", "No BGPDB host (Settings → API credentials)")
        return empty
    chosen = bgp.select_ips(domains, pdns, enrichment, ip_targets, max_ips)
    if not chosen:
        progress.skip("bgpdb", "No public hosting addresses to look up")
        return empty
    raw = []
    ips = sorted(chosen)
    breaker = bgpdb.Breaker()

    def guarded(lookup, command):
        return lambda argument, *rest: breaker.call(
            lambda *args: _safe_call(lookup, bgpdb.SOURCE, f"{command} {argument}", *args), f"{command} {argument}",
            argument, *rest)

    progress.start("bgpdb", len(ips), note=f"{len(ips)} IP(s): announced prefixes and origin networks")
    results = _parallel(ips, guarded(bgpdb.lookup_ip, "ip"), key="bgpdb")
    rows = []
    for ip, result in zip(ips, results):
        _bgp_logged(log, raw, result, "ip", ip)
        rows += bgp.origin_rows(ip, chosen[ip], result.data if result.ok else [])
    origins = pd.DataFrame(rows, columns=bgp.ORIGIN_COLUMNS)
    if breaker.tripped and origins.empty:
        log.record(FetchResult(bgpdb.SOURCE, f"{len(ips) - len(raw)} lookup(s) skipped",
                               error=bgpdb.STOPPED.format(count=breaker.limit)))
        progress.skip("bgpdb", "BGPDB host not reachable (DomainTools network or VPN needed)")
        return origins, *empty[1:4], pd.DataFrame(raw, columns=bgp.RAW_COLUMNS)
    if origins.empty:
        progress.finish("bgpdb", "no announced prefix found")
        return origins, *empty[1:4], pd.DataFrame(raw, columns=bgp.RAW_COLUMNS)
    usual = bgp.main_origins(origins)
    prefixes = list(dict.fromkeys(usual.sort_values("Updates", ascending=False)["Prefix"]))[:BGPDB_ROUTE_MAX]
    progress.start("bgpdb", len(prefixes), note="AS paths of the announced prefixes")
    routes = []
    for prefix, result in zip(prefixes, _parallel(prefixes, lambda p: guarded(
            bgpdb.lookup_route, "route")(p, BGPDB_ROUTE_LIMIT), key="bgpdb")):
        _bgp_logged(log, raw, result, "route", prefix, BGPDB_ROUTE_LIMIT)
        routes += bgp.route_rows(prefix, result.data if result.ok else [])
    routes = pd.DataFrame(routes, columns=bgp.ROUTE_COLUMNS)
    domains_of = {}
    for _, row in origins.iterrows():
        domains_of.setdefault(row["Origin"], set()).update(d.strip() for d in str(row["Domains"]).split(",") if d.strip())
    wanted = {asn: "origin" for asn in usual["Origin"]}
    wanted.update({asn: "origin" for asn in origins.loc[origins["Status"] == bgp.UNAUTHORIZED, "Origin"]})
    for upstream in bgp.main_upstreams(routes).values():
        wanted.setdefault(upstream, "upstream")
    asn_list = list(wanted)[:BGPDB_ASN_MAX]
    progress.start("bgpdb", len(asn_list), note="origin and upstream networks")
    asn_rows = []
    for asn, result in zip(asn_list, _parallel(asn_list, guarded(bgpdb.lookup_asn, "asn"), key="bgpdb")):
        _bgp_logged(log, raw, result, "asn", asn)
        for record in (result.data if result.ok else [])[:1]:
            asn_rows.append(bgp.asn_row(record, wanted[asn], domains_of.get(asn, ())))
    asns = pd.DataFrame(asn_rows, columns=bgp.ASN_COLUMNS)
    neighbours = pd.DataFrame(columns=bgp.NEIGHBOUR_COLUMNS)
    if context:
        ranges = {}
        for prefix in usual["Prefix"]:
            cover = bgp.covering_range(prefix)
            if cover:
                ranges.setdefault(cover, set()).add(prefix)
        covers = list(ranges)[:BGPDB_NEIGHBOUR_MAX]
        progress.start("bgpdb", len(covers), note="prefixes announced around them")
        run_origins = set(usual["Origin"])
        rows = []
        for cover, result in zip(covers, _parallel(covers, lambda c: guarded(
                bgpdb.lookup_prefix, "prefix")(c, BGPDB_NEIGHBOUR_LIMIT), key="bgpdb")):
            _bgp_logged(log, raw, result, "prefix", cover, BGPDB_NEIGHBOUR_LIMIT)
            rows += bgp.neighbour_rows(cover, ranges[cover], run_origins, result.data if result.ok else [])
        neighbours = pd.DataFrame(rows, columns=bgp.NEIGHBOUR_COLUMNS)
    if breaker.tripped:
        log.record(FetchResult(bgpdb.SOURCE, "remaining lookups skipped", error=bgpdb.STOPPED.format(count=breaker.limit)))
    progress.finish("bgpdb", f"{origins['Prefix'].nunique()} prefix(es), {usual['Origin'].nunique()} origin network(s)"
                    + (" (stopped early: host not answering)" if breaker.tripped else ""))
    return (bgp.with_names(origins, asns), asns, routes, neighbours, pd.DataFrame(raw, columns=bgp.RAW_COLUMNS))

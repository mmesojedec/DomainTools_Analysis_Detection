"""
BGPDB collection stage: the announced prefixes and origin networks of the run's hosting IPs, their AS paths, the
origin and upstream networks and the prefixes around them (core.bgp reads them). Stops early when the host does not
answer (bgpdb.Breaker).
"""
import ipaddress
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


def collect_bgp(domains, ip_targets, pdns, enrichment, log, max_ips=BGPDB_MAX_IPS, context=True, cidr_targets=()):
    """
    BGPDB: the announced prefixes and origin networks of the run's hosting IPs (core.bgp.select_ips), one `ip` lookup
    per /24 (IPv6 /48) they fall in; then the AS paths of the prefixes (`route?hops=2`: each upstream in front of the
    origin), the origin and upstream networks (`asn`) and, with `context`, every more-specific prefix announced
    inside the run's own prefixes (`prefix` on the announced prefix, e.g. the /22 the `ip` answer named). A CIDR
    target is looked up by its first address (the announcement covering it) and as a range of its own (every prefix
    announced inside it). Skipped without a BGPDB host. Returns (origins, asns, routes, neighbours, raw) frames; the
    neighbours frame keeps its name and columns (Covering Range = the prefix or range asked).
    """
    empty = (pd.DataFrame(columns=bgp.ORIGIN_COLUMNS), pd.DataFrame(columns=bgp.ASN_COLUMNS),
             pd.DataFrame(columns=bgp.ROUTE_COLUMNS), pd.DataFrame(columns=bgp.NEIGHBOUR_COLUMNS),
             pd.DataFrame(columns=bgp.RAW_COLUMNS))
    if not bgpdb.load_bgpdb_host():
        progress.skip("bgpdb", "No BGPDB host (Settings → API credentials)")
        return empty
    chosen = bgp.select_ips(domains, pdns, enrichment, ip_targets, max_ips, cidr_targets=cidr_targets)
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

    blocks = {}   # one `ip` lookup per /24 (IPv6 /48): its answer holds every prefix covering the run's addresses in it
    for ip in ips:
        blocks.setdefault(bgp.lookup_block(ip), []).append(ip)
    progress.start("bgpdb", len(blocks), note=f"{len(ips)} IP(s) in {len(blocks)} /24 or /48 block(s): announced "
                                              "prefixes and origin networks")
    results = _parallel(list(blocks), guarded(bgpdb.lookup_ip, "ip"), key="bgpdb")
    rows = []
    for block, result in zip(blocks, results):
        _bgp_logged(log, raw, result, "ip", block)
        records = result.data if result.ok else []
        for ip in blocks[block]:
            rows += bgp.origin_rows(ip, chosen[ip], [r for r in records if bgp.covers(r.get("prefix"), ip)])
    origins = pd.DataFrame(rows, columns=bgp.ORIGIN_COLUMNS)
    if breaker.tripped and origins.empty:
        log.record(FetchResult(bgpdb.SOURCE, f"{len(blocks) - len(raw)} lookup(s) skipped",
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
            bgpdb.lookup_route, "route")(p, BGPDB_ROUTE_LIMIT, bgpdb.ROUTE_HOPS), key="bgpdb")):
        _bgp_logged(log, raw, result, "route", prefix, BGPDB_ROUTE_LIMIT)
        routes += bgp.route_rows(prefix, result.data if result.ok else [])
    routes = pd.DataFrame(routes, columns=bgp.ROUTE_COLUMNS)
    domains_of = {}
    for _, row in origins.iterrows():
        domains_of.setdefault(row["Origin"], set()).update(d.strip() for d in str(row["Domains"]).split(",") if d.strip())
    wanted = {asn: "origin" for asn in usual["Origin"]}
    wanted.update({asn: "origin" for asn in origins.loc[origins["Status"] == bgp.UNAUTHORIZED, "Origin"]})
    for upstreams in bgp.prefix_upstreams(routes).values():   # every upstream, the most-seen first
        for upstream in upstreams:
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
    ranges = {}   # CIDR targets first (always): every prefix announced inside each, next to the one covering it
    for cidr in cidr_targets:
        first = str(ipaddress.ip_network(cidr, strict=False)[0])
        ranges[str(cidr)] = set(usual.loc[usual["IP"] == first, "Prefix"])
    if context:   # then the run's own announced prefixes, busiest first: every more-specific announced inside each
        for prefix in usual.sort_values("Updates", ascending=False)["Prefix"].astype(str).str.rstrip("+"):
            ranges.setdefault(prefix, set()).add(prefix)
    if ranges:
        covers = list(ranges)[:BGPDB_NEIGHBOUR_MAX]
        progress.start("bgpdb", len(covers), note="more-specific prefixes announced inside them")
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

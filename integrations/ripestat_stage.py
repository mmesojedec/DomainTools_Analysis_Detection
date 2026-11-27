"""
RIPEstat collection stage: the same BGP tables as the BGPDB stage (origins, networks, AS paths, more-specific prefixes,
answers as received) from RIPE RIS through RIPEstat, and the registration of each hosting IP (registry network object
and abuse contact). Used for routing when Settings → BGP routing source says so (Auto: when there is no BGPDB host),
and for registration alone next to BGPDB.
"""
import ipaddress

import pandas as pd

from config import (
    BGP_SOURCE_SETTING,
    BGP_SOURCES,
    RIPESTAT_ASN_MAX,
    RIPESTAT_MAX_IPS,
    RIPESTAT_NEIGHBOUR_MAX,
    RIPESTAT_REGISTRATION_SETTING,
    RIPESTAT_ROUTE_MAX,
)
from core import bgp
from core import ripestat as rs
from integrations import progress, ripestat
from integrations.bgp_stage import _bgp_logged
from integrations.credentials import load_bgpdb_host
from integrations.fetch_runner import _parallel, _safe_call
from integrations.http import FetchResult


def _settings():
    from core.persistence import load_settings
    return load_settings()


def routing_mode(settings=None):
    """The BGP routing source setting: "both" (default), "auto", "bgpdb" or "ripestat" (config.BGP_SOURCES)."""
    choice = (settings if settings is not None else _settings()).get(BGP_SOURCE_SETTING, "both")
    return choice if choice in BGP_SOURCES else "both"


def routing_plan(settings=None):
    """
    (BGPDB, RIPEstat) for the next run: BGPDB is asked when a host is set (not with "ripestat"); RIPEstat "always"
    (both, ripestat, or no BGPDB host), "fallback" (auto: only when BGPDB gives no routing) or "never".
    """
    mode, host = routing_mode(settings), bool(load_bgpdb_host())
    bgpdb = host and mode != "ripestat"
    if mode in ("both", "ripestat") or (mode == "auto" and not host):
        return bgpdb, "always"
    return bgpdb, "fallback" if mode == "auto" else "never"


def routing_source(settings=None):
    """The source a run's alerts use when everything answers: "bgpdb" or "ripestat"."""
    bgpdb, ripe = routing_plan(settings)
    return "bgpdb" if bgpdb or ripe == "never" else "ripestat"


def registration_on(settings=None):
    """Whether a run looks up the registration and abuse contact of its hosting IPs in RIPEstat."""
    return bool((settings if settings is not None else _settings()).get(RIPESTAT_REGISTRATION_SETTING, True))


def _logged(log, raw, result, call, resource, **extra):
    """Logs a RIPEstat call (Data sources) and keeps its answer for the BGP page's Responses."""
    if str(result.error or "").startswith("RIPEstat stopped"):
        return result
    if not (result.extras or {}).get("url"):
        result.extras = {**(result.extras or {}), "url": ripestat.request_url(call, resource, **extra)}
    return _bgp_logged(log, raw, result, call, " ".join([str(resource), *(str(v) for k, v in extra.items()
                                                                           if k == "prefix")]))


def collect_registration(chosen, log, raw, breaker=None):
    """REGISTRATION_COLUMNS: per IP its registry network object (whois) and abuse contact (abuse-contact-finder)."""
    breaker = breaker or ripestat.Breaker()
    ips = sorted(chosen)
    if not ips:
        return rs.registration_frame([])
    progress.start("ripestat", 2 * len(ips), note=f"registration and abuse contact of {len(ips)} IP(s)")

    def fetch(ip):
        return [_guarded(breaker, ripestat.whois, "whois")(ip),
                _guarded(breaker, ripestat.abuse_contact, "abuse-contact-finder")(ip)]

    rows = []
    for ip, (who, abuse) in zip(ips, _parallel(ips, fetch, key="ripestat")):
        _logged(log, raw, who, "whois", ip)
        _logged(log, raw, abuse, "abuse-contact-finder", ip)
        if who.ok or abuse.ok:
            rows.append(rs.registration_row(ip, chosen[ip], who.data if who.ok else None,
                                            abuse.data if abuse.ok else None))
    return rs.registration_frame(rows)


def _guarded(breaker, func, call):
    return lambda *args: breaker.call(lambda *a: _safe_call(func, ripestat.SOURCE, f"{call} {args[0]}", *a),
                                      f"{call} {args[0]}", *args)


def collect_ripestat(domains, ip_targets, pdns, enrichment, log, max_ips=RIPESTAT_MAX_IPS, context=True,
                     cidr_targets=(), routing=True, registration=True, chosen=None):
    """
    RIPEstat for the run's hosting IPs (core.bgp.select_ips, at most RIPESTAT_MAX_IPS): with `routing`, one
    routing-history per IP (prefixes and origins, years back), routing-status and rpki-validation of each prefix in
    use, the AS paths RIS sees (looking-glass), the origin and upstream networks, and with `context` the more-specific
    prefixes announced inside the run's prefixes and CIDR targets; with `registration`, the registry network object
    and abuse contact of each IP. Returns (origins, asns, routes, neighbours, raw, registration) frames.
    """
    empty = (pd.DataFrame(columns=bgp.ORIGIN_COLUMNS), pd.DataFrame(columns=bgp.ASN_COLUMNS),
             pd.DataFrame(columns=bgp.ROUTE_COLUMNS), pd.DataFrame(columns=bgp.NEIGHBOUR_COLUMNS))
    if chosen is None:
        chosen = bgp.select_ips(domains, pdns, enrichment, ip_targets, min(max_ips, RIPESTAT_MAX_IPS),
                                cidr_targets=cidr_targets)
    raw = []
    if not chosen:
        progress.skip("ripestat", "No public hosting addresses to look up")
        return (*empty, pd.DataFrame(raw, columns=bgp.RAW_COLUMNS), rs.registration_frame([]))
    breaker = ripestat.Breaker()
    frames = empty
    if routing:
        frames = _routing(chosen, log, raw, breaker, context, cidr_targets)
    reg = collect_registration(chosen, log, raw, breaker) if registration and not breaker.tripped \
        else rs.registration_frame([])
    if breaker.tripped:
        log.record(FetchResult(ripestat.SOURCE, "remaining lookups skipped",
                               error=ripestat.STOPPED.format(count=breaker.limit)))
    origins = frames[0]
    progress.finish("ripestat", (f"{origins['Prefix'].nunique()} prefix(es), {origins['Origin'].nunique()} origin "
                                 "network(s)" if routing else "") + (f"; {len(reg)} registration(s)" if registration
                                                                     else "")
                    + (" (stopped early: RIPEstat not answering)" if breaker.tripped else ""))
    return (*frames, pd.DataFrame(raw, columns=bgp.RAW_COLUMNS), reg)


def _routing(chosen, log, raw, breaker, context, cidr_targets):
    ips = sorted(chosen)
    progress.start("ripestat", len(ips), note=f"routing history of {len(ips)} IP(s)")
    rows, records_of = [], {}
    for ip, result in zip(ips, _parallel(ips, _guarded(breaker, ripestat.routing_history, "routing-history"),
                                         key="ripestat")):
        _logged(log, raw, result, "routing-history", ip)
        records_of[ip] = rs.history_records(result.data) if result.ok else []
    pairs = list(dict.fromkeys((r["prefix"], r["origin"]) for records in records_of.values() for r in records))
    prefixes = list(dict.fromkeys(prefix for prefix, _ in pairs))
    if not pairs:
        progress.finish("ripestat", "no announced prefix found")
        return (pd.DataFrame(columns=bgp.ORIGIN_COLUMNS), pd.DataFrame(columns=bgp.ASN_COLUMNS),
                pd.DataFrame(columns=bgp.ROUTE_COLUMNS), pd.DataFrame(columns=bgp.NEIGHBOUR_COLUMNS))
    progress.start("ripestat", 3 * len(prefixes) + len(pairs), note="registry checks of the announced prefixes")
    statuses = dict(zip(prefixes, _parallel(prefixes, _guarded(breaker, ripestat.routing_status, "routing-status"),
                                            key="ripestat")))
    for prefix, result in statuses.items():
        _logged(log, raw, result, "routing-status", prefix)
    rir_lines = {}   # prefix -> "RIPE 2003-11-20 NL": the RIR, when the prefix first appeared in its stats, the country

    def allocation(prefix):
        return [_guarded(breaker, ripestat.whois, "whois")(prefix), _guarded(breaker, ripestat.rir_country,
                                                                             "rir-stats-country")(prefix)]

    for prefix, (who, country) in zip(prefixes, _parallel(prefixes, allocation, key="ripestat")):
        _logged(log, raw, who, "whois", prefix)
        _logged(log, raw, country, "rir-stats-country", prefix)
        rir_lines[prefix] = rs.whois_rir_text(who.data if who.ok else None, country.data if country.ok else None)
    rpki = {}
    for (prefix, origin), result in zip(pairs, _parallel(pairs, lambda pair: breaker.call(
            lambda *a: _safe_call(ripestat.rpki_validation, ripestat.SOURCE, f"rpki-validation {pair[1]} {pair[0]}",
                                  *a), f"rpki-validation {pair[1]} {pair[0]}", pair[1], pair[0]), key="ripestat")):
        _logged(log, raw, result, "rpki-validation", origin, prefix=prefix)
        rpki[(prefix, origin)] = result.data if result.ok else None
    for ip in ips:
        status_data = {p: (r.data if r.ok else None) for p, r in statuses.items()}
        records = [{**rs.add_validity(r, status_data.get(r["prefix"]), rpki.get((r["prefix"], r["origin"]))),
                    "rir_prefix": [rir_lines[r["prefix"]]] if rir_lines.get(r["prefix"]) else []}
                   for r in records_of[ip]]
        rows += bgp.origin_rows(ip, chosen[ip], records)
    origins = pd.DataFrame(rows, columns=bgp.ORIGIN_COLUMNS)
    usual = bgp.main_origins(origins)
    busiest = list(dict.fromkeys(usual.sort_values("Updates", ascending=False)["Prefix"]))[:RIPESTAT_ROUTE_MAX]
    progress.start("ripestat", len(busiest), note="AS paths RIS sees towards the prefixes")
    routes = []
    for prefix, result in zip(busiest, _parallel(busiest, _guarded(breaker, ripestat.looking_glass, "looking-glass"),
                                                 key="ripestat")):
        _logged(log, raw, result, "looking-glass", prefix)
        routes += bgp.route_rows(prefix, rs.route_records(prefix, result.data) if result.ok else [])
    routes = pd.DataFrame(routes, columns=bgp.ROUTE_COLUMNS)
    domains_of = {}
    for _, row in origins.iterrows():
        domains_of.setdefault(row["Origin"], set()).update(d.strip() for d in str(row["Domains"]).split(",") if d.strip())
    wanted = {asn: "origin" for asn in usual["Origin"]}
    wanted.update({asn: "origin" for asn in origins.loc[origins["Status"] == bgp.UNAUTHORIZED, "Origin"]})
    for upstreams in bgp.prefix_upstreams(routes).values():
        for upstream in upstreams:
            wanted.setdefault(upstream, "upstream")
    asn_list = list(wanted)[:RIPESTAT_ASN_MAX]
    progress.start("ripestat", len(asn_list), note="origin and upstream networks")

    calls = {"as-overview": ripestat.as_overview, "asn-neighbours": ripestat.asn_neighbours, "whois": ripestat.whois,
             "rir-stats-country": ripestat.rir_country}

    def network(asn):
        """An origin's neighbour counts too; not an upstream's (a transit network's list runs to megabytes)."""
        return {call: _guarded(breaker, func, call)(asn) for call, func in calls.items()
                if call != "asn-neighbours" or wanted[asn] == "origin"}

    asn_rows = []
    for asn, answers in zip(asn_list, _parallel(asn_list, network, key="ripestat")):
        for call, result in answers.items():
            _logged(log, raw, result, call, asn)
        if any(r.ok for r in answers.values()):
            data = {call: (r.data if r.ok else None) for call, r in answers.items()}
            asn_rows.append(bgp.asn_row(rs.asn_record(asn, data.get("as-overview"), data.get("asn-neighbours"),
                                                      data.get("whois"), data.get("rir-stats-country")),
                                        wanted[asn], domains_of.get(asn, ())))
    asns = pd.DataFrame(asn_rows, columns=bgp.ASN_COLUMNS)
    neighbours = pd.DataFrame(columns=bgp.NEIGHBOUR_COLUMNS)
    ranges = {}
    for cidr in cidr_targets:
        first = str(ipaddress.ip_network(cidr, strict=False)[0])
        ranges[str(cidr)] = set(usual.loc[usual["IP"] == first, "Prefix"])
    if context:
        for prefix in usual.sort_values("Updates", ascending=False)["Prefix"].astype(str):
            ranges.setdefault(prefix, set()).add(prefix)
    covers = list(ranges)[:RIPESTAT_NEIGHBOUR_MAX]
    if covers:
        run_origins = set(usual["Origin"])
        missing = [c for c in covers if c not in statuses]
        fetched = dict(zip(missing, _parallel(missing, _guarded(breaker, ripestat.routing_status, "routing-status"),
                                              key="ripestat")))
        for cover, result in fetched.items():
            _logged(log, raw, result, "routing-status", cover)
        rows = []
        for cover in covers:
            result = statuses.get(cover) or fetched.get(cover)
            records = rs.more_specific_records(result.data) if result is not None and result.ok else []
            rows += bgp.neighbour_rows(cover, ranges[cover], run_origins, records)
        neighbours = pd.DataFrame(rows, columns=bgp.NEIGHBOUR_COLUMNS)
    return bgp.with_names(origins, asns), asns, routes, neighbours


def collect_registration_only(domains, ip_targets, pdns, enrichment, log, max_ips=RIPESTAT_MAX_IPS, cidr_targets=()):
    """Next to BGPDB: only the registration and abuse contact of the hosting IPs (raw answers, registration)."""
    *_, raw, reg = collect_ripestat(domains, ip_targets, pdns, enrichment, log, max_ips, context=False,
                                    cidr_targets=cidr_targets, routing=False, registration=True)
    return raw, reg


BGP_FIELDS = ("bgp_origins", "bgp_asns", "bgp_routes", "bgp_neighbours")
ALT_FIELDS = tuple(f"alt_{name}" for name in BGP_FIELDS)


def collect_routing(domains, ip_targets, pdns, enrichment, log, max_ips, context=True, cidr_targets=(),
                    step=lambda text: None, settings=None):
    """
    The run's BGP routing from the sources Settings picks (routing_plan), as CollectedData fields: bgp_* = the source
    the alerts use (BGPDB when it gave routing, else RIPEstat), alt_bgp_* = the other source's tables (shown with the
    BGP page's switch), bgp_source / alt_bgp_source their names, bgp_raw every answer of both, bgp_registration.
    """
    from integrations.bgp_stage import collect_bgp
    use_bgpdb, ripe = routing_plan(settings)
    register = registration_on(settings)
    frames, raws, registration = {}, [], rs.registration_frame([])
    if use_bgpdb or ripe == "never":
        step("Looking up BGP routing of the hosting IPs (BGPDB)...")
        *tables, raw = collect_bgp(domains, ip_targets, pdns, enrichment, log, max_ips, context, cidr_targets=cidr_targets)
        frames["BGPDB"] = tables
        raws.append(raw)
    bgpdb_answered = "BGPDB" in frames and not frames["BGPDB"][0].empty
    if ripe == "always" or (ripe == "fallback" and not bgpdb_answered):
        step("Looking up BGP routing of the hosting IPs (RIPEstat)...")
        *tables, raw, registration = collect_ripestat(domains, ip_targets, pdns, enrichment, log, max_ips, context,
                                                      cidr_targets=cidr_targets, registration=register)
        frames["RIPEstat"] = tables
        raws.append(raw)
    elif register:
        step("Looking up the registration of the hosting IPs (RIPEstat)...")
        raw, registration = collect_registration_only(domains, ip_targets, pdns, enrichment, log, max_ips,
                                                      cidr_targets=cidr_targets)
        raws.append(raw)
    primary = "BGPDB" if bgpdb_answered or "RIPEstat" not in frames else "RIPEstat"
    other = next((name for name in frames if name != primary and not frames[name][0].empty), "")
    empty = [pd.DataFrame(columns=c) for c in (bgp.ORIGIN_COLUMNS, bgp.ASN_COLUMNS, bgp.ROUTE_COLUMNS,
                                                  bgp.NEIGHBOUR_COLUMNS)]
    out = dict(zip(BGP_FIELDS, frames.get(primary, empty)))
    out.update(zip(ALT_FIELDS, frames[other] if other else [pd.DataFrame() for _ in ALT_FIELDS]))
    raws = [r for r in raws if r is not None and not r.empty]
    out.update(bgp_source=primary if primary in frames else "", alt_bgp_source=other,
               bgp_raw=pd.concat(raws, ignore_index=True) if raws else pd.DataFrame(columns=bgp.RAW_COLUMNS),
               bgp_registration=registration)
    return out

"""Orchestrates all data collection for an analysis run (parallel where safe) and records per-source status."""
import contextvars
import time
from concurrent.futures import ThreadPoolExecutor, wait
from contextlib import nullcontext
from dataclasses import dataclass, field, replace

import pandas as pd

from config import (
    BGPDB_MAX_IPS,
    BGPDB_RESOLVE_MAX_IPS,
    CAA_SUPPLEMENT_FETCH_LIMIT,
    CERT_API_MAX_WORKERS,
    CERT_RETRY_PAUSE_SECONDS,
    CERT_SHA256_EVENTS_MAX_RECORDS,
    CNAME_CHASE_MAX_STEPS,
    CNAME_CHASE_QUERIES_PER_DOMAIN,
    CNAME_CHASE_RECORD_LIMIT,
    CNAME_RDATA_RECORD_LIMIT,
    CNAME_SUPPLEMENT_FETCH_LIMIT,
    CT_LOOKUP_DEFAULT_MAX_HASHES,
    DOMAIN_HISTORY_MAX_CHANGES,
    PIVOT_IP_RECORD_LIMIT,
    PIVOT_IPS_PER_DOMAIN,
    RESOLVE_DEFAULT_QUERIES,
    RESOLVE_RECORD_LIMIT,
    RESOLVE_TREE_DAYS,
    RESOLVE_TREE_LIMIT,
    SEED_DEFAULT_TARGETS,
    SEED_MAX_CERTIFICATES,
    TARGET_IRIS_DOMAINS,
    TXT_SUPPLEMENT_FETCH_LIMIT,
    VPNDB_DETAIL_MAX,
    VPNDB_MAX_IPS,
)
from core.account import STAGE_NAMES, STAGE_PRODUCTS
from core.cert_inputs import InputItem, derive_hostnames, derive_targets, hostname_search_query, matched_kind, seed_query
from core.cname import CHASE_COLUMNS, QUERY_LIMIT, build_cname_map, chase_plan, merge_chases, rdata_rows
from core.helpers import classify_targets, is_cidr, is_ip_address
from core.network_intel import cdn_for_ip, explode_ip_events, is_public_ip
from core.pdns_features import add_event_gaps
from core.resolver import (
    LOOKUP_COLUMNS,
    RESOLVE_TYPES,
    build_index,
    build_tree,
    discovered_domains,
    discovery_marker,
    lookup_rows,
    merge_lookups,
)
from integrations import bgpdb, progress

# the stages and helpers live in their own modules; their names stay importable from here
from integrations.bgp_stage import _bgp_logged, collect_bgp  # noqa: F401
from integrations.cache import FROM_CACHE, refreshing
from integrations.certificates import (
    build_search_queries,
    dedupe_hits,
    fetch_cert_events_ctl,
    fetch_cert_events_hostname,
    fetch_cert_events_ip,
    fetch_cert_events_sha256,
    parse_domaintools_certs,
    search_certificates,
)
from integrations.credentials import load_cert_api_key, load_dnsdb_key, load_dtapi_credentials
from integrations.dnsdb import (
    CHASE_SOURCE,
    QueryBudget,
    chase_cname,
    fetch_cname_rdata,
    fetch_dnsdb_history,
    parse_dnsdb_to_dataframe,
)
from integrations.domain_history import extract_ssl_data, fetch_domain_history, parse_history_to_dataframe
from integrations.enrichment import (
    extract_iris_profile,
    extract_ssl_data_from_enrichment,
    fetch_iris_batch,
    fetch_irisql,
    iris_batches,
)
from integrations.fetch_runner import _concat, _parallel, _record_all, _safe_call  # noqa: F401
from integrations.http import FetchResult, StatusLog
from integrations.risk import risk_from_iris
from integrations.vpndb import SOURCE as VPNDB_SOURCE
from integrations.vpndb import (
    load_vpndb_key,
)
from integrations.vpndb_stage import (  # noqa: F401
    VPNDB_RAW_COLUMNS,
    _bulk_logged,
    _check_range_ips,
    _ip_logged,
    _prefix_lookup,
    _vpndb_logged,
    collect_anonymizer_context,
    collect_anonymizers,
    collect_ip_check,
    collect_prefixes,
    collect_tor_overview,
    vpndb_raw_frame,
)


@dataclass
class CollectedData:
    targets: list = field(default_factory=list)
    domain_targets: list = field(default_factory=list)
    pdns_provider: str = "DNSDB Scout"   # kept in saved datasets; DNSDB Scout is the only provider
    dh: pd.DataFrame = field(default_factory=pd.DataFrame)
    ssl: pd.DataFrame = field(default_factory=pd.DataFrame)
    risk: pd.DataFrame = field(default_factory=pd.DataFrame)
    enrichment: dict = field(default_factory=dict)
    ssl_active: pd.DataFrame = field(default_factory=pd.DataFrame)
    pdns: pd.DataFrame = field(default_factory=pd.DataFrame)
    cert_hostnames: pd.DataFrame = field(default_factory=pd.DataFrame)
    ctl: pd.DataFrame = field(default_factory=pd.DataFrame)
    cert_observations: pd.DataFrame = field(default_factory=pd.DataFrame)
    ip_pivots: pd.DataFrame = field(default_factory=pd.DataFrame)
    pdns_coverage: dict = field(default_factory=dict)
    cname_chases: pd.DataFrame = field(default_factory=pd.DataFrame)   # one row per chased CNAME target (chase_cname)
    cname_rdata: pd.DataFrame = field(default_factory=pd.DataFrame)    # reverse CNAME lookups (core.cname.rdata_rows)
    resolutions: pd.DataFrame = field(default_factory=pd.DataFrame)    # DNSDB lookups of the DNS tree (core.resolver)
    resolution_routing: pd.DataFrame = field(default_factory=pd.DataFrame)   # BGPDB origins of its addresses
    anonymizers: pd.DataFrame = field(default_factory=pd.DataFrame)    # VPNDB verdict per hosting IP (core.anonymizers)
    prefixes: pd.DataFrame = field(default_factory=pd.DataFrame)       # VPNDB verdict per CIDR target (PREFIX_COLUMNS)
    prefix_addresses: pd.DataFrame = field(default_factory=pd.DataFrame)   # addresses VPNDB reached in each CIDR
    range_ips: pd.DataFrame = field(default_factory=pd.DataFrame)      # every address of a CIDR target, bulk-checked
    exit_weeks: pd.DataFrame = field(default_factory=pd.DataFrame)     # VPNDB weekly history of the anonymizer exits
    neighbour_ranges: pd.DataFrame = field(default_factory=pd.DataFrame)   # /24s around non-exit hosting IPs (VPNDB)
    hosting_asns: pd.DataFrame = field(default_factory=pd.DataFrame)   # VPNDB providers on the run's Iris ASNs
    exit_neighbours: pd.DataFrame = field(default_factory=pd.DataFrame)    # other names on dedicated exits (DNSDB)
    vpndb_raw: pd.DataFrame = field(default_factory=pd.DataFrame)      # every VPNDB answer as received (Raw Records)
    tor_overview: dict = field(default_factory=dict)  # VPNDB /tor: the Tor network at a glance (not counted in quota)
    bgp_origins: pd.DataFrame = field(default_factory=pd.DataFrame)    # BGPDB: prefix and origin AS per hosting IP
    bgp_asns: pd.DataFrame = field(default_factory=pd.DataFrame)       # BGPDB: the origin and upstream networks
    bgp_routes: pd.DataFrame = field(default_factory=pd.DataFrame)     # BGPDB: AS paths towards the run's prefixes
    bgp_neighbours: pd.DataFrame = field(default_factory=pd.DataFrame)   # BGPDB: prefixes announced around them
    bgp_raw: pd.DataFrame = field(default_factory=pd.DataFrame)        # every BGPDB answer as received
    target_domains: pd.DataFrame = field(default_factory=pd.DataFrame)   # Iris: domains on each IP / CIDR target
    statuses: list = field(default_factory=list)
    seed_inputs: list = field(default_factory=list)                  # certificate input labels, e.g. "cn:Acme VPN"
    seeds: pd.DataFrame = field(default_factory=pd.DataFrame)        # one row per certificate input and what it found
    derived: pd.DataFrame = field(default_factory=pd.DataFrame)      # analyzed targets derived from certificate inputs
    host_focus: dict = field(default_factory=dict)   # apex -> hostnames picked in the certificate preview (view focus)
    dnsdb_limit: int = 0                              # DNSDB records per name requested by the main query

    @property
    def has_data(self):
        return not (self.dh.empty and self.pdns.empty and self.ssl.empty and self.anonymizers.empty
                    and self.prefixes.empty)


def history_since(days, today=None):
    """The ISO date `days` days before today (UTC), or None for all of a domain's history."""
    if not days or days <= 0:
        return None
    today = pd.Timestamp.now(tz="UTC").normalize() if today is None else pd.Timestamp(today)
    return (today - pd.Timedelta(days=int(days))).strftime("%Y-%m-%d")


def history_args(domain, since=None, max_changes=DOMAIN_HISTORY_MAX_CHANGES):
    """The arguments a domain's Domain History is fetched (and cached) with (`max_changes` 0: no cap)."""
    if since or max_changes != DOMAIN_HISTORY_MAX_CHANGES:
        return (domain, max_changes, since) if since else (domain, max_changes)
    return (domain,)


def collect_domain_history(domains, log, days=0, max_changes=DOMAIN_HISTORY_MAX_CHANGES):
    """
    Domain History of each domain: the newest `max_changes` changes (0: no cap); `days` > 0 keeps only the changes of
    that many days (fewer pages, queries).
    """
    since = history_since(days)
    scope = ", ".join(filter(None, [f"changes since {since}" if since else "",
                                    f"up to {max_changes:,} per domain" if max_changes else "no limit"]))
    progress.start("history", len(domains), scope)
    results = _record_all(log, _parallel(domains, lambda d: _safe_call(fetch_domain_history, "Domain History", d,
                                                                       *history_args(d, since, max_changes)),
                                         key="history"))
    progress.finish("history")
    dh = _concat([parse_history_to_dataframe(r.data, d) for d, r in zip(domains, results)])
    ssl = _concat([extract_ssl_data(r.data, d) for d, r in zip(domains, results)])
    return dh, ssl


def fetch_rest_of_history(collected, domains, max_changes=0):
    """
    Fetches the Domain History of `domains` again, without a period and up to `max_changes` per domain (0: no cap),
    and puts it in place of what `collected` holds for them: their changes, their Domain History certificates and
    their status rows. Returns the new status rows (one per domain).
    """
    log = StatusLog()
    dh, ssl = collect_domain_history(list(domains), log, 0, max_changes)
    names = set(domains)
    old_dh = collected.dh[~collected.dh["Domain"].isin(names)] if not collected.dh.empty else collected.dh
    collected.dh = _concat([old_dh, dh])
    if not collected.ssl.empty and {"Domain", "Source"} <= set(collected.ssl.columns):
        old_ssl = collected.ssl[~(collected.ssl["Domain"].isin(names) & (collected.ssl["Source"] == "Domain History"))]
    else:
        old_ssl = collected.ssl
    collected.ssl = _concat([old_ssl, ssl])
    collected.statuses = [row for row in collected.statuses
                          if not (str(row.get("Source", "")).startswith("Domain History") and row.get("Target") in names)
                          ] + log.rows
    return log.rows


def collect_certificates(targets, log, seed_hits=None, host_focus=None):
    """
    Certificates naming each target. `seed_hits` are full records already found through certificate inputs: they
    are merged in, so a seed certificate is part of the run even when a target's own search would not return it.
    When a domain's search stops at the record limit and the domain has focus hostnames, those hostnames are searched
    on their own as well, so certificates the capped search missed are filled in.
    """
    queries = build_search_queries(targets)
    progress.start("certs", len(queries), "certificate search")
    by_query, _ = run_with_retry(queries, lambda q: _safe_call(search_certificates, "Certificate Search", q[0], q[0], q[1]),
                                 key="certs")
    results = _record_all(log, [by_query[q] for q in queries])
    gaps = [(dom, hostname_search_query(hosts)) for dom, hosts in (host_focus or {}).items()
            if any(q[0] == dom and by_query[q].truncated for q in queries)]
    # results may come from the lookup cache, so they are relabelled on a copy
    if gaps:
        progress.start("certs", len(gaps), "hostname gap-fill search")
    gap_results = _record_all(log, [replace(progress.counted("certs", lambda job: _safe_call(
        search_certificates, "Certificate Search", job[0], job[0], job[1]))((dom, query)),
        source="Certificate Search (Hostname Gap-Fill)") for dom, query in gaps])
    progress.finish("certs", "certificate search done; certificate events next")
    return parse_domaintools_certs(dedupe_hits([seed_hits or [], *(r.data for r in results), *(r.data for r in gap_results)]),
                                   targets)


def collect_enrichment(domains, log):
    batches = iris_batches(domains)
    progress.start("iris", len(batches), f"{len(domains)} domain(s) in {len(batches)} batch(es)")
    results = _record_all(log, _parallel(batches, lambda b: _safe_call(fetch_iris_batch, "Iris Investigate", ", ".join(b), b),
                                         key="iris"))
    progress.finish("iris")
    enrichment = {}
    for result in results:
        enrichment.update(result.data or {})
    return enrichment


DEDUP_COLUMNS = ["Domain", "RRName", "Field", "Value", "First Seen"]


@dataclass(frozen=True)
class SupplementSpec:
    """A record-type-specific pDNS lookup run alongside the main query."""
    rrtype: str
    fetch_limit: int
    keep_latest: int = None      # None keeps every record (CAA history matters for stripping detection)
    include_wildcard: bool = True
    only_if_capped: bool = False   # Iris: run only where the main query hit its limit (DNSDB supplements always do)

    @property
    def collection(self):
        return f"{self.rrtype} lookup"


def supplement_specs(txt_records=0, caa_lookup=False, cname_lookup=False):
    specs = []
    if txt_records > 0:
        specs.append(SupplementSpec("TXT", TXT_SUPPLEMENT_FETCH_LIMIT, keep_latest=txt_records))
    if caa_lookup:
        specs.append(SupplementSpec("CAA", CAA_SUPPLEMENT_FETCH_LIMIT, include_wildcard=False))
    if cname_lookup:
        specs.append(SupplementSpec("CNAME", CNAME_SUPPLEMENT_FETCH_LIMIT, only_if_capped=True))
    return specs


def latest_records(frame, n):
    """Keeps the `n` most recently seen records per domain (Last Seen, falling back to First Seen)."""
    if frame.empty or n <= 0:
        return frame.iloc[0:0]
    seen = pd.to_datetime(frame["Last Seen"], errors="coerce").fillna(frame["First Seen"])
    ordered = frame.assign(_seen=seen).sort_values("_seen", ascending=False, kind="stable")
    return ordered.groupby("Domain", sort=False).head(n).drop(columns="_seen")


def merge_supplements(pdns, supplements, log):
    """Adds supplemental rows the main query missed (per record type), then recomputes per-domain event gaps."""
    merged = pdns
    for spec, frame in supplements.items():
        if frame.empty:
            continue
        before = len(merged)
        merged = _concat([merged, frame.assign(Collection=spec.collection)])
        merged = merged.drop_duplicates(subset=DEDUP_COLUMNS, keep="first")  # main-query rows win
        added = len(merged) - before
        # Records found but already present still mean the lookup worked, so both cases are "OK"
        log.add(f"{spec.rrtype} Lookup", f"{frame['Domain'].nunique()} domain(s)", "OK",
                f"Added {added} {spec.rrtype} record(s) not returned by the main query" if added
                else f"All {spec.rrtype} lookup records were already in the main results", added)
    if merged is pdns or merged.empty:
        return merged
    return add_event_gaps(merged).sort_values("Date", ascending=False).reset_index(drop=True)


def _apply_spec(spec, frame, result, log):
    """Trims a supplemental frame per its spec and records its status (trimming is expected, not truncation)."""
    kept = latest_records(frame, spec.keep_latest) if spec.keep_latest else frame
    result.truncated = False
    if result.ok and result.record_count and spec.keep_latest:
        result.note = f"Kept latest {len(kept)} of {result.record_count} {spec.rrtype} record(s)"
    log.record(result)
    return kept


def _coverage(domains, main_results, caa_results):
    """Per domain: was the main query truncated, and did a dedicated CAA lookup succeed?"""
    return {domain: {"truncated": any(r.truncated or not r.ok for r in main_results[domain]),
                     "caa_checked": bool(caa_results.get(domain) is not None and caa_results[domain].ok)}
            for domain in domains}


INCREMENTAL_OVERLAP_SECONDS = 86400   # an incremental lookup starts a day before the earlier dataset was collected


def incremental_since(created):
    """Epoch seconds (start of the UTC day, so the lookup stays cacheable that day) an incremental passive DNS lookup
    starts from: a day before `created` (the earlier dataset's ISO creation time); None when it cannot be read."""
    when = pd.to_datetime(created, errors="coerce", utc=True)
    if pd.isna(when):
        return None
    return int((when.normalize() - pd.Timedelta(seconds=INCREMENTAL_OVERLAP_SECONDS)).timestamp())


def merge_incremental(new, base, targets):
    """
    `new` passive DNS rows (an incremental lookup of `targets`) plus the `base` dataset's rows of those targets that
    the new lookup did not return again. DNSDB returns a record still being seen with a later last-seen time, so a
    new row with the same name, type, value and first-seen time replaces the earlier one.
    """
    old = base[base["Domain"].isin(targets)] if base is not None and not base.empty else pd.DataFrame()
    if old.empty:
        return new
    combined = _concat([new, old]).drop_duplicates(subset=DEDUP_COLUMNS, keep="first")
    return add_event_gaps(combined).sort_values("Date", ascending=False).reset_index(drop=True)


def collect_pdns(targets, dnsdb_limit, log, txt_records=0, caa_lookup=False, cname_lookup=False, base=None):
    """
    Main passive DNS query per target plus optional record-type supplements (TXT: latest N per domain; CAA: apex name,
    all records; CNAME: name and subdomains, all records). Large result limits are often filled by A/NS rows before
    TXT, CAA or CNAME records appear, so the supplements only run for domains whose main query was cut off.
    Returns (pdns_frame, coverage) where coverage maps domain -> {"truncated", "caa_checked"}.
    `base` ({"frame": passive DNS of an earlier dataset of these targets, "created": its ISO time, "name": its name})
    makes DNSDB look up only records seen since a day before that dataset and add its older records (incremental);
    targets missing from it are looked up in full.
    """
    domains = [t for t in targets if not is_ip_address(t) and not is_cidr(t)]
    specs = supplement_specs(txt_records, caa_lookup, cname_lookup)
    supplements = {spec: [] for spec in specs}
    main_results, caa_results = {}, {}

    base_frame = (base or {}).get("frame")
    since = incremental_since((base or {}).get("created")) if base_frame is not None else None
    known = set(base_frame["Domain"]) if since and not base_frame.empty else set()
    progress.start("pdns", len(targets), f"incremental for {len(known & set(targets))} target(s)" if known else "")
    results = _record_all(log, _parallel(
        targets, lambda t: _incremental_note(_safe_call(
            fetch_dnsdb_history, "DNSDB Scout", t, t, dnsdb_limit, **({"since": since} if t in known else {})),
            base, t in known), key="pdns"
    ))
    progress.finish("pdns")
    main_results = {t: [r] for t, r in zip(targets, results)}
    pdns = _concat([parse_dnsdb_to_dataframe(r.data, t) for t, r in zip(targets, results)])
    if known:
        pdns = merge_incremental(pdns, base_frame, sorted(known & set(targets)))
    # A complete ANY lookup already holds every TXT and CAA record, so supplements only run where it was cut off
    incomplete = [d for d in domains if main_results[d][0].truncated or not main_results[d][0].ok]
    for spec in specs:
        skipped = len(domains) - len(incomplete)
        if skipped:
            log.add(f"DNSDB {spec.rrtype} Lookup", f"{skipped} domain(s)", "OK",
                    f"Not needed: the main lookup returned every record, {spec.rrtype} included")
        if incomplete:
            progress.start(spec.rrtype, len(incomplete), f"main lookup hit its limit for {len(incomplete)} domain(s)"
                           + (f"; not needed for {skipped}" if skipped else ""))
        else:
            progress.skip(spec.rrtype, f"Not needed: the main lookup returned every record for all {skipped} "
                                       "domain(s)")
        spec_results = _parallel(incomplete, lambda d, spec=spec: _safe_call(
            fetch_dnsdb_history, f"DNSDB {spec.rrtype} Lookup", d, d, spec.fetch_limit, spec.rrtype, spec.include_wildcard),
            key=spec.rrtype)
        progress.finish(spec.rrtype)
        for domain, result in zip(incomplete, spec_results):
            supplements[spec].append(_apply_spec(spec, parse_dnsdb_to_dataframe(result.data, domain), result, log))
            if spec.rrtype == "CAA":
                caa_results[domain] = result

    merged = merge_supplements(pdns, {spec: _concat(frames) for spec, frames in supplements.items()}, log)
    return merged, _coverage([d for d in domains if d in main_results], main_results, caa_results)


def _incremental_note(result, base, incremental):
    """Says on an incremental lookup's status row that older records come from the earlier dataset."""
    if not incremental:
        return result
    text = (f"Incremental: records seen since a day before {str(base.get('created', ''))[:10]}; older ones from the "
            f"offline dataset {base.get('name') or base.get('created', '')}")
    return replace(result, note=f"{result.note}; {text}" if result.note else text)


def fill_pdns_gaps(pdns, coverage, host_focus, dnsdb_limit, log):
    """
    For domains whose main passive DNS query stopped at the result limit, looks up each focus hostname exactly
    (its own limit), so records the capped apex query missed are filled in. DNSDB Scout only. Rows keep the apex as
    their Domain; already-present records are dropped. Returns the merged frame.
    """
    jobs = [(dom, host) for dom, hosts in (host_focus or {}).items() if coverage.get(dom, {}).get("truncated")
            for host in hosts]
    if not jobs:
        return pdns
    progress.start("pdns", len(jobs), "hostname gap-fill")
    results = _parallel(jobs, lambda job: _safe_call(fetch_dnsdb_history, "DNSDB Hostname Gap-Fill", job[1], job[1],
                                                     dnsdb_limit, "ANY", False), key="pdns")
    progress.finish("pdns")
    frames = []
    for (dom, _), result in zip(jobs, results):
        log.record(replace(result, source="DNSDB Hostname Gap-Fill"))
        frames.append(parse_dnsdb_to_dataframe(result.data, dom).assign(Collection="Hostname gap-fill"))
    added = _concat(frames)
    if added.empty:
        return pdns
    merged = _concat([pdns, added]).drop_duplicates(subset=DEDUP_COLUMNS, keep="first")
    return add_event_gaps(merged).sort_values("Date", ascending=False).reset_index(drop=True)


def cert_event_jobs(domains, ip_targets):
    """(kind, domain the rows belong to, name queried, include subdomains) per Certificate Events lookup."""
    return [("hostname", d, d, True) for d in domains] + [("ip", ip, ip, False) for ip in ip_targets]


def collect_cert_events(domains, ip_targets, log, host_focus=None):
    """
    Observed certificate events per domain (with subdomains) and IP. When a domain's events stop at the record limit,
    each focus hostname of that domain is looked up on its own as well (gap-fill).
    """
    jobs = cert_event_jobs(domains, ip_targets)

    def run(job):
        kind, _, name, subdomains = job
        if kind == "hostname":
            return _safe_call(fetch_cert_events_hostname, "Cert Events (Hostname)", name, name, subdomains)
        return _safe_call(fetch_cert_events_ip, "Cert Events (IP)", name, name)

    progress.start("certs", len(jobs), "certificate events")
    by_job, _ = run_with_retry(jobs, run, key="certs")
    gaps = [("hostname", dom, host, False) for dom, hosts in (host_focus or {}).items()
            if by_job.get(("hostname", dom, dom, True)) is not None and by_job[("hostname", dom, dom, True)].truncated
            for host in hosts if not host.startswith("*.")]   # wildcard SANs are not observable names
    if gaps:
        progress.start("certs", len(gaps), "certificate events, hostname gap-fill")
    gap_results = {job: replace(progress.counted("certs", run)(job), source="Cert Events (Hostname Gap-Fill)")
                   for job in gaps}
    progress.finish("certs", "")
    jobs, by_job = jobs + gaps, {**by_job, **gap_results}
    rows = []
    for (kind, target, _, _), result in zip(jobs, _record_all(log, [by_job[job] for job in jobs])):
        for ev in result.data or []:
            hostname = ev.get("hostname", "") if kind == "hostname" else ev.get("hostname", target)
            rows.append({
                "Domain": target,
                "Hostname": hostname,
                "RRName": hostname,
                "IP": ev.get("ip", "N/A") if kind == "hostname" else target,
                "Cert_SHA256": ev.get("sha256", "N/A"),
                "Source": "Cert API (Hostname Events)" if kind == "hostname" else "Cert API (IP Events)",
                "Timestamp": ev.get("event_timestamp") or ev.get("first_seen"),
                "First Seen": ev.get("first_seen"),
                "Last Seen": ev.get("last_seen"),
            })
    return pd.DataFrame(rows)


@dataclass
class SeedResolution:
    """Certificate inputs resolved to the domains and IPs their certificates cover, before the analysis run."""
    seeds: pd.DataFrame
    derived: pd.DataFrame
    statuses: list
    items: list = field(default_factory=list)   # inputs as finally searched (e.g. relabeled as a serial number)
    hits: list = field(default_factory=list)    # full certificate records found, reused by the analysis run
    hostnames: pd.DataFrame = field(default_factory=pd.DataFrame)   # full hostnames found, for the optional hostname focus


SEED_COLUMNS = ["Seed", "Input", "Query", "Certificates", "Observations", "Derived Targets", "Note"]


def _resolve_seed(item, max_certs):
    """(item actually used, search FetchResult, observation FetchResult or None) for one certificate input."""
    search = _safe_call(search_certificates, "Certificate Search", item.label, item.label, seed_query(item), max_certs)
    if item.auto and item.kind == "sha256" and search.ok and not search.data:
        # 64 hex characters can also be a public key hash: retry before giving up
        as_key = InputItem("spki", item.value, auto=True)
        retry = _safe_call(search_certificates, "Certificate Search", as_key.label, as_key.label, seed_query(as_key), max_certs)
        if retry.ok and retry.data:
            item, search = as_key, retry
    if matched_kind(item, search.data) == "serial":   # 32 / 40 hex characters matched a serial number, not a hash
        item = InputItem("serial", item.value, auto=True)
    observations = None
    if item.kind == "sha256":
        observations = _safe_call(fetch_cert_events_sha256, "Cert Events (SHA256)", item.value, item.value,
                                  CERT_SHA256_EVENTS_MAX_RECORDS)
    return item, search, observations


def resolve_seeds(items, max_certs=SEED_MAX_CERTIFICATES, max_selected=SEED_DEFAULT_TARGETS):
    """
    Looks up certificate inputs (Certificate Search, plus SHA-256 observation events for fingerprints) and derives the
    domains and IPs they cover. Nothing is analyzed yet: the caller shows `derived` for selection first.
    """
    log = StatusLog()
    resolved = _parallel(items, lambda item: _resolve_seed(item, max_certs), CERT_API_MAX_WORKERS)
    seed_results, rows = [], []
    for original, (item, search, observations) in zip(items, resolved):
        log.record(search)
        if observations is not None:
            log.record(observations)
        hits, events = search.data or [], (observations.data if observations is not None else None) or []
        seed_results.append((item, hits, events))
        reread = {"spki": "a public key hash", "serial": "a serial number"}.get(item.kind, "")
        note = search.error or (f"Matched as {reread}" if item is not original and reread else "")
        if search.truncated:
            note = f"Stopped at {max_certs} certificates; narrow the input for complete results"
        rows.append({"Seed": item.label, "Input": item.display, "Query": seed_query(item), "Certificates": len(hits),
                     "Observations": len(events), "Note": note})
    derived = derive_targets(seed_results, max_selected)
    all_hits = dedupe_hits(hits for _, hits, _ in seed_results)
    for row, (item, _, _) in zip(rows, seed_results):
        row["Derived Targets"] = int(derived["Seeds"].str.split(", ").map(lambda seeds, label=item.label: label in seeds).sum()) \
            if not derived.empty else 0
    return SeedResolution(pd.DataFrame(rows, columns=SEED_COLUMNS), derived, log.rows,
                          items=[item for item, _, _ in seed_results], hits=all_hits,
                          hostnames=derive_hostnames(seed_results))


MAX_LISTED_ERRORS = 3
CT_SOURCES = ("CT Log Events", "Cert Events (SHA256)")


def _ct_lookup(job):
    source, sha = job
    if source == "CT Log Events":
        return _safe_call(fetch_cert_events_ctl, source, sha, sha)
    return _safe_call(fetch_cert_events_sha256, source, sha, sha, CERT_SHA256_EVENTS_MAX_RECORDS)


def run_with_retry(jobs, lookup, max_workers=CERT_API_MAX_WORKERS, pause=CERT_RETRY_PAUSE_SECONDS, key=None):
    """
    Runs lookups in parallel, then retries failed ones once, sequentially after a pause. Transient HTTP 503 /
    connection errors come from bursts of parallel calls, so the slower second pass usually succeeds.
    Returns ({job: FetchResult}, set of retried jobs).
    """
    results = dict(zip(jobs, _parallel(jobs, lookup, max_workers, key=key)))
    failed = [job for job, result in results.items() if not result.ok]
    if failed:
        progress.note(key, f"retrying {len(failed)} failed lookup(s)")
        time.sleep(pause)
        for job in failed:
            results[job] = lookup(job)
        progress.recovered(key, sum(1 for job in failed if results[job].ok))
    return results, set(failed)


def summarize_lookups(source, results, retried, row_count, log):
    """One summary row per source: how many lookups returned data, were empty, or still failed after the retry."""
    total = len(results)
    failed = [r for r in results if not r.ok]
    empty = sum(1 for r in results if r.ok and not r.record_count)
    with_data = total - len(failed) - empty
    capped = sum(1 for r in results if r.ok and r.truncated)
    for result in failed[:MAX_LISTED_ERRORS]:
        log.record(result)
    if len(failed) > MAX_LISTED_ERRORS:
        log.add(source, f"{len(failed)} certificates", "Error",
                f"{len(failed) - MAX_LISTED_ERRORS} further lookup errors not listed individually")
    if failed and len(failed) == total:
        status = "Error"
    elif failed or capped:
        status = "Partial"
    else:
        status = "OK" if row_count else "No data"
    detail = f"{with_data} with data, {empty} empty (no records exist), {len(failed)} failed"
    if capped:
        detail += f" - {capped} capped at the per-certificate record limit"
    if retried:
        detail += f" - {retried} retried once after a transient error"
    log.add(source, f"{total} certificates", status, detail, row_count)


def ct_hashes(ssl_df):
    """
    Cert API certificate fingerprints in the order the CT / co-occurrence lookups use them: newest (Not Before) first,
    taking turns between domains, so a capped list covers every domain's latest certificates.
    """
    if ssl_df is None or ssl_df.empty or "Source" not in ssl_df.columns:
        return []
    certs = ssl_df[ssl_df["Source"] == "DomainTools Cert API"]
    certs = certs[certs["Hash"].notna() & (certs["Hash"].astype(str).str.strip() != "")]
    if certs.empty:
        return []
    issued = pd.to_datetime(certs["Not Before Date"], errors="coerce") if "Not Before Date" in certs.columns \
        else pd.Series(pd.NaT, index=certs.index)
    domain = certs["Domain"].astype(str) if "Domain" in certs.columns else pd.Series("", index=certs.index)
    ordered = certs.assign(_issued=issued, _domain=domain).sort_values("_issued", ascending=False, na_position="last",
                                                                         kind="stable")
    ordered = ordered.drop_duplicates("Hash")
    ordered = ordered.assign(_turn=ordered.groupby("_domain", sort=False).cumcount())
    return list(ordered.sort_values("_turn", kind="stable")["Hash"])


def collect_ct_telemetry(ssl_df, max_hashes, log):
    """CT log submissions and SHA-256 co-occurrence for Cert API certificates (capped, parallel, one retry pass)."""
    hashes = ct_hashes(ssl_df)
    if not hashes:
        for source in CT_SOURCES:
            log.add(source, "-", "No data", "Skipped - Certificate Search returned no certificates to look up")
        progress.skip("ct", "Nothing to look up: the certificate search found no certificates")
        return pd.DataFrame(), pd.DataFrame()
    if len(hashes) > max_hashes:
        log.add("CT / Co-occurrence", f"{len(hashes)} certificates", "Partial",
                f"Only the {max_hashes} newest certificates (shared across domains) were looked up; raise the cap in the "
                "sidebar for more", max_hashes)
        hashes = hashes[:max_hashes]

    jobs = [(source, h) for h in hashes for source in CT_SOURCES]
    progress.start("ct", len(jobs), f"{len(hashes)} certificate(s), 2 lookups each")
    results, retried_jobs = run_with_retry(jobs, _ct_lookup, key="ct")
    progress.finish("ct", f"{len(hashes)} certificate(s), 2 lookups each")

    ctl_rows, obs_rows = [], []
    for h in hashes:
        for ce in results[("CT Log Events", h)].data or []:
            log_url = ce.get("log_url", "") or ""
            ctl_rows.append({
                "Hash": h,
                "Log URL": log_url,
                "Log Host": log_url.replace("https://", "").replace("http://", "").split("/")[0] if log_url else "Unknown",
                "Timestamp": ce.get("event_timestamp") or ce.get("timestamp"),
            })
        for se in results[("Cert Events (SHA256)", h)].data or []:
            obs_rows.append({
                "Cert_SHA256": h,
                "Observed Domain": se.get("domain", ""),
                "Observed Hostname": se.get("hostname", ""),
                "Observed IP": se.get("ip", ""),
                "Timestamp": se.get("event_timestamp"),
            })
    for source, rows in (("CT Log Events", ctl_rows), ("Cert Events (SHA256)", obs_rows)):
        source_results = [results[(source, h)] for h in hashes]
        retried = sum(1 for h in hashes if (source, h) in retried_jobs)
        summarize_lookups(source, source_results, retried, len(rows), log)
    return pd.DataFrame(ctl_rows), pd.DataFrame(obs_rows)


def select_pivot_ips(domains, pdns, enrichment, max_ips):
    """Picks up to PIVOT_IPS_PER_DOMAIN public, non-CDN IPs per domain (current Iris IPs first, then latest pDNS)."""
    chosen = {}
    ip_rows = explode_ip_events(pdns) if pdns is not None and not pdns.empty else pd.DataFrame()
    for domain in domains:
        candidates = [e["ip"] for e in extract_iris_profile(enrichment.get(domain))["ips"]]
        if not ip_rows.empty:
            dom_rows = ip_rows[ip_rows["Domain"] == domain].copy()
            if not dom_rows.empty:
                dom_rows["_seen"] = pd.to_datetime(dom_rows["Last Seen"], errors="coerce").fillna(dom_rows["Date"])
                candidates += list(dom_rows.sort_values("_seen", ascending=False)["IP"])
        picked = 0
        for ip in dict.fromkeys(candidates):
            if picked >= PIVOT_IPS_PER_DOMAIN:
                break
            if not is_public_ip(ip) or cdn_for_ip(ip):
                continue
            if ip not in chosen and len(chosen) >= max_ips:
                continue  # global budget spent; only already-chosen IPs can still be linked to this domain
            chosen.setdefault(ip, set()).add(domain)
            picked += 1
    return chosen


def collect_ip_pivots(domains, pdns, enrichment, max_ips, log):
    """DNSDB reverse lookups (rdata/ip) on hosting IPs: which other hostnames used them, and when."""
    chosen = select_pivot_ips(domains, pdns, enrichment, max_ips)
    if not chosen:
        progress.skip("pivot", "No public, non-CDN hosting IPs to pivot on")
        return pd.DataFrame()
    ips = list(chosen)
    progress.start("pivot", len(ips))
    results = _record_all(log, _parallel(
        ips, lambda ip: _safe_call(fetch_dnsdb_history, "DNSDB IP Pivot", ip, ip, PIVOT_IP_RECORD_LIMIT), key="pivot"
    ))
    progress.finish("pivot")
    frames = []
    for ip, result in zip(ips, results):
        frame = parse_dnsdb_to_dataframe(result.data, ip)
        if not frame.empty:
            frames.append(pd.DataFrame({
                "IP": ip, "RRName": frame["RRName"], "First Seen": frame["First Seen"], "Last Seen": frame["Last Seen"],
                "Related": ", ".join(sorted(chosen[ip])),
            }))
    return _concat(frames)


def _chase(name, budget=None):
    try:
        return chase_cname(name, CNAME_CHASE_MAX_STEPS, CNAME_CHASE_RECORD_LIMIT, budget)
    except Exception as exc:  # defensive: one failing chase must not abort the others
        error = f"Unexpected error: {type(exc).__name__}: {exc}"[:300]
        return ({"Start": name, "Path": name, "Hops": 0, "Outcome": "Lookup failed", "Final": "",
                 "Final Last Seen": pd.NaT, "Note": error, "Chased At": pd.Timestamp.now("UTC").tz_localize(None),
                 "From Cache": False}, [FetchResult(f"{CHASE_SOURCE} (CNAME)", name, error=error)])


@dataclass
class ChaseRun:
    """Outcome of one chase click: the chases, and what they cost."""
    chases: pd.DataFrame
    queries: int = 0       # DNSDB queries made
    cached: int = 0        # lookups served from the cache (free)
    left: int = 0          # names not reached because their domain's query budget ran out


def chase_cnames(plan, log, max_queries=CNAME_CHASE_QUERIES_PER_DOMAIN, fresh=False):
    """
    DNSDB CNAME chases of `plan` ({domain: [names]}, one exact-name lookup per step): domains in parallel, each
    domain's names in order until it has spent `max_queries` DNSDB queries (cached lookups are free). A chase cut off
    by the budget keeps the path so far (Outcome QUERY_LIMIT); a name never started is left for the next click.
    `fresh`: look every name up again in DNSDB instead of using the cache (a re-chase).
    """
    def run(names):
        budget, done, left = QueryBudget(max_queries), [], 0
        for name in names:
            chase, results = _chase(name, budget)
            if chase["Outcome"] == QUERY_LIMIT and not chase["Hops"]:
                left += 1
                continue
            done.append((chase, results))
        return done, left

    with refreshing() if fresh else nullcontext():
        per_domain = _parallel(list(plan.values()), run)
    chases, queries, cached = [], 0, 0
    for done, _ in per_domain:
        for chase, results in done:
            chases.append(chase)
            for result in results:
                log.record(result)
                hit = FROM_CACHE in str(result.note or "")
                cached, queries = cached + hit, queries + (not hit)
    return ChaseRun(pd.DataFrame(chases, columns=CHASE_COLUMNS), queries, cached, sum(left for _, left in per_domain))


def restore_cached_chases(collected, log=None):
    """
    Replays every chase whose DNSDB lookups are still in the lookup cache, so a new run or a loaded dataset shows the
    chains chased before (From cache, Chased at) without any query: chases with a budget of 0 queries, which may only
    use cached lookups. Partial ones keep the path the cache knows. Merged into `collected.cname_chases` (the newest
    chase of a name wins); returns how many chases were restored.
    """
    plan = chase_plan(build_cname_map(collected.pdns, collected.cname_chases))
    if not plan:
        return 0
    run = chase_cnames(plan, StatusLog(), max_queries=0)
    if run.chases.empty:
        return 0
    collected.cname_chases = merge_chases(collected.cname_chases, run.chases)
    if log is not None:
        log.add(CHASE_SOURCE, f"{len(run.chases)} name(s)", "OK",
                f"Restored {len(run.chases)} CNAME chase(s) from the lookup cache ({run.cached} cached lookups, no "
                "query)", len(run.chases))
    return len(run.chases)


RESOLVE_SOURCE = "DNSDB Resolve"


@dataclass
class ResolveRun:
    """Outcome of one Resolve click: the lookups (core.resolver.LOOKUP_COLUMNS, old and new), and what they cost."""
    lookups: pd.DataFrame
    queries: int = 0       # DNSDB queries made
    cached: int = 0        # lookups served from the cache (free)
    left: int = 0          # names still to look up when the budget ran out
    looked: int = 0        # names looked up by this click
    discovered: int = 0    # domains whose current tree was discovered by this click
    cut_off: int = 0       # of those, discoveries still cut off at the record limit


def tree_since(now=None, days=RESOLVE_TREE_DAYS):
    """Epoch seconds `days` before today (UTC midnight, so a day's discoveries share their cache entries)."""
    today = (now or pd.Timestamp.now("UTC")).normalize()
    return int((today - pd.Timedelta(days=days)).timestamp())


def discover_trees(domains, log, max_queries, fresh=False, since=None):
    """
    The current DNS tree of each domain, as DNSDB knows it: `*.domain` (every record type) last seen within
    RESOLVE_TREE_DAYS. A busy domain's main passive DNS lookup is cut off at its limit, mostly by old records, and
    misses current names; this time-fenced lookup does not. When it is still cut off, one lookup per record type
    follows. Returns (lookup rows with a discovery_marker per domain, queries, cached lookups).
    """
    since = since or tree_since()
    is_cached = getattr(fetch_dnsdb_history, "is_cached", lambda *args: False)
    rows, queries, cached = [], 0, 0

    def fetch(domain, rrtype):
        nonlocal queries, cached
        if queries >= max_queries and (fresh or not is_cached(domain, RESOLVE_TREE_LIMIT, rrtype, True, since)):
            return None
        result = replace(fetch_dnsdb_history(domain, RESOLVE_TREE_LIMIT, rrtype, True, since), source=RESOLVE_SOURCE)
        log.record(result)
        hit = FROM_CACHE in str(result.note or "")
        cached, queries = cached + hit, queries + (not hit)
        return result

    for domain in domains:
        result = fetch(domain, "ANY")
        if result is None:
            break
        if not result.ok:
            continue
        when = pd.to_datetime(result.cached_at if result.cached_at is not None else time.time(), unit="s")
        complete = not result.truncated
        found = lookup_rows(domain, result.data, when, result.cached_at is not None, lookup=f"*.{domain}")
        if not complete:      # cut off: one lookup per record type, each with its own limit
            complete = True
            for rrtype in RESOLVE_TYPES:
                part = fetch(domain, rrtype)
                if part is None or not part.ok:
                    complete = False
                    continue
                complete = complete and not part.truncated
                found += lookup_rows(domain, part.data, when, part.cached_at is not None,
                                     lookup=f"*.{domain}/{rrtype}")
        rows += found + [discovery_marker(domain, complete, when, result.cached_at is not None)]
    return rows, queries, cached


def resolve_tree(pdns, domains, coverage, lookups, log, max_queries=RESOLVE_DEFAULT_QUERIES, fresh=False,
                 max_rounds=10):
    """
    Resolves the DNS tree of `domains` (core.resolver): in rounds, looks up in DNSDB (exact name, every record type)
    the names the tree reaches outside the collected passive DNS (CNAME, MX and NS targets, SPF includes, the domains of
    dead targets), until none is left, `max_rounds` is reached or `max_queries` DNSDB queries are spent; cached
    lookups are free. `fresh`: every name again with fresh DNSDB lookups instead of the cache (a re-resolve).
    """
    current = pd.DataFrame(columns=LOOKUP_COLUMNS) if fresh else lookups
    is_cached = getattr(fetch_dnsdb_history, "is_cached", lambda *args: False)
    queries = cached = looked = left = 0
    done = set()
    with refreshing() if fresh else nullcontext():
        # first the domains' current trees (what a cut-off main lookup missed), then what they point to
        names = [d for d in domains if d and "/" not in str(d) and not is_ip_address(d)]
        todo_trees = [d for d in names if fresh or d not in discovered_domains(current)]
        tree_rows, queries, cached = discover_trees(todo_trees, log, max_queries, fresh)
        trees = pd.DataFrame(tree_rows, columns=LOOKUP_COLUMNS)
        discovered = discovered_domains(trees)
        cut_off = int(((trees["Type"].fillna("") == "") & (trees["Value"] == "cut off")).sum()) if not trees.empty else 0
        if not trees.empty:
            current = merge_lookups(current, trees)
        for _ in range(max_rounds):
            _, todo = build_tree(build_index(pdns, current, coverage, domains), domains)
            todo = [name for name in todo if name not in done]
            free = [] if fresh else [name for name in todo if is_cached(name, RESOLVE_RECORD_LIMIT, "ANY", False)]
            paid = [name for name in todo if name not in free]
            batch = free + paid[:max(0, max_queries - queries)]
            left = len(todo) - len(batch)
            if not batch:
                break
            done.update(batch)
            results = _parallel(batch, lambda name: fetch_dnsdb_history(name, RESOLVE_RECORD_LIMIT, "ANY", False))
            rows = []
            for name, result in zip(batch, results):
                result = replace(result, source=RESOLVE_SOURCE)
                log.record(result)
                hit = FROM_CACHE in str(result.note or "")
                cached, queries = cached + hit, queries + (not hit)
                if not result.ok:
                    continue    # stays "Not resolved yet": the next click tries again
                when = pd.to_datetime(result.cached_at if result.cached_at is not None else time.time(), unit="s")
                rows += lookup_rows(name, result.data, when, hit)
                looked += 1
            current = merge_lookups(current, pd.DataFrame(rows, columns=LOOKUP_COLUMNS))
    if fresh:
        current = merge_lookups(lookups, current)
    return ResolveRun(current.reset_index(drop=True), queries, cached, left, looked, len(discovered), cut_off)


@dataclass
class RoutingRun:
    """Outcome of BGPDB lookups of resolved addresses: their origin rows (core.bgp.ORIGIN_COLUMNS), old and new."""
    origins: pd.DataFrame
    looked: int = 0        # addresses looked up
    cached: int = 0        # lookups served from the cache
    left: int = 0          # addresses not looked up (over the limit, or the host stopped answering)
    stopped: bool = False  # BGPDB did not answer
    raw: pd.DataFrame = None   # the answers as received (core.bgp.RAW_COLUMNS), for Responses and Evidence

    def keep_raw(self, collected, ds=None):
        """Adds the answers to the run's BGPDB answers (the BGP page's Responses, Evidence → BGPDB Responses)."""
        if self.raw is None or self.raw.empty:
            return
        old = getattr(collected, "bgp_raw", None)
        frames = [f for f in (old, self.raw) if f is not None and not f.empty]
        merged = pd.concat(frames, ignore_index=True).drop_duplicates(["Command", "Argument"], keep="last") \
            .reset_index(drop=True)
        collected.bgp_raw = merged
        if ds is not None:
            ds.bgp_raw = merged


def route_ips(ips, existing, log, max_ips=BGPDB_RESOLVE_MAX_IPS, cached_only=False):
    """
    BGPDB `ip` lookups of `ips` (the DNS resolution's addresses): prefix, origin, RPKI / IRR and visibility of each,
    added to `existing` origin rows. `cached_only`: only addresses whose lookup is in the cache (no query). Stops when
    the host does not answer (only reachable on the DomainTools network).
    """
    from core import bgp
    existing = existing if existing is not None and not existing.empty else pd.DataFrame(columns=bgp.ORIGIN_COLUMNS)
    if not bgpdb.load_bgpdb_host() or not ips:
        return RoutingRun(existing, left=len(ips))
    if cached_only:
        is_cached = getattr(bgpdb.lookup_ip, "is_cached", lambda *args: False)
        ips = [ip for ip in ips if is_cached(ip)]
    batch = list(ips)[:max_ips]
    breaker = bgpdb.Breaker()
    results = _parallel(batch, lambda ip: breaker.call(
        lambda *args: _safe_call(bgpdb.lookup_ip, bgpdb.SOURCE, f"ip {ip}", *args), f"ip {ip}", ip))
    rows, raw, looked, cached = [], [], 0, 0
    for ip, result in zip(batch, results):
        if str(result.error or "").startswith("BGPDB stopped"):
            continue
        _bgp_logged(log, raw, result, "ip", ip)
        if not result.ok:
            continue
        looked += 1
        cached += result.cached_at is not None
        # an address BGPDB knows no announcement for keeps an empty row: looked up, nothing announced
        rows += bgp.origin_rows(ip, (), result.data) or [{"IP": ip, "Prefix": "", "Origin": "", "Updates": 0,
                                                          "Collectors": 0}]
    if breaker.tripped:
        log.record(FetchResult(bgpdb.SOURCE, "remaining lookups skipped", error=bgpdb.STOPPED.format(count=breaker.limit)))
    new = pd.DataFrame(rows, columns=bgp.ORIGIN_COLUMNS)
    origins = pd.concat([existing[~existing["IP"].isin(set(new["IP"]))], new], ignore_index=True) \
        if not new.empty else existing
    raw = pd.DataFrame(raw, columns=bgp.RAW_COLUMNS)
    raw["Detail"] = ("DNS resolution · " + raw["Detail"].astype(str)).str.rstrip(" ·")
    return RoutingRun(origins.reset_index(drop=True), looked, cached, len(ips) - looked, breaker.tripped, raw)


def restore_cached_resolutions(collected, log=None):
    """
    Replays the Resolve lookups still in the lookup cache (no query: a budget of 0), so a new run or a loaded dataset
    shows the DNS tree resolved as far as it was before. Returns how many names were restored.
    """
    if collected.pdns is None or collected.pdns.empty:
        return 0
    run = resolve_tree(collected.pdns, list(collected.targets), collected.pdns_coverage, collected.resolutions,
                       StatusLog(), max_queries=0)
    if run.looked:
        collected.resolutions = run.lookups
        if log is not None:
            log.add(RESOLVE_SOURCE, f"{run.looked} name(s)", "OK",
                    f"Restored {run.looked} DNS resolution lookup(s) from the lookup cache (no query)", run.looked)
    return run.looked + restore_cached_routing(collected)


def resolution_ips(collected, coverage=None):
    """The public addresses of the collected data's DNS tree that have no BGPDB routing yet."""
    from core.resolver import routed_set, tree_ips
    tree, _ = build_tree(build_index(collected.pdns, collected.resolutions, coverage or collected.pdns_coverage,
                                     list(collected.targets)), list(collected.targets))
    known = routed_set(getattr(collected, "bgp_origins", None), collected.resolution_routing)
    return [ip for ip in tree_ips(tree) if ip not in known]


def restore_cached_routing(collected):
    """BGPDB routing of the tree's addresses still in the lookup cache (no query); returns how many were restored."""
    ips = resolution_ips(collected)
    if not ips:
        return 0
    run = route_ips(ips, collected.resolution_routing, StatusLog(), cached_only=True)
    if run.looked:
        collected.resolution_routing = run.origins
        run.keep_raw(collected)
    return run.looked


def reverse_cnames(names, analyzed_domains, log):
    """Reverse CNAME lookups (DNSDB rdata/name/{name}/CNAME) of `names`: one RDATA_COLUMNS row per name pointing there."""
    names = list(names)
    results = _record_all(log, _parallel(names, lambda name: fetch_cname_rdata(name, CNAME_RDATA_RECORD_LIMIT)))
    return _concat([rdata_rows(name, result.data, analyzed_domains, result.truncated)
                    for name, result in zip(names, results)])


def _background(executor, func, *args):
    """`func(*args)` in `executor`, with this thread's context (the collection progress tracker) carried over."""
    return executor.submit(contextvars.copy_context().run, func, *args)


def _wait_drawing(futures):
    """Waits for `futures` while this (the drawing) thread keeps the collection progress moving."""
    tracker, pending = progress.current(), set(futures)
    while pending:
        _, pending = wait(pending, timeout=progress.TICK_SECONDS)
        if tracker is not None:
            tracker.tick()
    return [future.result() for future in futures]


KEY_SERVICES = {"iris": "DomainTools API", "history": "DomainTools API", "certs": "Certificate API",
                "events": "Certificate API", "pdns": "DNSDB"}   # stage -> the key it needs


def stages_without_keys():
    """The stages whose service has no API key: they are skipped (no query) until a key is entered."""
    missing = set()
    if not load_dtapi_credentials():
        missing |= {"iris", "history"}
    if not load_cert_api_key():
        missing |= {"certs", "events"}
    if not load_dnsdb_key():
        missing.add("pdns")
    return missing


def rows_without_keys():
    """
    {lookup row (core.use_cases.query_plan Key): why it is skipped} for the services without an API key, so the
    checklist shows them as skipped from the start instead of up next.
    """
    missing, notes = stages_without_keys(), {}
    if "iris" in missing:
        notes.update(dict.fromkeys(("iris", "history"), _no_key_text("iris")))
    if "certs" in missing:
        notes.update(dict.fromkeys(("certs", "ct"), _no_key_text("certs")))
    if "pdns" in missing:
        notes.update(dict.fromkeys(("pdns", "TXT", "CAA", "CNAME", "pivot"), _no_key_text("pdns")))
    if not load_vpndb_key():
        notes["vpndb"] = "Skipped: no VPNDB key (Settings → API credentials)"
    if not bgpdb.load_bgpdb_host():
        notes["bgpdb"] = "Skipped: no BGPDB host (Settings → API credentials)"
    return notes


def _skip_rows(rows, note):
    """Marks lookup rows skipped (collect_all's `progress` argument hides the progress module there)."""
    for row in rows:
        progress.skip(row, note)


def _no_key_text(stage):
    return f"Skipped: no {KEY_SERVICES[stage]} key (Settings → API credentials)"


def _skip_stage(stage, targets, log, row=None):
    """Logs that `stage` was skipped: no API key for its service, or the account does not have its product."""
    where = ", ".join(targets[:3]) + (" ..." if len(targets) > 3 else "")
    if stage in stages_without_keys():
        log.add(STAGE_NAMES[stage], where, "No data", _no_key_text(stage))
        if row:
            progress.skip(row, _no_key_text(stage))
        return
    products = " or ".join(STAGE_PRODUCTS[stage])
    log.add(STAGE_NAMES[stage], where, "No data",
            f"Skipped: the DomainTools account has no {products} product (see the Account page)")
    if row:
        progress.skip(row, "Skipped: not in this DomainTools account")


def _certificate_stage(lookup_inputs, domains, ip_targets, seed_hits, host_focus, unavailable):
    """Certificate search, then certificate events: one after the other, since the Certificate API answers too many
    parallel calls with HTTP 503. Returns (ssl frame, events frame, StatusLog)."""
    log = StatusLog()
    ssl = pd.DataFrame()
    if "certs" in unavailable:
        _skip_stage("certs", lookup_inputs, log)
    else:
        ssl = collect_certificates(lookup_inputs, log, seed_hits, host_focus)
    if "events" in unavailable:
        _skip_stage("events", domains + ip_targets, log)
        events = pd.DataFrame()
    else:
        events = collect_cert_events(domains, ip_targets, log, host_focus)
    if "certs" in unavailable and "events" in unavailable:
        progress.skip("certs", _no_key_text("certs") if "certs" in stages_without_keys()
                      else "Skipped: not in this DomainTools account")
    return ssl, events, log


TARGET_DOMAIN_COLUMNS = ["Target", "Domain", "Risk Score", "Active", "Create Date", "Registrar", "IPs", "ASNs",
                         "Name Servers"]


def collect_target_domains(targets, log, max_results=TARGET_IRIS_DOMAINS):
    """
    Iris Investigate's reverse lookup of the IP and CIDR targets: the domains whose current IPs are the address
    (`ip matches`) or in the range (its first to last address), up to `max_results` per target, riskiest first. One
    IrisQL search per target. Returns TARGET_DOMAIN_COLUMNS rows.
    """
    from core.irisql import TOO_MANY, domain_frame, similar_query

    frames = []
    results = _parallel(targets, lambda t: _safe_call(fetch_irisql, "Iris Investigate (domains on target)", t,
                                                      similar_query(t), max_results, "risk_score"))
    for target, result in zip(targets, results):
        result = replace(result, source="Iris Investigate (domains on target)", target=target)
        if TOO_MANY in str(result.error or ""):
            result.error = (f"Iris matches more than 10,000 domains in {target}, so it returns none: search a smaller "
                            "range, or open it in IrisQL and narrow the query (e.g. created in the last 30 days)")
        log.record(result)
        frame = domain_frame(result.data or [])
        if not frame.empty:
            frames.append(frame.assign(Target=target))
    if not frames:
        return pd.DataFrame(columns=TARGET_DOMAIN_COLUMNS)
    return pd.concat(frames, ignore_index=True).reindex(columns=TARGET_DOMAIN_COLUMNS)


def _target_domain_stage(targets, unavailable):
    log = StatusLog()
    if "iris" in unavailable:
        _skip_stage("iris", targets, log)
        return pd.DataFrame(columns=TARGET_DOMAIN_COLUMNS), log
    return collect_target_domains(targets, log), log


def _history_stage(domains, history_days, history_max, unavailable):
    log = StatusLog()
    if "history" in unavailable:
        _skip_stage("history", domains, log, "history")
        return pd.DataFrame(), pd.DataFrame(), log
    return (*collect_domain_history(domains, log, history_days, history_max), log)


def _iris_stage(domains, unavailable):
    log = StatusLog()
    if "iris" in unavailable:
        _skip_stage("iris", domains, log, "iris")
        return {}, log
    return collect_enrichment(domains, log), log


def collect_all(target_inputs, dnsdb_limit, include_ct=True, ct_max_hashes=CT_LOOKUP_DEFAULT_MAX_HASHES,
                progress=None, pivot_ips=False, pivot_max_ips=10, txt_records=0, caa_lookup=False,
                seed_hits=None, host_focus=None, cname_lookup=False, vpndb_check=False, vpndb_only=False,
                vpndb_max_ips=VPNDB_MAX_IPS, vpndb_details=VPNDB_DETAIL_MAX, vpndb_context=True, history_days=0,
                history_max=DOMAIN_HISTORY_MAX_CHANGES, pdns_base=None, unavailable=(), bgp_check=False,
                bgp_max_ips=BGPDB_MAX_IPS, bgp_context=True):
    """
    Runs every collection stage and returns CollectedData. `progress(label)` is called from the calling thread.
    Every domain is looked up in full (all subdomains). `host_focus` ({apex: [hostnames]}) is kept for the views'
    hostname focus, and its hostnames are looked up on their own only where an apex lookup stopped at its limit.
    CNAME chains are chased later, on demand, from the CNAME Chains lens (chase_cnames).

    Stages that do not need each other run at the same time: Domain History, Iris Investigate (with the risk scores)
    and the certificates (search, then events) in worker threads while this thread collects passive DNS (DNSDB Scout); then the CT telemetry (needs the certificates) runs while this thread pivots on IPs and
    checks VPNDB (both need passive DNS and Iris). `history_days` > 0 keeps only that many days of Domain History
    changes, and `history_max` caps them per domain (0: no cap); `pdns_base` (see collect_pdns) makes DNSDB fetch only what is new since an earlier dataset;
    `unavailable` names stages (STAGE_PRODUCTS) whose product the account does not have, which are skipped.
    """
    def step(label):
        if progress:
            progress(label)

    log = StatusLog()
    no_key = stages_without_keys()   # services without an API key are not queried
    unavailable = set(unavailable or ()) | no_key
    classified = classify_targets(target_inputs)
    domains, cidrs = classified["domains"], classified["cidrs"]
    ip_targets = [t for t in target_inputs if is_ip_address(t)]
    lookup_inputs = [t for t in target_inputs if not is_cidr(t)] + cidrs   # ranges: passive DNS and certificates too
    host_focus = {d: list(hosts) for d, hosts in (host_focus or {}).items() if d in domains and hosts}
    data = CollectedData(targets=list(target_inputs), domain_targets=domains,
                         host_focus=host_focus, dnsdb_limit=dnsdb_limit)

    if vpndb_only:   # IP check use case: no other source
        step("Checking IP addresses in VPNDB...")
        if domains:
            log.add(VPNDB_SOURCE, ", ".join(domains[:3]) + (" ..." if len(domains) > 3 else ""), "No data",
                    f"{len(domains)} domain target(s) skipped: the IP check looks up IP addresses only")
        data.anonymizers = collect_ip_check(ip_targets, log, vpndb_details) if ip_targets or not cidrs \
            else pd.DataFrame()
        data.prefixes, data.prefix_addresses, data.range_ips = collect_prefixes(cidrs, log)
        data.tor_overview = collect_tor_overview(log)
        data.statuses = log.rows
        data.vpndb_raw = vpndb_raw_frame(log.raw)
        return data

    if cidrs and not vpndb_check:
        log.add(VPNDB_SOURCE, ", ".join(cidrs[:3]), "No data", "CIDR ranges are not checked in VPNDB: turn on "
                "Check hosting IPs for VPN, residential proxy and Tor (Settings → Collection options)")
    address_targets = ip_targets + cidrs   # Iris: the domains on each address and range

    step("Collecting Domain History, Iris Investigate, certificates and passive DNS at the same time...")
    with ThreadPoolExecutor(max_workers=4) as executor:
        history = _background(executor, _history_stage, domains, history_days, history_max, unavailable)
        on_targets = _background(executor, _target_domain_stage, address_targets, unavailable) \
            if address_targets else None
        iris = _background(executor, _iris_stage, domains, unavailable)
        certs = _background(executor, _certificate_stage, lookup_inputs, domains, ip_targets, seed_hits, host_focus,
                            unavailable)
        pdns_log = StatusLog()
        if "pdns" in no_key:
            pdns_log.add("DNSDB Scout", ", ".join(lookup_inputs[:3]) + (" ..." if len(lookup_inputs) > 3 else ""),
                         "No data", _no_key_text("pdns"))
            _skip_rows(("pdns", "TXT", "CAA", "CNAME", "pivot"), _no_key_text("pdns"))
            data.pdns, data.pdns_coverage = pd.DataFrame(), {}
        else:
            data.pdns, data.pdns_coverage = collect_pdns(lookup_inputs, dnsdb_limit, pdns_log, txt_records,
                                                         caa_lookup, cname_lookup, pdns_base)
        if host_focus and "pdns" not in no_key:
            data.pdns = fill_pdns_gaps(data.pdns, data.pdns_coverage, host_focus, dnsdb_limit, pdns_log)
        step("Waiting for Domain History, Iris Investigate and certificates...")
        (dh, dh_ssl, history_log), (data.enrichment, iris_log), (cert_ssl, cert_events, cert_log) = _wait_drawing(
            [history, iris, certs])
        target_log = StatusLog()
        if on_targets is not None:
            [(data.target_domains, target_log)] = _wait_drawing([on_targets])
    for part in (history_log, iris_log, target_log, cert_log, pdns_log):   # status rows in a fixed order, whatever finished first
        log.rows.extend(part.rows)
    data.dh = dh
    data.ssl = _concat([dh_ssl, cert_ssl])
    data.cert_hostnames = cert_events
    data.risk = risk_from_iris({d: data.enrichment[d] for d in domains if d in data.enrichment})
    data.ssl_active = extract_ssl_data_from_enrichment(data.enrichment)

    with ThreadPoolExecutor(max_workers=1) as executor:
        ct_log = StatusLog()
        ct = _background(executor, collect_ct_telemetry, data.ssl, ct_max_hashes, ct_log) \
            if include_ct and "events" not in unavailable else None
        if pivot_ips and "pdns" not in no_key:
            step("Pivoting on hosting IPs (DNSDB reverse lookups)...")
            data.ip_pivots = collect_ip_pivots(domains, data.pdns, data.enrichment, pivot_max_ips, log)
        if vpndb_check:
            step("Checking hosting IPs for VPN, proxy and Tor (VPNDB)...")
            data.anonymizers = collect_anonymizers(domains, ip_targets, data.pdns, data.enrichment, log, vpndb_max_ips,
                                                   vpndb_details)
            data.exit_weeks, data.neighbour_ranges, data.hosting_asns, data.exit_neighbours = collect_anonymizer_context(
                data.anonymizers, domains, data.enrichment, log, vpndb_details, vpndb_context)
            data.tor_overview = collect_tor_overview(log)
            data.prefixes, data.prefix_addresses, data.range_ips = collect_prefixes(cidrs, log)
        if bgp_check:
            step("Looking up BGP routing of the hosting IPs (BGPDB)...")
            (data.bgp_origins, data.bgp_asns, data.bgp_routes, data.bgp_neighbours,
             data.bgp_raw) = collect_bgp(domains, ip_targets, data.pdns, data.enrichment, log, bgp_max_ips, bgp_context,
                                         cidr_targets=cidrs)
        if ct is not None:
            step("Fetching CT log and certificate co-occurrence telemetry...")
            [(data.ctl, data.cert_observations)] = _wait_drawing([ct])
            log.rows.extend(ct_log.rows)

    data.statuses = log.rows
    data.vpndb_raw = vpndb_raw_frame(log.raw)
    return data

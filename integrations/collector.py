"""Orchestrates all data collection for an analysis run (parallel where safe) and records per-source status."""
import contextvars
import ipaddress
import json
import queue
import time
from concurrent.futures import ThreadPoolExecutor, wait
from contextlib import nullcontext
from dataclasses import dataclass, field, replace

import pandas as pd

from config import (
    CAA_SUPPLEMENT_FETCH_LIMIT,
    CERT_API_MAX_WORKERS,
    CERT_RETRY_PAUSE_SECONDS,
    CERT_SHA256_EVENTS_MAX_RECORDS,
    CIDR_ADDRESSES_PER_RANGE,
    CIDR_IP_CHECK_MAX,
    CIDR_IP_CHECK_TOTAL,
    CIDR_MAX_RANGES,
    CNAME_CHASE_MAX_STEPS,
    CNAME_CHASE_QUERIES_PER_DOMAIN,
    CNAME_CHASE_RECORD_LIMIT,
    CNAME_RDATA_RECORD_LIMIT,
    CNAME_SUPPLEMENT_FETCH_LIMIT,
    CT_LOOKUP_DEFAULT_MAX_HASHES,
    DOMAIN_HISTORY_MAX_CHANGES,
    IP_CHECK_MAX_IPS,
    MAX_WORKERS,
    PIVOT_IP_RECORD_LIMIT,
    PIVOT_IPS_PER_DOMAIN,
    SEED_DEFAULT_TARGETS,
    SEED_MAX_CERTIFICATES,
    TXT_SUPPLEMENT_FETCH_LIMIT,
    VPNDB_ASN_MAX,
    VPNDB_DETAIL_MAX,
    VPNDB_HISTORY_MAX,
    VPNDB_IPS_PER_DOMAIN,
    VPNDB_MAX_IPS,
    VPNDB_NEIGHBOUR_MAX,
    VPNDB_REVERSE_LIMIT,
    VPNDB_REVERSE_MAX,
)
from core import anonymizers
from core.account import STAGE_NAMES, STAGE_PRODUCTS
from core.cert_inputs import InputItem, derive_hostnames, derive_targets, hostname_search_query, matched_kind, seed_query
from core.cname import CHASE_COLUMNS, QUERY_LIMIT, build_cname_map, chase_plan, merge_chases, rdata_rows
from core.helpers import classify_targets, is_cidr, is_ip_address
from core.network_intel import cdn_for_ip, explode_ip_events, is_public_ip
from core.pdns_features import add_event_gaps
from integrations import progress
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
from integrations.credentials import load_dnsdb_key
from integrations.dnsdb import (
    CHASE_SOURCE,
    QueryBudget,
    chase_cname,
    fetch_cname_rdata,
    fetch_dnsdb_history,
    parse_dnsdb_to_dataframe,
)
from integrations.domain_history import extract_ssl_data, fetch_domain_history, parse_history_to_dataframe
from integrations.enrichment import extract_iris_profile, extract_ssl_data_from_enrichment, fetch_iris_batch, iris_batches
from integrations.http import FetchResult, StatusLog
from integrations.iris import fetch_iris_pdns_many, parse_iris_json_to_dataframe
from integrations.risk import risk_from_iris
from integrations.vpndb import SOURCE as VPNDB_SOURCE
from integrations.vpndb import (
    bulk_lookup,
    ip_history,
    load_vpndb_key,
    lookup_asn,
    lookup_ip,
    lookup_prefix,
    prefix_addresses,
    tor_overview,
)


@dataclass
class CollectedData:
    targets: list = field(default_factory=list)
    domain_targets: list = field(default_factory=list)
    pdns_provider: str = ""
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


def _safe_call(func, source, target, *args, **kwargs):
    """Runs a fetcher, converting unexpected exceptions into an error FetchResult."""
    try:
        return func(*args, **kwargs)
    except Exception as exc:  # defensive: one failing lookup must not abort the whole run
        return FetchResult(source, str(target), error=f"Unexpected error: {type(exc).__name__}: {exc}"[:300])


def _parallel(items, func, max_workers=MAX_WORKERS, key=None):
    """
    Ordered parallel map for I/O-bound fetchers. With `key`, each lookup is counted on that row of the current
    collection progress, which this (the calling) thread redraws while it waits.
    """
    if not items:
        return []
    func, tracker = progress.counted(key, func), progress.current()
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(items)))) as executor:
        futures = [executor.submit(func, item) for item in items]
        pending = set(futures)
        while pending and tracker is not None:
            _, pending = wait(pending, timeout=progress.TICK_SECONDS)
            tracker.tick()
        return [future.result() for future in futures]


def _with_clock(func, item, events=None, handlers=None):
    """
    func(item) in a worker thread while this (the drawing) thread keeps redrawing the collection progress, so the
    elapsed times keep moving during one long lookup. UI callbacks the worker queued on `events` as (name, args) run
    here with `handlers[name]`, because Streamlit elements must not be drawn from worker threads.
    """
    tracker = progress.current()

    def relay():
        while events is not None and not events.empty():
            name, args = events.get_nowait()
            handlers[name](*args)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(func, item)
        while True:
            done, _ = wait([future], timeout=progress.TICK_SECONDS)
            relay()
            if tracker is not None:
                tracker.tick()
            if done:
                return future.result()


def _concat(frames):
    frames = [f for f in frames if f is not None and not f.empty]
    return pd.concat(frames, ignore_index=True) if frames else pd.DataFrame()


def _record_all(log, results):
    for result in results:
        log.record(result)
    return results


def history_since(days, today=None):
    """The ISO date `days` days before today (UTC), or None for all of a domain's history."""
    if not days or days <= 0:
        return None
    today = pd.Timestamp.now(tz="UTC").normalize() if today is None else pd.Timestamp(today)
    return (today - pd.Timedelta(days=int(days))).strftime("%Y-%m-%d")


def history_args(domain, since=None):
    """The arguments a domain's Domain History is fetched (and cached) with."""
    return (domain, DOMAIN_HISTORY_MAX_CHANGES, since) if since else (domain,)


def collect_domain_history(domains, log, days=0):
    """Domain History of each domain; `days` > 0 keeps only the changes of that many days (fewer pages, queries)."""
    since = history_since(days)
    progress.start("history", len(domains), f"changes since {since}" if since else "")
    results = _record_all(log, _parallel(domains, lambda d: _safe_call(fetch_domain_history, "Domain History", d,
                                                                       *history_args(d, since)), key="history"))
    progress.finish("history")
    dh = _concat([parse_history_to_dataframe(r.data, d) for d, r in zip(domains, results)])
    ssl = _concat([extract_ssl_data(r.data, d) for d, r in zip(domains, results)])
    return dh, ssl


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
        return f"{self.rrtype} supplement"


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
        log.add(f"{spec.rrtype} Supplement", f"{frame['Domain'].nunique()} domain(s)", "OK",
                f"Added {added} {spec.rrtype} record(s) not returned by the main query" if added
                else f"All supplemental {spec.rrtype} records were already in the main results", added)
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


def collect_pdns(targets, provider, dnsdb_limit, log, on_auth_required=None, on_auth_done=None, txt_records=0, caa_lookup=False,
                 cname_lookup=False, base=None):
    """
    Main passive DNS query per target plus optional record-type supplements (TXT: latest N per domain; CAA: apex name,
    all records; CNAME: name and subdomains, all records). Large result limits are often filled by A/NS rows before
    TXT, CAA or CNAME records appear; with DNSDB the supplements only run for domains whose main query was cut off
    (Iris runs them in the same session). Returns (pdns_frame, coverage) where coverage maps domain -> {"truncated", "caa_checked"}.
    `base` ({"frame": passive DNS of an earlier dataset of these targets, "created": its ISO time, "name": its name})
    makes DNSDB look up only records seen since a day before that dataset and add its older records (incremental);
    targets missing from it are looked up in full.
    """
    domains = [t for t in targets if not is_ip_address(t)]
    specs = supplement_specs(txt_records, caa_lookup, cname_lookup)
    supplements = {spec: [] for spec in specs}
    main_results, caa_results = {}, {}

    if provider == "Iris pDNS":
        frames = []
        extra = tuple(spec.rrtype for spec in specs if not spec.only_if_capped)
        if_capped = tuple(spec.rrtype for spec in specs if spec.only_if_capped)
        progress.start("pdns", len(targets), "session check, then several targets at a time")
        # In a worker thread so the progress clock keeps running; the login prompt callbacks are relayed back to this
        # thread (Streamlit elements are drawn here only)
        events, handlers = queue.Queue(), {"required": on_auth_required, "done": on_auth_done}
        required = (lambda t: events.put(("required", (t,)))) if on_auth_required else None
        done = (lambda: events.put(("done", ()))) if on_auth_done else None
        tracker = progress.current()

        def finished(target, result):
            if tracker is not None:
                tracker.begin("pdns")
                tracker.advance("pdns", result)

        def fetch_all(items):
            try:
                return fetch_iris_pdns_many(items, required, done, extra, if_capped, on_result=finished)
            except Exception as exc:  # defensive: a browser failure must not abort the whole run
                return {"__error__": f"Unexpected error: {type(exc).__name__}: {exc}"[:300]}

        fetched = _with_clock(fetch_all, list(targets), events, handlers)
        failure = fetched.pop("__error__", "Not looked up")
        for target in targets:
            result = log.record(fetched.get(target) or FetchResult("Iris pDNS", target, data=[], error=failure))
            main_results[target] = [result]
            frames.append(parse_iris_json_to_dataframe(result.data, target))
            for spec in specs:
                extra_result = result.extras.get(spec.rrtype)
                if extra_result is not None:
                    row = "CNAME" if spec.only_if_capped else "extra"
                    progress.start(row, 1)
                    progress.counted(row, lambda r: r)(extra_result)
                    supplements[spec].append(_apply_spec(spec, parse_iris_json_to_dataframe(extra_result.data, target), extra_result, log))
                    if spec.rrtype == "CAA":
                        caa_results[target] = extra_result
        pdns = _concat(frames)
        progress.finish("pdns")
        for spec in specs:
            skipped = [d for d in domains if d in main_results and main_results[d][0].ok
                       and spec.rrtype not in main_results[d][0].extras]
            if spec.only_if_capped and skipped:
                log.add(f"Iris pDNS {spec.rrtype} Supplement", f"{len(skipped)} domain(s)", "OK",
                        f"Not needed: the main lookup returned every record, {spec.rrtype} included")
        for row in ("extra", "CNAME"):
            progress.skip(row, "Not needed: the main lookup returned every record")
            progress.finish(row)
    else:
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
                log.add(f"DNSDB {spec.rrtype} Supplement", f"{skipped} domain(s)", "OK",
                        f"Not needed: the main lookup returned every record, {spec.rrtype} included")
            if incomplete:
                progress.start(spec.rrtype, len(incomplete), f"main lookup hit its limit for {len(incomplete)} domain(s)"
                               + (f"; not needed for {skipped}" if skipped else ""))
            else:
                progress.skip(spec.rrtype, f"Not needed: the main lookup returned every record for all {skipped} "
                                           "domain(s)")
            spec_results = _parallel(incomplete, lambda d, spec=spec: _safe_call(
                fetch_dnsdb_history, f"DNSDB {spec.rrtype} Supplement", d, d, spec.fetch_limit, spec.rrtype, spec.include_wildcard),
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


def _vpndb_logged(log, result, endpoint, path, params=None, body=None):
    """Logs a VPNDB lookup with the request it made (Lookup Queries) and keeps its answer (Raw Records)."""
    request = {"method": "POST" if body is not None else "GET", "endpoint": endpoint, "path": path,
               "params": params or {}, "body": body}
    log.record(result, request=request, keep_raw=True)
    return result


def _bulk_logged(log, result, ips):
    return _vpndb_logged(log, result, "/bulk", "/bulk", body={"ips": list(ips)})


def _ip_logged(log, results, ips):
    return [_vpndb_logged(log, r, "/ip/{ip}", f"/ip/{ip}") for ip, r in zip(ips, results)]


def vpndb_raw_frame(rows):
    """VPNDB_RAW_COLUMNS: one row per VPNDB lookup with its request and the answer as received (JSON text)."""
    frame = pd.DataFrame([{
        "Endpoint": (row.get("Request") or {}).get("endpoint", ""), "Target": row["Target"], "Status": row["Status"],
        "Records": row.get("Records", 0), "Detail": row.get("Detail", ""), "Cached At": row.get("Cached At"),
        "Request": json.dumps(row.get("Request") or {}, default=str),
        "Response": json.dumps(row.get("Response"), default=str),
    } for row in rows], columns=VPNDB_RAW_COLUMNS)
    return frame


VPNDB_RAW_COLUMNS = ["Endpoint", "Target", "Status", "Records", "Detail", "Cached At", "Request", "Response"]


def collect_anonymizers(domains, ip_targets, pdns, enrichment, log, max_ips=VPNDB_MAX_IPS,
                        max_details=VPNDB_DETAIL_MAX):
    """
    VPNDB: one bulk request for the run's hosting IPs (core.anonymizers.select_ips), then the full verdict (sharing,
    Tor, evidence) of up to VPNDB_DETAIL_MAX of those it attributes to an anonymizer. Skipped without a VPNDB key.
    """
    if not load_vpndb_key():
        progress.skip("vpndb", "No VPNDB key (Settings → API credentials)")
        return pd.DataFrame()
    candidates = anonymizers.select_ips(domains, pdns, enrichment, ip_targets, max_ips,
                                        min(VPNDB_IPS_PER_DOMAIN, max_ips))
    if not candidates:
        progress.skip("vpndb", "No public IPv4 hosting addresses to check")
        return pd.DataFrame()
    progress.start("vpndb", 1, note=f"{len(candidates)} IP(s) in one bulk request")
    bulk = _parallel([tuple(sorted(candidates))], lambda ips: _safe_call(bulk_lookup, VPNDB_SOURCE, f"{len(ips)} IP(s)", ips),
                     key="vpndb")[0]
    _bulk_logged(log, bulk, sorted(candidates))
    if not bulk.ok or not isinstance(bulk.data, dict):
        progress.finish("vpndb")
        return pd.DataFrame()
    flagged = [r["ip"] for r in bulk.data.get("results", []) if r.get("anonymous") or "TOR" in (r.get("types") or [])]
    flagged = flagged[:max_details]
    details = {}
    if flagged:
        progress.start("vpndb", len(flagged))
        results = _ip_logged(log, _parallel(flagged, lambda ip: _safe_call(lookup_ip, VPNDB_SOURCE, ip, ip),
                                            key="vpndb"), flagged)
        details = {ip: r.data for ip, r in zip(flagged, results) if r.ok and isinstance(r.data, dict)}
    quota = bulk.extras.get("quota", {})
    progress.finish("vpndb", f"{len(flagged)} anonymizer IP(s)" + (f"; quota left {quota['remaining']}"
                                                                   if quota.get("remaining") else ""))
    return anonymizers.build_rows(candidates, bulk.data, details)


def collect_anonymizer_context(table, domains, enrichment, log, max_history=VPNDB_HISTORY_MAX, neighbours=True):
    """
    What the VPNDB verdicts gain from the other sources, after collect_anonymizers: the weekly history of each exit (was
    it an exit while the domain used it?), the /24 around each non-exit hosting IP and the run's Iris ASNs (hosted
    among exits?), and DNSDB's other names on each dedicated exit (leads). Returns (exit_weeks, neighbour_ranges,
    hosting_asns, exit_neighbours).
    """
    empty = (pd.DataFrame(),) * 4
    if table is None or table.empty or not load_vpndb_key():
        return empty
    exits = anonymizers.anonymizer_rows(table)
    history_ips = list(exits["IP"])[:max_history]
    # neighbouring /24s, hosting networks and the other domains on dedicated exits: off in the lighter use cases
    ranges = anonymizers.neighbour_cidrs(table[~table["IP"].isin(set(exits["IP"]))], VPNDB_NEIGHBOUR_MAX) \
        if neighbours else {}
    asns = anonymizers.hosting_asns(enrichment, domains, VPNDB_ASN_MAX) if neighbours else {}
    reverse = list(exits[exits.apply(anonymizers.dedicated_exit, axis=1)]["IP"])[:VPNDB_REVERSE_MAX] \
        if neighbours and not exits.empty else []
    total = len(history_ips) + len(ranges) + len(asns)
    if not total and not reverse:
        return empty
    progress.start("vpndb", total, note="exit history, neighbouring ranges and hosting networks")
    history = [_vpndb_logged(log, r, "/ip/{ip}/history", f"/ip/{ip}/history") for ip, r in zip(history_ips, _parallel(
        history_ips, lambda ip: _safe_call(ip_history, VPNDB_SOURCE, ip, ip), key="vpndb"))]
    range_results = [_vpndb_logged(log, r, "/prefix/{cidr}", f"/prefix/{cidr}") for cidr, r in zip(ranges, _parallel(
        list(ranges), lambda cidr: _safe_call(lookup_prefix, VPNDB_SOURCE, cidr, cidr), key="vpndb"))]
    asn_results = [_vpndb_logged(log, r, "/asn/{asn}", f"/asn/{asn}") for asn, r in zip(asns, _parallel(
        list(asns), lambda asn: _safe_call(lookup_asn, VPNDB_SOURCE, f"AS{asn}", asn), key="vpndb"))]
    progress.finish("vpndb")
    weeks = anonymizers.exit_week_rows({ip: r.data for ip, r in zip(history_ips, history) if r.ok})
    neighbours = anonymizers.neighbour_frame(
        {cidr: r.data for cidr, r in zip(ranges, range_results) if r.ok}, ranges)
    networks = anonymizers.asn_frame({asn: r.data for asn, r in zip(asns, asn_results) if r.ok}, asns)
    names = pd.DataFrame()
    if reverse and load_dnsdb_key():
        progress.start("pivot", len(reverse), note="other names on dedicated VPN / proxy exits")
        results = _record_all(log, _parallel(reverse, lambda ip: _safe_call(
            fetch_dnsdb_history, "DNSDB IP Pivot", ip, ip, VPNDB_REVERSE_LIMIT), key="pivot"))
        progress.finish("pivot")
        names = anonymizers.exit_neighbour_rows(
            {ip: parse_dnsdb_to_dataframe(r.data, ip) for ip, r in zip(reverse, results) if r.ok}, domains)
    return weeks, neighbours, networks, names


def collect_tor_overview(log):
    """VPNDB /tor: exit relays and their share of Tor exit traffic by network, country and prefix. One call, not
    counted against the quota; {} without a key or on an error."""
    if not load_vpndb_key():
        return {}
    result = _vpndb_logged(log, _safe_call(tor_overview, VPNDB_SOURCE, "tor"), "/tor", "/tor")
    return result.data if result.ok and isinstance(result.data, dict) else {}


def collect_ip_check(ips, log, max_details=IP_CHECK_MAX_IPS):
    """
    IP check use case: VPNDB only. One bulk request for every IP target (IPv4 and IPv6: VPNDB answers IPv6 as not
    collected), then the full verdict of each IPv4 target, up to `max_details`.
    """
    ips = list(dict.fromkeys(str(ip) for ip in ips))
    if not load_vpndb_key():
        log.add(VPNDB_SOURCE, ", ".join(ips[:3]) or "-", "Error", "No VPNDB key: add it under Settings → API credentials")
        progress.skip("vpndb", "No VPNDB key (Settings → API credentials)")
        return pd.DataFrame()
    if not ips:
        log.add(VPNDB_SOURCE, "-", "No data", "No IP address among the targets: the IP check looks up IP addresses only")
        progress.skip("vpndb", "No IP address among the targets")
        return pd.DataFrame()
    progress.start("vpndb", 1, note=f"{len(ips)} IP(s) in one bulk request")
    bulk = _parallel([tuple(ips)], lambda batch: _safe_call(bulk_lookup, VPNDB_SOURCE, f"{len(batch)} IP(s)", batch),
                     key="vpndb")[0]
    _bulk_logged(log, bulk, ips)
    if not bulk.ok or not isinstance(bulk.data, dict):
        progress.finish("vpndb")
        return pd.DataFrame()
    detailed = [ip for ip in ips if anonymizers.is_ipv4(ip)][:max_details]
    progress.start("vpndb", len(detailed))
    results = _ip_logged(log, _parallel(detailed, lambda ip: _safe_call(lookup_ip, VPNDB_SOURCE, ip, ip), key="vpndb"),
                         detailed)
    details = {ip: r.data for ip, r in zip(detailed, results) if r.ok and isinstance(r.data, dict)
               and r.data.get("observed") is not False}
    progress.finish("vpndb")
    return anonymizers.build_rows({ip: {ip} for ip in ips}, bulk.data, details)


def _prefix_lookup(cidr):
    """One CIDR: the /prefix verdict, then the addresses VPNDB probing reached in it (IPv4 ranges of /12 or smaller)."""
    verdict = lookup_prefix(cidr)
    results = [verdict]
    network = ipaddress.ip_network(cidr)
    if verdict.ok and (verdict.data or {}).get("observedIps") and network.version == 4 and network.prefixlen >= 12:
        # observed only: interpolated rows restate the range's own providers for every address and use up list quota
        results.append(prefix_addresses(cidr, method="observed", size=CIDR_ADDRESSES_PER_RANGE, max_pages=1))
    return results


def collect_prefixes(cidrs, log):
    """
    CIDR targets, VPNDB only: which providers are inside each range and in what share (/prefix), and the addresses
    probing reached there in the last 30 days (/prefix/{cidr}/addresses), then every address of the IPv4 ranges VPNDB
    knows exits in, one row per IP from one bulk request (range_ips). Returns (prefixes, addresses, range_ips).
    """
    if not cidrs:
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    if not load_vpndb_key():
        log.add(VPNDB_SOURCE, ", ".join(cidrs[:3]), "Error", "No VPNDB key: CIDR ranges are looked up in VPNDB only")
        return pd.DataFrame(), pd.DataFrame(), pd.DataFrame()
    kept = cidrs[:CIDR_MAX_RANGES]
    if len(cidrs) > len(kept):
        log.add(VPNDB_SOURCE, ", ".join(cidrs[len(kept):][:3]), "Partial",
                f"{len(cidrs) - len(kept)} CIDR range(s) over the limit of {CIDR_MAX_RANGES} per run were not looked up")
    progress.start("vpndb", len(kept), note=f"{len(kept)} CIDR range(s)")
    lookups = _parallel(kept, lambda cidr: _safe_call(_prefix_lookup, VPNDB_SOURCE, cidr, cidr), key="vpndb")
    prefixes, addresses = [], []
    for cidr, results in zip(kept, lookups):
        results = results if isinstance(results, list) else [results]   # _safe_call returns one error result
        _vpndb_logged(log, results[0], "/prefix/{cidr}", f"/prefix/{cidr}")
        if len(results) > 1:
            _vpndb_logged(log, results[1], "/prefix/{cidr}/addresses", f"/prefix/{cidr}/addresses",
                          {"method": "observed", "size": CIDR_ADDRESSES_PER_RANGE})
        verdict = results[0]
        note = verdict.error or ("" if FROM_CACHE in str(verdict.note or "") else verdict.note or "")   # VPNDB's note
        prefixes.append(anonymizers.prefix_row(cidr, verdict.data if verdict.ok else None, note))
        if len(results) > 1 and results[1].ok:
            addresses += anonymizers.address_rows(cidr, results[1].data)
    frame = anonymizers.prefix_frame(prefixes)
    range_ips = _check_range_ips(frame, log)
    progress.finish("vpndb")
    return frame, pd.DataFrame(addresses, columns=anonymizers.ADDRESS_COLUMNS), range_ips


def _check_range_ips(prefixes, log):
    """
    Every address of each IPv4 range VPNDB knows exits in (up to CIDR_IP_CHECK_MAX per range, CIDR_IP_CHECK_TOTAL in
    all), in one bulk request: one row per IP, like the IP targets. Ranges with no known exit are not expanded.
    """
    candidates, skipped = {}, []
    for row in prefixes.to_dict("records"):
        network = ipaddress.ip_network(row["CIDR"])
        if network.version != 4 or not row["Known Exits"]:
            continue
        if network.num_addresses > CIDR_IP_CHECK_MAX or len(candidates) + network.num_addresses > CIDR_IP_CHECK_TOTAL:
            skipped.append(row["CIDR"])
            continue
        for ip in network:
            candidates.setdefault(str(ip), set()).add(row["CIDR"])
    if skipped:
        log.add(VPNDB_SOURCE, ", ".join(skipped[:3]), "Partial",
                f"Not checked IP by IP: over {CIDR_IP_CHECK_MAX:,} addresses per range or {CIDR_IP_CHECK_TOTAL:,} per run")
    if not candidates:
        return pd.DataFrame()
    progress.start("vpndb", 1, note=f"{len(candidates):,} range address(es) in one bulk request")
    bulk = _parallel([tuple(candidates)], lambda ips: _safe_call(bulk_lookup, VPNDB_SOURCE, f"{len(ips)} IP(s)", ips),
                     key="vpndb")[0]
    _bulk_logged(log, bulk, candidates)
    if not bulk.ok or not isinstance(bulk.data, dict):
        return pd.DataFrame()
    return anonymizers.build_rows(candidates, bulk.data).rename(columns={"Domains": "CIDR"})


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


def _skip_stage(stage, targets, log, row=None):
    """Logs that `stage` was skipped because the account does not have its product."""
    products = " or ".join(STAGE_PRODUCTS[stage])
    log.add(STAGE_NAMES[stage], ", ".join(targets[:3]) + (" ..." if len(targets) > 3 else ""), "No data",
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
        progress.skip("certs", "Skipped: not in this DomainTools account")
    return ssl, events, log


def _history_stage(domains, history_days, unavailable):
    log = StatusLog()
    if "history" in unavailable:
        _skip_stage("history", domains, log, "history")
        return pd.DataFrame(), pd.DataFrame(), log
    return (*collect_domain_history(domains, log, history_days), log)


def _iris_stage(domains, unavailable):
    log = StatusLog()
    if "iris" in unavailable:
        _skip_stage("iris", domains, log, "iris")
        return {}, log
    return collect_enrichment(domains, log), log


def collect_all(target_inputs, pdns_provider, dnsdb_limit, include_ct=True, ct_max_hashes=CT_LOOKUP_DEFAULT_MAX_HASHES,
                progress=None, on_auth_required=None, on_auth_done=None, pivot_ips=False, pivot_max_ips=10, txt_records=0, caa_lookup=False,
                seed_hits=None, host_focus=None, cname_lookup=False, vpndb_check=False, vpndb_only=False,
                vpndb_max_ips=VPNDB_MAX_IPS, vpndb_details=VPNDB_DETAIL_MAX, vpndb_context=True, history_days=0,
                pdns_base=None, unavailable=()):
    """
    Runs every collection stage and returns CollectedData. `progress(label)` is called from the calling thread.
    Every domain is looked up in full (all subdomains). `host_focus` ({apex: [hostnames]}) is kept for the views'
    hostname focus, and its hostnames are looked up on their own only where an apex lookup stopped at its limit.
    CNAME chains are chased later, on demand, from the CNAME Chains lens (chase_cnames).

    Stages that do not need each other run at the same time: Domain History, Iris Investigate (with the risk scores)
    and the certificates (search, then events) in worker threads while this thread collects passive DNS (its login
    prompt is drawn here); then the CT telemetry (needs the certificates) runs while this thread pivots on IPs and
    checks VPNDB (both need passive DNS and Iris). `history_days` > 0 keeps only that many days of Domain History
    changes; `pdns_base` (see collect_pdns) makes DNSDB fetch only what is new since an earlier dataset;
    `unavailable` names stages (STAGE_PRODUCTS) whose product the account does not have, which are skipped.
    """
    def step(label):
        if progress:
            progress(label)

    log = StatusLog()
    unavailable = set(unavailable or ())
    classified = classify_targets(target_inputs)
    domains, cidrs = classified["domains"], classified["cidrs"]
    lookup_inputs = [t for t in target_inputs if not is_cidr(t)]   # CIDR ranges go to VPNDB only
    ip_targets = [t for t in lookup_inputs if is_ip_address(t)]
    host_focus = {d: list(hosts) for d, hosts in (host_focus or {}).items() if d in domains and hosts}
    data = CollectedData(targets=list(target_inputs), domain_targets=domains, pdns_provider=pdns_provider,
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
        log.add(VPNDB_SOURCE, ", ".join(cidrs[:3]), "No data", "CIDR ranges are looked up in VPNDB only: turn on "
                "Check hosting IPs for VPN, residential proxy and Tor (Settings → Collection options)")
    elif cidrs:
        log.add("Iris, passive DNS, certificates", ", ".join(cidrs[:3]), "No data",
                "CIDR ranges are looked up in VPNDB only; the other sources take single IP addresses")

    step("Collecting Domain History, Iris Investigate, certificates and passive DNS at the same time...")
    with ThreadPoolExecutor(max_workers=3) as executor:
        history = _background(executor, _history_stage, domains, history_days, unavailable)
        iris = _background(executor, _iris_stage, domains, unavailable)
        certs = _background(executor, _certificate_stage, lookup_inputs, domains, ip_targets, seed_hits, host_focus,
                            unavailable)
        pdns_log = StatusLog()
        data.pdns, data.pdns_coverage = collect_pdns(
            lookup_inputs, pdns_provider, dnsdb_limit, pdns_log, on_auth_required, on_auth_done, txt_records, caa_lookup,
            cname_lookup, pdns_base if pdns_provider == "DNSDB Scout" else None,
        )
        if host_focus and pdns_provider == "DNSDB Scout":
            data.pdns = fill_pdns_gaps(data.pdns, data.pdns_coverage, host_focus, dnsdb_limit, pdns_log)
        step("Waiting for Domain History, Iris Investigate and certificates...")
        (dh, dh_ssl, history_log), (data.enrichment, iris_log), (cert_ssl, cert_events, cert_log) = _wait_drawing(
            [history, iris, certs])
    for part in (history_log, iris_log, cert_log, pdns_log):   # status rows in a fixed order, whatever finished first
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
        if pivot_ips:
            if pdns_provider == "DNSDB Scout":
                step("Pivoting on hosting IPs (DNSDB reverse lookups)...")
                data.ip_pivots = collect_ip_pivots(domains, data.pdns, data.enrichment, pivot_max_ips, log)
            else:
                log.add("DNSDB IP Pivot", "-", "Partial", "IP pivots require the DNSDB Scout provider")
        if vpndb_check:
            step("Checking hosting IPs for VPN, proxy and Tor (VPNDB)...")
            data.anonymizers = collect_anonymizers(domains, ip_targets, data.pdns, data.enrichment, log, vpndb_max_ips,
                                                   vpndb_details)
            data.exit_weeks, data.neighbour_ranges, data.hosting_asns, data.exit_neighbours = collect_anonymizer_context(
                data.anonymizers, domains, data.enrichment, log, vpndb_details, vpndb_context)
            data.tor_overview = collect_tor_overview(log)
            data.prefixes, data.prefix_addresses, data.range_ips = collect_prefixes(cidrs, log)
        if ct is not None:
            step("Fetching CT log and certificate co-occurrence telemetry...")
            [(data.ctl, data.cert_observations)] = _wait_drawing([ct])
            log.rows.extend(ct_log.rows)

    data.statuses = log.rows
    data.vpndb_raw = vpndb_raw_frame(log.raw)
    return data

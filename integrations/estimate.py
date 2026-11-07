"""
Cost estimate of the next Analyze: how many API queries each service and DomainTools product would take for these
targets and collection options, leaving out lookups the lookup cache would answer (checked from the cache files'
age, without reading them). A range where the count depends on the answers (pages of a busy domain, supplements
that run only when a lookup hit its limit, VPNDB verdicts of the exits it finds). No API query is made.
"""
import math

from config import (
    CERT_EVENTS_MAX_RECORDS,
    CERT_SEARCH_MAX_RECORDS,
    DOMAIN_HISTORY_MAX_CHANGES,
    VPNDB_ASN_MAX,
    VPNDB_NEIGHBOUR_MAX,
    VPNDB_REVERSE_MAX,
)
from core.api_usage import DNSDB, DOMAINTOOLS, IRIS_WEB, VPNDB
from core.helpers import classify_targets, is_cidr, is_ip_address
from integrations.certificates import PAGE_SIZE as CERT_PAGE_SIZE
from integrations.certificates import build_search_queries, fetch_cert_events_hostname, fetch_cert_events_ip, search_certificates
from integrations.collector import cert_event_jobs, history_args, history_since, supplement_specs
from integrations.dnsdb import fetch_dnsdb_history
from integrations.domain_history import PAGE_SIZE as HISTORY_PAGE_SIZE
from integrations.domain_history import fetch_domain_history
from integrations.enrichment import fetch_iris_batch, iris_batches
from integrations.iris import iris_pdns_lookup, lookup_args

HISTORY_PAGES = math.ceil(DOMAIN_HISTORY_MAX_CHANGES / HISTORY_PAGE_SIZE)
CERT_SEARCH_PAGES = math.ceil(CERT_SEARCH_MAX_RECORDS / CERT_PAGE_SIZE)
CERT_EVENT_PAGES = math.ceil(CERT_EVENTS_MAX_RECORDS / CERT_PAGE_SIZE)


def _row(service, product, lookups, cached, low, high):
    return {"Service": service, "Product": product, "Lookups": lookups, "From cache": cached,
            "Queries (min)": low, "Queries (max)": high}


def estimate_run(targets, settings, unavailable=()):
    """
    Estimate rows (see core.api_usage.compare_estimate) of a run of `targets` (domains, IPs, CIDR ranges) with
    LookupSettings `settings`. Stages in `unavailable` (the account lacks their product) are left out.
    """
    lookup_inputs = [t for t in targets if not is_cidr(t)]
    classified = classify_targets(targets)
    domains, cidrs = classified["domains"], classified["cidrs"]
    ip_targets = [t for t in lookup_inputs if is_ip_address(t)]
    rows = []
    if settings.vpndb_only:
        ips = len(ip_targets)
        return [_row(VPNDB, VPNDB, ips + len(cidrs), 0, ips + len(cidrs),
                     ips + min(ips, settings.vpndb_details) + len(cidrs) * 2)] if ips or cidrs else []

    if domains and "iris" not in unavailable:
        batches = iris_batches(domains)
        cached = sum(fetch_iris_batch.peek(batch) for batch in batches)
        rows.append(_row(DOMAINTOOLS, "iris-investigate", len(batches), cached, len(batches) - cached,
                         len(batches) - cached))
    if domains and "history" not in unavailable:
        since = history_since(settings.history_days)
        cached = sum(fetch_domain_history.peek(*history_args(d, since)) for d in domains)
        todo = len(domains) - cached
        rows.append(_row(DOMAINTOOLS, "domain-history", len(domains), cached, todo, todo * HISTORY_PAGES))
    if lookup_inputs and "certs" not in unavailable:
        queries = build_search_queries(lookup_inputs)
        cached = sum(search_certificates.peek(target, query) for target, query in queries)
        todo = len(queries) - cached
        rows.append(_row(DOMAINTOOLS, "certificate-search", len(queries), cached, todo, todo * CERT_SEARCH_PAGES))
    if lookup_inputs and "events" not in unavailable:
        jobs = cert_event_jobs(domains, ip_targets)
        cached = sum(fetch_cert_events_hostname.peek(name, subdomains) if kind == "hostname"
                     else fetch_cert_events_ip.peek(name) for kind, _, name, subdomains in jobs)
        todo = len(jobs) - cached
        ct = 2 * settings.ct_max_hashes if settings.include_ct else 0
        rows.append(_row(DOMAINTOOLS, "certificate-events", len(jobs) + (settings.ct_max_hashes if ct else 0), cached,
                         todo, todo * CERT_EVENT_PAGES + ct))

    specs = supplement_specs(settings.txt_records, settings.caa_lookup, settings.cname_lookup)
    if lookup_inputs and settings.pdns_provider == "DNSDB Scout":
        cached = sum(fetch_dnsdb_history.peek(t, settings.dnsdb_limit) for t in lookup_inputs)
        todo = len(lookup_inputs) - cached
        per_domain = 1 + sum(1 if spec.rrtype == "CAA" else 2 for spec in specs)   # apex re-query and supplements
        high = todo + len(domains) * per_domain
        if settings.pivot_ips:
            high += settings.pivot_max_ips
        if settings.vpndb_check and settings.vpndb_context:
            high += VPNDB_REVERSE_MAX
        rows.append(_row(DNSDB, DNSDB, len(lookup_inputs), cached, todo, high))
    elif lookup_inputs:
        extra = tuple(spec.rrtype for spec in specs if not spec.only_if_capped)
        capped = tuple(spec.rrtype for spec in specs if spec.only_if_capped)
        args = [lookup_args(t, extra, capped) for t in lookup_inputs]
        todo = [a for a in args if not iris_pdns_lookup.peek(*a)]
        low = sum(1 + len(a[1]) for a in todo)   # the main query and the supplements run in its session
        rows.append(_row(IRIS_WEB, IRIS_WEB, len(args), len(args) - len(todo), low,
                         low + sum(len(a[2]) for a in todo)))
    if settings.vpndb_check:
        high = settings.vpndb_max_ips + 2 * settings.vpndb_details + len(cidrs) * 2
        if settings.vpndb_context:
            high += VPNDB_NEIGHBOUR_MAX + VPNDB_ASN_MAX
        rows.append(_row(VPNDB, VPNDB, len(lookup_inputs) + len(cidrs), 0, len(ip_targets) + len(cidrs), high))
    return rows

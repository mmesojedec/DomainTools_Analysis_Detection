"""DomainTools v1 Certificate Search API, Hostname/IP/SHA256/CTL Events, and X.509 normalization."""
import ipaddress
import json

import pandas as pd

from config import (
    CERT_CTL_LIMIT,
    CERT_EVENTS_LOOKBACK_DAYS,
    CERT_EVENTS_MAX_RECORDS,
    CERT_SEARCH_MAX_RECORDS,
    CERTSQL_DEFAULT_RESULTS,
    CERTSQL_PAGE_SIZE,
)
from core.cert_inputs import domain_search_query
from core.helpers import classify_targets, hostname_matches
from integrations.cache import cached_fetch
from integrations.credentials import CERT_API_MISSING, load_cert_api_key
from integrations.http import FetchResult, describe_exception, describe_http_status, get_session

CERT_API_BASE_URL = "https://api.domaintools.com/v1/certificates"
PAGE_SIZE = 500
REQUEST_TIMEOUT = 30


def _headers(api_key):
    return {"x-api-key": api_key, "accept": "application/json", "Content-Type": "application/json"}


def _post(endpoint_path, payload, api_key):
    """POSTs to a certificate endpoint. Returns (json or None, error or None); 404 means 'no data'."""
    try:
        resp = get_session().post(
            f"{CERT_API_BASE_URL}/{endpoint_path}", headers=_headers(api_key), json=payload, timeout=REQUEST_TIMEOUT
        )
    except Exception as exc:  # network errors, timeouts
        return None, describe_exception(exc)
    if resp.status_code == 404:
        return {}, None
    if not resp.ok:
        return None, describe_http_status(resp.status_code) + _error_message(resp)
    try:
        return resp.json(), None
    except ValueError:
        return None, "Invalid JSON response"


def _error_message(resp):
    """': message' from the API's error body ({"error": {"message"}} or a 422 {"detail": [...]}), or ''."""
    try:
        body = resp.json()
    except ValueError:
        return ""
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict) and error.get("message"):
        return f": {error['message']}"
    if isinstance(error, str) and error:   # e.g. 502 {"error": "The upstream service is currently unavailable."}
        return f": {error}"
    detail = body.get("detail") if isinstance(body, dict) else None
    if isinstance(detail, list):
        return ": " + "; ".join(str(item.get("msg", item)) if isinstance(item, dict) else str(item) for item in detail)
    return f": {detail}" if detail else ""


def build_search_queries(target_inputs):
    """One CertsQL query per target so each target gets its own record budget."""
    classified = classify_targets(target_inputs)
    queries = [(dom, domain_search_query(dom)) for dom in classified["domains"]]
    queries += [(ip4, f'# CertsQL-1.0\nsan_ip_v4 between ["{ip4}", "{ip4}"]\n') for ip4 in classified["ipv4"]]
    queries += [(ip6, f'# CertsQL-1.0\nsan_ip_v6 between ["{ip6}", "{ip6}"]\n') for ip6 in classified["ipv6"]]
    return queries


# ==============================================================================
# CERTIFICATE SEARCH WITH CURSOR PAGINATION
# ==============================================================================

@cached_fetch(group="certs")
def search_certificates(target, query_string, max_records=CERT_SEARCH_MAX_RECORDS):
    """Runs one paginated /v1/certificates/search query (cursor pagination)."""
    api_key = load_cert_api_key()
    if not api_key:
        return FetchResult("Certificate Search", target, data=[], error=CERT_API_MISSING)

    hits, cursor = [], None
    while len(hits) < max_records:
        payload = {"query_string": query_string, "limit": min(PAGE_SIZE, max_records - len(hits))}
        if cursor:
            payload["cursor"] = cursor
        data, error = _post("search", payload, api_key)
        if error:
            return FetchResult("Certificate Search", target, data=hits, error=error, record_count=len(hits))
        page = (data or {}).get("hits", [])
        if not page:
            break
        hits.extend(page)
        cursor = data.get("cursor")
        if not cursor:
            break

    truncated = len(hits) >= max_records and bool(cursor)
    note = f"Stopped at {max_records} certificates" if truncated else None
    if not hits:
        note = "No certificates in the Cert API name this target; SHA256 / CT log lookups are skipped for it"
    return FetchResult("Certificate Search", target, data=hits, truncated=truncated, record_count=len(hits), note=note)


@cached_fetch(group="certs")
def fetch_certsql(query, max_results=CERTSQL_DEFAULT_RESULTS, sort=(), page_size=CERTSQL_PAGE_SIZE):
    """
    A CertsQL page (Certificate Search) followed by cursor until `max_results` certificates or the last page; `sort`
    is (field, order) or (). On an error the pages fetched so far are kept. extras: total (exact through 10,000),
    relation ("eq" or "gte"), pages.
    """
    api_key = load_cert_api_key()
    label = "CertsQL"
    if not api_key:
        return FetchResult("Certificate Search", label, data=[], error=CERT_API_MISSING)
    hits, cursor, pages, total, relation = [], None, 0, 0, "eq"
    while len(hits) < max_results:
        payload = {"query_string": query, "limit": min(page_size, max_results - len(hits))}
        if sort:
            payload["sort"] = [{"field": sort[0], "order": sort[1]}]
        if cursor:
            payload["cursor"] = cursor
        data, error = _post("search", payload, api_key)
        pages += 1
        if error:
            return FetchResult("Certificate Search", label, data=hits, error=error, record_count=len(hits),
                               extras={"total": total, "relation": relation, "pages": pages})
        data = data or {}
        if pages == 1:
            total_info = data.get("total") or {}
            total = int(total_info.get("value") or 0) if isinstance(total_info, dict) else int(total_info or 0)
            relation = total_info.get("relation", "eq") if isinstance(total_info, dict) else "eq"
        page = data.get("hits") or []
        hits.extend(page)
        cursor = data.get("cursor")
        if not page or not cursor:
            cursor = None
            break
    more = bool(cursor) and (relation == "gte" or len(hits) < total)   # a last full page may still carry a cursor
    return FetchResult("Certificate Search", label, data=hits, truncated=more, record_count=len(hits),
                       extras={"total": max(total, len(hits)), "relation": relation, "pages": pages})


def dedupe_hits(hit_lists):
    """Merges hit lists from several queries, keeping the first occurrence of each certificate."""
    seen, merged = set(), []
    for hits in hit_lists:
        for hit in hits or []:
            key = hit.get("sha256") or hit.get("serial_number") or json.dumps(hit, sort_keys=True, default=str)
            if key not in seen:
                seen.add(key)
                merged.append(hit)
    return merged


# ==============================================================================
# CERTIFICATE EVENTS API (HOSTNAME, IP, SHA256 & CTL)
# ==============================================================================

def events_start_time(days=CERT_EVENTS_LOOKBACK_DAYS, now=None):
    """
    Start of the Certificate Events window: `days` before today (UTC midnight, so cached lookups match within a day).
    Without it the API only covers the last 30 days. The end defaults to the request time.
    """
    now = pd.Timestamp(now) if now is not None else pd.Timestamp.now(tz="UTC")
    start = (now.tz_convert("UTC") if now.tzinfo else now).normalize() - pd.Timedelta(days=days)
    return start.strftime("%Y-%m-%dT%H:%M:%S")


def _fetch_paginated_events(source, target, endpoint_path, base_payload, container_key, max_records, empty_note=None):
    """Paginator for /v1/certificates/events/{hostname, ip, sha256} using pagination.next_cursor."""
    base_payload = {"start_time": events_start_time(), **base_payload}   # resent with every cursor page
    api_key = load_cert_api_key()
    if not api_key:
        return FetchResult(source, target, data=[], error=CERT_API_MISSING)

    events, cursor, has_more = [], None, False
    while len(events) < max_records:
        payload = dict(base_payload, limit=min(PAGE_SIZE, max_records - len(events)))
        if cursor:
            payload["cursor"] = cursor
        data, error = _post(endpoint_path, payload, api_key)
        if error:
            return FetchResult(source, target, data=events, error=error, record_count=len(events))
        page = (data or {}).get(container_key, [])
        if not page:
            break
        events.extend(page)
        pagination = data.get("pagination", {})
        has_more = bool(pagination.get("has_more") and pagination.get("next_cursor"))
        if not has_more:
            break
        cursor = pagination["next_cursor"]

    truncated = has_more and len(events) >= max_records
    note = f"Stopped at {max_records} events" if truncated else (None if events else empty_note)
    return FetchResult(source, target, data=events, truncated=truncated, record_count=len(events), note=note)


@cached_fetch(group="certs")
def fetch_cert_events_hostname(hostname, include_subdomains=True, max_records=CERT_EVENTS_MAX_RECORDS):
    """Observed certificate events for a domain/hostname."""
    return _fetch_paginated_events(
        "Cert Events (Hostname)", hostname, "events/hostname",
        {"hostname": hostname, "include_subdomains": include_subdomains}, "events", max_records,
        empty_note="No certificate events observed for this hostname",
    )


@cached_fetch(group="certs")
def fetch_cert_events_ip(ip_address, max_records=CERT_EVENTS_MAX_RECORDS):
    """Observed certificate events for an IPv4 or IPv6 address."""
    ip_clean = str(ip_address).strip()
    return _fetch_paginated_events("Cert Events (IP)", ip_clean, "events/ip", {"ip": ip_clean}, "events", max_records,
                                   empty_note="No certificates observed on this IP")


@cached_fetch(group="certs")
def fetch_cert_events_sha256(sha256_hash, max_records=CERT_EVENTS_MAX_RECORDS):
    """Observed domain/IP connections where a specific certificate SHA256 was seen."""
    sha = str(sha256_hash).strip()
    return _fetch_paginated_events("Cert Events (SHA256)", sha, "events/sha256", {"sha256": sha}, "active_events", max_records,
                                   empty_note="Certificate not observed on any host in the API's recent time window")


@cached_fetch(group="certs")
def fetch_cert_events_ctl(sha256_hash, limit=CERT_CTL_LIMIT):
    """Raw Certificate Transparency log submissions for a certificate fingerprint."""
    sha = str(sha256_hash).strip()
    api_key = load_cert_api_key()
    if not api_key:
        return FetchResult("CT Log Events", sha, data=[], error=CERT_API_MISSING)
    data, error = _post("events/ctl", {"sha256": sha, "limit": limit}, api_key)
    events = (data or {}).get("ctl_events", []) if not error else []
    note = None if error or events else "No CT log submissions recorded for this certificate"
    return FetchResult("CT Log Events", sha, data=events, error=error, record_count=len(events), note=note)


# ==============================================================================
# TARGET MATCHING & X.509 NORMALIZATION
# ==============================================================================

def _as_list(value):
    return value if isinstance(value, list) else []


def match_target_against_hit(tgt, hit):
    """Evaluates whether a target (Domain, IPv4, or IPv6) matches a certificate hit."""
    tgt_clean = str(tgt).strip().lower()
    cn = str(hit.get("subject_common_name") or "").strip().lower()
    try:
        ip_obj = ipaddress.ip_address(tgt_clean)
    except ValueError:
        return any(hostname_matches(tgt_clean, san) for san in _as_list(hit.get("san_dns"))) or hostname_matches(tgt_clean, cn)

    candidates = _as_list(hit.get("san_ip_v4") if ip_obj.version == 4 else hit.get("san_ip_v6")) + [cn]
    for ip_str in candidates:
        try:
            if ipaddress.ip_address(str(ip_str).strip()) == ip_obj:
                return True
        except ValueError:
            continue
    return False


def parse_domaintools_certs(hits, target_inputs):
    """Parses Certificate Search API hits into a normalized DataFrame (one row per matched target)."""
    if not hits:
        return pd.DataFrame()

    ssl_records = []
    for hit in hits:
        san_dns = _as_list(hit.get("san_dns"))
        san_ip_v4 = _as_list(hit.get("san_ip_v4"))
        san_ip_v6 = _as_list(hit.get("san_ip_v6"))
        all_sans = san_dns + san_ip_v4 + san_ip_v6

        subj_dn = str(hit.get("subject_dn") or "").strip().lower()
        iss_dn = str(hit.get("issuer_dn") or "").strip().lower()
        cn = str(hit.get("subject_common_name") or "").strip().lower()
        issuer = str(hit.get("issuer_common_name") or "").strip().lower()
        is_self_signed = bool(hit.get("is_self_signed")) or (bool(subj_dn) and subj_dn == iss_dn) or (bool(cn) and cn == issuer)

        matched_targets = []
        for tgt in target_inputs:
            if tgt not in matched_targets and match_target_against_hit(tgt, hit):
                matched_targets.append(tgt)

        for matched_target in matched_targets:
            ssl_records.append({
                "Domain": matched_target,
                "Source": "DomainTools Cert API",
                "Hash": hit.get("sha256", ""),
                "SHA1": hit.get("sha1", ""),
                "MD5": hit.get("md5", ""),
                "Serial Number": hit.get("serial_number", ""),

                "Common Name": hit.get("subject_common_name", ""),
                "Subject DN": hit.get("subject_dn", ""),
                "Subject Org": hit.get("subject_organization", ""),
                "Subject State/Province": hit.get("subject_state_or_province", ""),
                "Subject Country": hit.get("subject_country", ""),
                "Subject Key ID": hit.get("subject_key_id", ""),

                "Issuer": hit.get("issuer_common_name", ""),
                "Issuer DN": hit.get("issuer_dn", ""),
                "Issuer Org": hit.get("issuer_organization", ""),
                "Issuer OU": hit.get("issuer_organizational_unit", []),
                "Issuer Country": hit.get("issuer_country", ""),
                "Authority Key ID": hit.get("authority_key_id", ""),

                "Timestamp": hit.get("validity_not_before", ""),
                "Not Before": hit.get("validity_not_before", ""),
                "Not After": hit.get("validity_not_after", ""),
                "Duration": hit.get("validity_duration_days", None),
                "Has Embedded SCTs": hit.get("has_embedded_scts"),
                "Signed Certificate Timestamps": hit.get("signed_certificate_timestamp", []),

                "Public Key Algo": hit.get("public_key_algorithm", ""),
                "Public Key Bits": hit.get("public_key_bits", None),
                "Public Key SHA256": hit.get("public_key_sha256", ""),
                "Signature Algo": hit.get("signature_algorithm", ""),
                "Key Usage": hit.get("key_usage", []),
                "Extended Key Usage": hit.get("extended_key_usage", []),
                "Extended Key Usage OIDs": hit.get("extended_key_usage_oids", []),

                "Extension OIDs": hit.get("extension_oids", []),
                "Basic Constraints": hit.get("basic_constraints", {}),
                "Certificate Policy": hit.get("certificate_policy", []),

                "Alt Names List": all_sans,
                "SAN DNS": san_dns,
                "SAN IPv4": san_ip_v4,
                "SAN IPv6": san_ip_v6,
                "SAN Count": hit.get("san_count", len(all_sans)),
                "Has Wildcard SAN": hit.get("has_wildcard_san", False),
                "Validation Level": hit.get("validation_level", "unknown"),
                "Is Self Signed": is_self_signed,
                "Is Precertificate": hit.get("is_precertificate", False),
            })

    df = pd.DataFrame(ssl_records)
    if not df.empty:
        df["Date"] = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True).dt.tz_localize(None)
        df["Not Before Date"] = pd.to_datetime(df["Not Before"], errors="coerce", utc=True).dt.tz_localize(None)
        df["Not After Date"] = pd.to_datetime(df["Not After"], errors="coerce", utc=True).dt.tz_localize(None)
    return df

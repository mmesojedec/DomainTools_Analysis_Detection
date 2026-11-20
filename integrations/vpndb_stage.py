"""
VPNDB collection stage: VPN, residential proxy and Tor verdicts of the run's hosting IPs (one bulk request, then
full verdicts), their weekly history, the ranges and networks around them, the Tor overview, IP targets and CIDR
ranges. Each lookup is logged with the request it made and kept as received.
"""
import ipaddress
import json

import pandas as pd

from config import (
    CIDR_ADDRESSES_PER_RANGE,
    CIDR_IP_CHECK_MAX,
    CIDR_IP_CHECK_TOTAL,
    CIDR_MAX_RANGES,
    IP_CHECK_MAX_IPS,
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
from integrations import progress
from integrations.cache import FROM_CACHE
from integrations.credentials import load_dnsdb_key
from integrations.dnsdb import (
    fetch_dnsdb_history,
    parse_dnsdb_to_dataframe,
)
from integrations.fetch_runner import _parallel, _record_all, _safe_call
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

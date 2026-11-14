"""IP / hosting intelligence: CDN attribution, ASN-aware network keys, hosting watchlist, and origin discovery."""
import functools
import ipaddress

import pandas as pd

from core.helpers import extract_ip_addresses
from core.intel_data import (
    CDN_CNAME_SUFFIXES,
    CDN_IP_RANGES,
    CDN_ISP_MARKERS,
    CLOUDFLARE_NS_SUFFIX,
    HOSTING_WATCHLIST,
    LARGE_DNS_PROVIDER_MARKERS,
    PARKING_NS_MARKERS,
)
from integrations.enrichment import extract_iris_profile

IP_RECORD_TYPES = {"A", "AAAA", "IP", "A RECORD"}


@functools.lru_cache(maxsize=1)
def _cdn_networks():
    return [(name, ipaddress.ip_network(cidr)) for name, cidrs in CDN_IP_RANGES.items() for cidr in cidrs]


@functools.lru_cache(maxsize=1)
def _cdn_index():
    """{IP version: [(prefix length, {network address as int: CDN name}), ...]}: a lookup per prefix length instead of
    a scan of every range (hundreds of them) for each IP. The first provider listed wins where ranges overlap."""
    index = {4: {}, 6: {}}
    for name, network in _cdn_networks():
        index[network.version].setdefault(network.prefixlen, {}).setdefault(int(network.network_address), name)
    return {version: sorted(by_length.items()) for version, by_length in index.items()}


@functools.lru_cache(maxsize=65536)
def _cdn_range(ip):
    """The CDN whose published (or announced) ranges contain `ip`, or None."""
    bits = ip.max_prefixlen
    value = int(ip)
    for length, networks in _cdn_index()[ip.version]:
        name = networks.get(value >> (bits - length) << (bits - length))
        if name:
            return name
    return None


@functools.lru_cache(maxsize=65536)
def _parse_ip(ip_str):
    try:
        return ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return None


def _naive_ts(value):
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    return parsed.tz_localize(None) if pd.notna(parsed) else pd.NaT


def is_public_ip(ip_str):
    ip = _parse_ip(ip_str)
    return ip is not None and ip.is_global


def build_ip_intel(enrichment):
    """Maps IP -> {asn, isp, country, domains} using the IPs Iris reports for each domain."""
    intel = {}
    for domain, obj in (enrichment or {}).items():
        for entry in extract_iris_profile(obj)["ips"]:
            record = intel.setdefault(entry["ip"], {"asn": None, "isp": "", "country": "", "count": None,
                                                    "domains": set()})
            record["count"] = record["count"] or entry.get("count")
            record["asn"] = record["asn"] or entry["asn"]
            record["isp"] = record["isp"] or entry["isp"]
            record["country"] = record["country"] or entry["country"]
            record["domains"].add(domain)
    return intel


def cdn_for_ip(ip_str, ip_intel=None):
    """Returns the CDN name an IP belongs to (published ranges or Iris ISP), or None."""
    ip = _parse_ip(ip_str)
    if ip is None:
        return None
    name = _cdn_range(ip)
    if name:
        return name
    isp = str(((ip_intel or {}).get(str(ip)) or {}).get("isp", "")).lower()
    for marker, name in CDN_ISP_MARKERS.items():
        if marker in isp:
            return name
    return None


def network_key(ip_str, ip_intel=None):
    """ASN when known (from Iris), otherwise the /16 (IPv4) or /32 (IPv6) prefix as an approximation."""
    ip = _parse_ip(ip_str)
    if ip is None:
        return None
    asn = ((ip_intel or {}).get(str(ip)) or {}).get("asn")
    if asn:
        return f"AS{asn}"
    prefix = 16 if ip.version == 4 else 32
    return f"net:{ipaddress.ip_network(f'{ip}/{prefix}', strict=False)}"


def watchlisted_hosting(isp):
    isp_lower = str(isp or "").lower()
    return next((marker for marker in HOSTING_WATCHLIST if marker in isp_lower), None)


def is_parking_ns(host):
    host_lower = str(host or "").lower()
    return any(marker in host_lower for marker in PARKING_NS_MARKERS)


def is_large_dns_provider(host):
    host_lower = str(host or "").lower()
    return any(marker in host_lower for marker in LARGE_DNS_PROVIDER_MARKERS)


def cdn_for_cname(target):
    target_lower = str(target or "").lower().rstrip(".")
    return next((name for suffix, name in CDN_CNAME_SUFFIXES.items() if target_lower.endswith(suffix)), None)


def record_types(events):
    return events["Field"].astype(str).str.upper().str.replace(r"^(?:PDNS|DH):\s*", "", regex=True)


def explode_ip_events(events):
    """One row per (event, IP) for A/AAAA-style records, including multi-value rrsets."""
    if events is None or events.empty or "Field" not in events.columns:
        return pd.DataFrame(columns=["Date", "Last Seen", "RRName", "IP"])
    ip_rows = events[record_types(events).isin(IP_RECORD_TYPES)].copy()
    if ip_rows.empty:
        return pd.DataFrame(columns=["Date", "Last Seen", "RRName", "IP"])
    ip_rows["IP"] = ip_rows["Value"].astype(str).map(extract_ip_addresses)
    ip_rows = ip_rows.explode("IP").dropna(subset=["IP"])
    for col in ("Last Seen", "RRName"):
        if col not in ip_rows.columns:
            ip_rows[col] = pd.NA
    return ip_rows


def cdn_fronting(domain, events, profile, ip_intel):
    """Returns the CDN name a domain appears to be fronted by (current Iris IPs, NS, CNAMEs, or recent A records)."""
    for entry in profile.get("ips", []):
        name = cdn_for_ip(entry["ip"], ip_intel)
        if name:
            return name
    if any(ns.endswith(CLOUDFLARE_NS_SUFFIX) for ns in profile.get("name_servers", [])):
        return "Cloudflare"
    if events is not None and not events.empty:
        cnames = events[record_types(events) == "CNAME"]
        for value in cnames["Value"].astype(str):
            for line in value.split("\n"):
                name = cdn_for_cname(line)
                if name:
                    return name
        ip_rows = explode_ip_events(events)
        if not ip_rows.empty:
            seen = pd.to_datetime(ip_rows["Last Seen"], errors="coerce").fillna(ip_rows["Date"])
            recent = ip_rows[seen >= seen.max() - pd.Timedelta(days=30)]
            names = {cdn_for_ip(ip, ip_intel) for ip in recent["IP"]}
            names.discard(None)
            if len(names) == 1 and recent["IP"].map(lambda ip: cdn_for_ip(ip, ip_intel) is not None).all():
                return names.pop()
    return None


def find_origin_candidates(domain, events, cert_events, ip_intel):
    """Public, non-CDN IPs seen for a CDN-fronted domain in pDNS history or certificate hostname events."""
    rows = []
    ip_rows = explode_ip_events(events)
    for _, row in ip_rows.iterrows():
        ip = row["IP"]
        if is_public_ip(ip) and not cdn_for_ip(ip, ip_intel):
            rows.append({"IP": ip, "Hostname": row.get("RRName") or domain, "Source": "Passive DNS",
                         "First Seen": row.get("Date"), "Last Seen": row.get("Last Seen")})
    if cert_events is not None and not cert_events.empty and "IP" in cert_events.columns:
        for _, row in cert_events.iterrows():
            ip = str(row.get("IP") or "").strip()
            if is_public_ip(ip) and not cdn_for_ip(ip, ip_intel):
                rows.append({"IP": ip, "Hostname": row.get("Hostname") or domain, "Source": "Cert Hostname Events",
                             "First Seen": _naive_ts(row.get("Timestamp")), "Last Seen": pd.NaT})
    if not rows:
        return pd.DataFrame(columns=["IP", "Hostnames", "Sources", "First Seen", "Last Seen"])
    frame = pd.DataFrame(rows)
    frame["First Seen"] = pd.to_datetime(frame["First Seen"], errors="coerce")
    frame["Last Seen"] = pd.to_datetime(frame["Last Seen"], errors="coerce")
    return frame.groupby("IP").agg(
        Hostnames=("Hostname", lambda x: ", ".join(sorted({str(v) for v in x if pd.notna(v)}))[:200]),
        Sources=("Source", lambda x: ", ".join(sorted(set(x)))),
        **{"First Seen": ("First Seen", "min"), "Last Seen": ("Last Seen", "max")},
    ).reset_index().sort_values("Last Seen", ascending=False, na_position="last")

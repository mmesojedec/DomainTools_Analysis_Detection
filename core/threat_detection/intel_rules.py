"""Intel-driven rules: registration age, hosting, redirects, parking, ASN-aware flux, volume anomalies, origin exposure, lookalikes."""
from collections import Counter

import pandas as pd

from core.helpers import registrable_domain
from core.lookalike import analyze_lookalike
from core.network_intel import (
    cdn_for_ip,
    cdn_fronting,
    explode_ip_events,
    find_origin_candidates,
    is_parking_ns,
    network_key,
    record_types,
    watchlisted_hosting,
)
from core.threat_detection.context import MAX_IOC_LINES, evidence_record, fmt_ts

NS_FIELDS = {"NS", "NAME_SERVER"}
ACTIVATION_FIELDS = {"A", "AAAA", "IP", "A RECORD", "MX"}


def rule_newly_registered(ctx):
    created = ctx.profile.get("create_date")
    if ctx.is_ip or created is None or pd.isna(created):
        return
    age_days = (ctx.now - created).total_seconds() / 86400.0
    if age_days < 0 or age_days > ctx.thresholds["nrd_days"]:
        return
    evidence = []
    if not ctx.ssl.empty and "Not Before Date" in ctx.ssl.columns:
        issued = pd.to_datetime(ctx.ssl["Not Before Date"], errors="coerce")
        fresh = issued[issued >= created - pd.Timedelta(days=1)]
        if not fresh.empty:
            evidence.append(f"Certificate issued {fmt_ts(fresh.min())}")
    if not ctx.events.empty:
        ip_events = explode_ip_events(ctx.events)
        live = ip_events[ip_events["Date"] >= created - pd.Timedelta(days=1)]
        if not live.empty:
            evidence.append(f"DNS resolving since {fmt_ts(live['Date'].min())} ({live['IP'].nunique()} IPs)")
    iocs = f"Created: {fmt_ts(created, '%Y-%m-%d')}\nAge: {int(age_days)} days\nRegistrar: {ctx.profile.get('registrar') or 'N/A'}"
    if evidence:
        ctx.add(
            "Newly Registered & Weaponized Domain", "High", "T1583.001 (Acquire Infrastructure: Domains)",
            f"Domain registered {int(age_days)} days ago and already operational: {'; '.join(evidence)}.",
            iocs + "\n" + "\n".join(evidence), flag="nrd",
        )
    else:
        ctx.add(
            "Newly Registered Domain", "Medium", "T1583.001 (Acquire Infrastructure: Domains)",
            f"Domain registered {int(age_days)} days ago (threshold <= {int(ctx.thresholds['nrd_days'])} days).",
            iocs, flag="nrd",
        )


def rule_hosting_watchlist(ctx):
    hits = []
    for entry in ctx.profile.get("ips", []):
        marker = watchlisted_hosting(entry.get("isp"))
        if marker:
            hits.append(f"{entry['ip']} - {entry.get('isp')} (AS{entry.get('asn') or '?'}, {entry.get('country') or '??'})")
    if hits:
        ctx.add(
            "High-Abuse / Offshore Hosting Provider", "Medium-High", "T1583.003 (Acquire Infrastructure: Virtual Private Server)",
            "Domain currently resolves to a hosting provider on the high-abuse / offshore watchlist.",
            "\n".join(hits[:MAX_IOC_LINES]), flag="watchlist_hosting",
        )


def rule_cross_domain_redirect(ctx):
    target = ctx.profile.get("redirect_domain")
    if ctx.is_ip or not target:
        return
    if registrable_domain(target) != registrable_domain(ctx.domain):
        ctx.add(
            "Cross-Domain Redirect", "Medium", "T1608.005 (Stage Capabilities: Link Target)",
            f"Website redirects to a different registrable domain ({target}), a common cloaking / traffic-distribution pattern.",
            f"Domain: {ctx.domain}\nRedirect: {ctx.profile.get('redirect') or target}\nRedirect Domain: {target}",
        )


def _ns_rows(events):
    if events.empty:
        return events
    ns = events[record_types(events).isin(NS_FIELDS)].copy()
    if ns.empty:
        return ns
    ns["NS Host"] = ns["Value"].astype(str).str.split("\n")
    ns = ns.explode("NS Host")
    ns["NS Host"] = ns["NS Host"].str.strip().str.lower().str.rstrip(".")
    ns = ns[ns["NS Host"] != ""]
    ns["Parking"] = ns["NS Host"].map(is_parking_ns)
    ns["Until"] = pd.to_datetime(ns["Last Seen"], errors="coerce").fillna(ns["Date"]) if "Last Seen" in ns.columns else ns["Date"]
    return ns


def rule_parking(ctx):
    """Parked domains (parking name servers) and parked domains that exit parking and go live."""
    if ctx.is_ip:
        return
    current_parking = [ns for ns in ctx.profile.get("name_servers", []) if is_parking_ns(ns)]
    ns = _ns_rows(ctx.events)
    parked_hist = ns[ns["Parking"]] if not ns.empty else ns
    if current_parking or not parked_hist.empty:
        hosts = current_parking or sorted(parked_hist["NS Host"].unique())
        ctx.add(
            "Parked Domain (Parking Name Servers)", "Low", "T1583.001 (Acquire Infrastructure: Domains)",
            "Domain is or was delegated to domain-parking name servers" + (" (currently parked)." if current_parking else " (historically)."),
            "Parking NS: " + ", ".join(hosts[:10]), flag="parked",
        )
    if parked_hist.empty:
        return
    parked_until = parked_hist["Until"].max()
    exits = ns[(~ns["Parking"]) & (ns["Date"] > parked_until)]
    if exits.empty:
        return
    exit_row = exits.sort_values("Date").iloc[0]
    window_end = exit_row["Date"] + pd.Timedelta(days=7)
    activations = ctx.events[record_types(ctx.events).isin(ACTIVATION_FIELDS)
                             & (ctx.events["Date"] >= exit_row["Date"] - pd.Timedelta(days=1)) & (ctx.events["Date"] <= window_end)]
    if activations.empty:
        return
    lines = [f"Last parking NS seen: {fmt_ts(parked_until)}", f"[{fmt_ts(exit_row['Date'])}] NS ➔ {exit_row['NS Host']}"]
    lines += [f"[{fmt_ts(r['Date'])}] {r['Field']} ➔ {str(r['Value'])[:80]}" for _, r in activations.head(10).iterrows()]
    ctx.add(
        "Parking Exit / Reactivation", "High", "T1583.001 (Acquire Infrastructure: Domains)",
        f"Domain left parking name servers and gained {len(activations)} live A/AAAA/MX record(s) within 7 days.",
        "\n".join(lines), flag="parking_exit",
    )


def rule_multi_network_flux(ctx):
    """Fast-flux across distinct ASNs / networks within 7 days, ignoring CDN anycast addresses."""
    ip_rows = explode_ip_events(ctx.events)
    if ip_rows.empty:
        return
    ip_rows = ip_rows[ip_rows["IP"].map(lambda ip: cdn_for_ip(ip, ctx.ip_intel) is None)]
    if ip_rows.empty:
        return
    ip_rows = ip_rows.assign(Network=ip_rows["IP"].map(lambda ip: network_key(ip, ctx.ip_intel)))
    ip_rows = ip_rows.dropna(subset=["Network"]).sort_values("Date", kind="stable").reset_index(drop=True)
    dates, networks, ips = ip_rows["Date"].tolist(), ip_rows["Network"].tolist(), ip_rows["IP"].tolist()
    min_networks, min_ips = ctx.thresholds["flux_networks"], ctx.thresholds["flux_ips"]
    window = pd.Timedelta(days=7)
    net_counts, ip_counts, j = Counter(), Counter(), 0
    for i in range(len(dates)):
        while j < len(dates) and dates[j] <= dates[i] + window:
            net_counts[networks[j]] += 1
            ip_counts[ips[j]] += 1
            j += 1
        if len(net_counts) >= min_networks and len(ip_counts) >= min_ips:
            known_asn = sum(1 for n in net_counts if n.startswith("AS"))
            ctx.add(
                "Multi-Network Fast-Flux (ASN-Diverse)", "High", "T1568.001 (Fast Flux DNS)",
                f"{len(ip_counts)} non-CDN IPs across {len(net_counts)} distinct networks within 7 days "
                f"({known_asn} identified by ASN, others by network prefix).",
                f"Window start: {fmt_ts(dates[i])}\nNetworks: {', '.join(sorted(net_counts)[:15])}\nIPs: {', '.join(sorted(ip_counts)[:15])}",
                flag="multi_network_flux",
            )
            return
        for counter, key in ((net_counts, networks[i]), (ip_counts, ips[i])):
            counter[key] -= 1
            if counter[key] == 0:
                del counter[key]


def rule_volume_anomaly(ctx):
    """Days whose summed pDNS query counts are robust outliers against the domain's own baseline (median/MAD)."""
    ev = ctx.events
    if ev.empty or "Count" not in ev.columns:
        return
    counts = pd.to_numeric(ev["Count"], errors="coerce")
    daily = counts.groupby(ev["Date"].dt.floor("D")).sum()
    daily = daily[daily > 0]
    if len(daily) < 7:
        return
    median = daily.median()
    mad = (daily - median).abs().median()
    if mad <= 0:
        return
    robust_z = 0.6745 * (daily - median) / mad
    spikes = daily[(robust_z >= ctx.thresholds["volume_z"]) & (daily >= 100)]
    if spikes.empty:
        return
    top = spikes.sort_values(ascending=False).head(5)
    lines = [f"{day:%Y-%m-%d}: {int(val):,} queries (robust z={robust_z[day]:.1f})" for day, val in top.items()]
    ctx.add(
        "Query Volume Anomaly", "Medium", "T1071.004 (App Layer Protocol: DNS)",
        f"{len(spikes)} day(s) with query volume far above this domain's baseline (median {int(median):,}/day). "
        "DNSDB counts are attributed to each record's first-seen day, so spikes are approximate.",
        "\n".join(lines),
        evidence=[evidence_record(day, "Query Volume", f"{int(val):,} queries (robust z={robust_z[day]:.1f})")
                  for day, val in spikes.sort_index().items()],
    )


def rule_origin_exposure(ctx):
    if ctx.is_ip:
        return
    cdn = cdn_fronting(ctx.domain, ctx.events, ctx.profile, ctx.ip_intel)
    if not cdn:
        return
    candidates = find_origin_candidates(ctx.domain, ctx.events, ctx.cert_events, ctx.ip_intel)
    if candidates.empty:
        return
    lines = [f"{r['IP']} ({r['Sources']}; last seen {fmt_ts(r['Last Seen'], '%Y-%m-%d')}) - {r['Hostnames']}"
             for _, r in candidates.head(MAX_IOC_LINES).iterrows()]
    ctx.add(
        "Potential Origin IP Exposure (Behind CDN)", "Medium-High", "T1090.002 (Proxy: External Proxy)",
        f"Domain is fronted by {cdn}, but {len(candidates)} non-CDN IP(s) appear in DNS history or certificate events "
        "(possible origin servers or unproxied hosts).",
        "\n".join(lines),
    )


LOOKALIKE_SEVERITY = {
    "Homoglyph / IDN Brand Impersonation": ("Critical", "T1583.001 (Acquire Infrastructure: Domains)"),
    "Typosquatting Lookalike": ("High", "T1583.001 (Acquire Infrastructure: Domains)"),
    "Combosquatting (Brand + Keyword)": ("High", "T1583.001 (Acquire Infrastructure: Domains)"),
    "Brand in Subdomain": ("Medium-High", "T1566.002 (Phishing: Spearphishing Link)"),
    "Brand Name on Alternate TLD": ("Low", "T1583.001 (Acquire Infrastructure: Domains)"),
    "IDN / Punycode Domain": ("Low", "T1583.001 (Acquire Infrastructure: Domains)"),
}


def rule_lookalike(ctx):
    if ctx.is_ip:
        return
    for finding in analyze_lookalike(ctx.domain, ctx.brands, ctx.official_domains):
        severity, mitre = LOOKALIKE_SEVERITY[finding["type"]]
        if finding["type"] == "Combosquatting (Brand + Keyword)" and not finding.get("keywords"):
            severity = "Medium"
        brand = f" brand '{finding['brand']}'" if finding["brand"] else ""
        ctx.add(
            finding["type"], severity, mitre,
            f"Domain resembles protected{brand}: {finding['detail']}.",
            f"Domain: {ctx.domain}\nBrand: {finding['brand'] or 'N/A'}\nDetail: {finding['detail']}",
            flag="lookalike",
        )


INTEL_RULES = (
    rule_newly_registered,
    rule_hosting_watchlist,
    rule_cross_domain_redirect,
    rule_parking,
    rule_multi_network_flux,
    rule_volume_anomaly,
    rule_origin_exposure,
    rule_lookalike,
)

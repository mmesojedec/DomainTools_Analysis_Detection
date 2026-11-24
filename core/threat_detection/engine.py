"""Unified Automated Threat Detection Engine: builds per-domain contexts and runs the rule sets."""
from dataclasses import dataclass, field

import pandas as pd

from config import DEFAULT_THRESHOLDS
from core import bgp
from core.alert_grouping import merge_duplicate_alerts
from core.allowlist import parse_allowlist
from core.anonymizers import by_ip, tor_exit_lookups, vpndb_lookups
from core.caa import extract_domain_caa_policy
from core.cname import build_cname_map
from core.correlation import Correlation, collect_artifacts, correlate, detect_domain_hops
from core.helpers import is_ip_address
from core.network_intel import build_ip_intel
from core.pdns_features import add_event_gaps
from core.resolver import build_index, build_tree
from core.threat_detection.anonymizer_rules import ANONYMIZER_RULES, shared_exit_alerts
from core.threat_detection.bgp_rules import BGP_RULES
from core.threat_detection.cert_anomaly_rules import certificate_anomaly_alerts
from core.threat_detection.cname_rules import CNAME_RULES, shared_cname_alerts
from core.threat_detection.compound_rules import (
    COMPOUND_RULES,
    bulk_registration_alerts,
    campaign_wave_alerts,
    malicious_link_alerts,
)
from core.threat_detection.context import ALERT_COLUMNS, MAX_IOC_LINES, DomainContext, evidence_record, fmt_ts
from core.threat_detection.dns_rules import DNS_RULES, rule_dga_entropy
from core.threat_detection.enrichment_rules import ENRICHMENT_RULES, apply_popularity, build_tracker_occurrences
from core.threat_detection.intel_rules import INTEL_RULES
from core.threat_detection.lifecycle_rules import LIFECYCLE_RULES
from core.threat_detection.resolver_rules import RESOLVER_RULES
from core.threat_detection.risk_rules import RISK_RULES
from core.threat_detection.ssl_rules import run_ssl_rules
from integrations.enrichment import extract_iris_profile
from integrations.risk import risk_components

# Rules still kept for domains below the Min Risk Score: their evidence stands on its own (brand lookalikes, takeover
# risk, CAA breaches, known C2 certificate fingerprints, a high Proximity with a low threat profile), and new or own domains often have a low risk score
GATE_EXEMPT_RULES = frozenset({
    "Phishing Kit Staging", "Mail-Capable Lookalike", "Lure Subdomain",
    "Homoglyph / IDN Brand Impersonation", "Typosquatting Lookalike", "Combosquatting (Brand + Keyword)",
    "Brand in Subdomain", "Brand Name on Alternate TLD",
    "Dangling CNAME (Subdomain Takeover Risk)", "Unverified CNAME to Takeover-Prone Service",
    "Dangling NS Record (Zone Takeover Risk)", "Dangling MX Record (Mail Interception Risk)",
    "Dangling SPF Include (Mail Spoofing Risk)", "CNAME to Lapsed Domain (Takeover Risk)",
    "Unauthorized CA Certificate Issuance (CAA Breach)", "Wildcard Issuance Forbidden by CAA Policy",
    "Known C2 Certificate Fingerprint (JA4X)", "Code-Generated Certificate Layout (JA4X)",
    "Possible Domain Hijack", "Benign-Looking Domain in Malicious Neighborhood",
})


@dataclass
class ThreatResult:
    """Engine output: alerts plus which domains were skipped or evaluated without a risk score."""
    alerts: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=ALERT_COLUMNS))
    skipped_domains: list = field(default_factory=list)
    unscored_domains: list = field(default_factory=list)
    evaluated_domains: list = field(default_factory=list)
    correlation: Correlation = field(default_factory=Correlation)
    hops: pd.DataFrame = field(default_factory=pd.DataFrame)


def build_risk_lookup(risk_df):
    """Maps domain -> (display score, numeric score or None, evidence string)."""
    lookup = {}
    if risk_df is None or risk_df.empty:
        return lookup
    for dom, dom_risk in risk_df.groupby("Domain"):
        overall = dom_risk[dom_risk["Component"] == "Overall Risk"]
        raw_score = overall["Score"].iloc[0] if not overall.empty else None
        numeric = pd.to_numeric(raw_score, errors="coerce")
        numeric = None if pd.isna(numeric) else float(numeric)
        evidence = set()
        for ev_str in dom_risk["Evidence"].dropna():
            evidence.update(item.strip().title() for item in str(ev_str).split(",") if item.strip())
        lookup[dom] = (f"{numeric:g}" if numeric is not None else "N/A", numeric, ", ".join(sorted(evidence)) or "None")
    return lookup


def prepare_events(events_df, history_gaps=False):
    """
    Normalizes the merged DH + pDNS frame: Value column, valid dates, and per-domain gaps recomputed after merging.
    With `history_gaps=True` the frame is a windowed slice whose gaps were computed on full history; they are kept.
    """
    if events_df is None or events_df.empty or "Domain" not in events_df.columns:
        return pd.DataFrame(columns=["Domain", "Date", "Field", "Value", "Days Since Previous Event"])
    events = events_df.copy()
    if "Value" not in events.columns:
        events["Value"] = events.get("After", "")
    elif "After" in events.columns:
        events["Value"] = events["Value"].where(events["Value"].notna(), events["After"])
    events["Date"] = pd.to_datetime(events["Date"], errors="coerce")
    events = events.dropna(subset=["Date"])
    if history_gaps and "Days Since Previous Event" in events.columns:
        return events.sort_values("Date", kind="stable").reset_index(drop=True)
    return add_event_gaps(events)


def _cluster_alerts(contexts, correlation):
    for cluster in correlation.clusters:
        strong = cluster["Strength"] == "Strong"
        artifact_lines = [f"{kind}: {', '.join(values[:5])}{' ...' if len(values) > 5 else ''}"
                          for kind, values in cluster["Shared Artifacts"].items()]
        for domain in cluster["Domains"]:
            ctx = contexts.get(domain)
            if ctx is None:
                continue
            others = [d for d in cluster["Domains"] if d != domain]
            ctx.add(
                "Shared Infrastructure Cluster", "High" if strong else "Medium-High", "T1583.001 (Acquire Infrastructure: Domains)",
                f"Member of infrastructure cluster {cluster['Cluster']} ({cluster['Size']} domains) linked by "
                f"{', '.join(cluster['Shared Artifacts'])}: {', '.join(others[:10])}{' ...' if len(others) > 10 else ''}.",
                f"Cluster: {cluster['Cluster']} ({cluster['Strength']})\nMembers: {', '.join(cluster['Domains'])}\n" + "\n".join(artifact_lines),
                flag="cluster", confidence="High" if strong else "Medium",
                evidence=[evidence_record(None, kind, value, artifact=value)
                          for kind, values in cluster["Shared Artifacts"].items() for value in values],
            )


def _hop_alerts(contexts, hops):
    if hops.empty:
        return
    for related_value, group in hops.groupby("Related"):
        for domain in {r.strip() for r in str(related_value).split(",") if r.strip()}:
            ctx = contexts.get(domain)
            if ctx is None:
                continue
            lines = [f"{r['IP']}: {r['From Domain']} (last {fmt_ts(r['From Last Seen'], '%Y-%m-%d')}) ➔ "
                     f"{r['To Domain']} (first {fmt_ts(r['To First Seen'], '%Y-%m-%d')}, gap {r['Gap Days']}d)"
                     for _, r in group.head(MAX_IOC_LINES).iterrows()]
            ctx.add(
                "Domain Hopping on Shared IP", "Medium-High", "T1583.001 (Acquire Infrastructure: Domains)",
                f"{len(group)} hop(s): new domains appeared on {group['IP'].nunique()} shared IP(s) shortly after earlier domains went dark "
                "(typical takedown evasion).",
                "\n".join(lines), flag="domain_hopping", confidence="High" if len(group) >= 2 else "Medium",
                evidence=[evidence_record(r["To First Seen"], "Domain Hop",
                                          f"{r['From Domain']} ➔ {r['To Domain']} (gap {r['Gap Days']}d)", artifact=r["IP"])
                          for _, r in group.iterrows()],
            )


def detect_threat_flags(events_df, thresholds, risk_df=None, ssl_df=None, enrichment_data=None,
                        cert_events_df=None, ip_observations=None, brands=(), official_domains=(),
                        history_gaps=False, window_start=None, cname_chases=None, cname_rdata=None, anonymizers=None,
                        vpndb_context=None, verdicts=None, allowlist=None, bgp_frames=None, resolutions=None,
                        pdns_coverage=None, ct_logs=None):
    """
    Evaluates DNS/pDNS/Domain History events, SSL/TLS certificates, Iris enrichment, and cross-domain
    correlations per domain on raw UTC timestamps. Returns a ThreatResult.
    `history_gaps`: events are an analysis-window slice with dormancy gaps precomputed on full history.
    `window_start`: only domain hops whose new domain appeared on/after this time are reported.
    `cname_chases`: DNSDB CNAME chases (integrations.dnsdb.chase_cname rows) that continue chains leaving the data.
    `cname_rdata`: reverse CNAME lookups (core.cname.rdata_rows) that add analyzed domains pointing to a shared name.
    `anonymizers`: VPNDB verdicts of the run's IPs (core.anonymizers table) for the VPN / proxy / Tor rules.
    `vpndb_context`: {"exit_weeks", "neighbour_ranges", "hosting_asns"} frames (collector.collect_anonymizer_context)
    and "tor_overview" (VPNDB /tor).
    `bgp_frames`: {"origins", "asns", "routes"} (BGPDB, core.bgp) for the BGP routing rules.
    `resolutions`: DNSDB lookups of the DNS tree (core.resolver.LOOKUP_COLUMNS) and `pdns_coverage` (which domains'
    passive DNS lookup was complete) for the dangling DNS rules.
    `ct_logs`: the run's CT log entries (Hash, Timestamp) for the certificate anomaly rules (first log time).
    """
    thresholds = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    enrichment_data = enrichment_data or {}
    ssl_df = ssl_df if ssl_df is not None else pd.DataFrame()
    events = prepare_events(events_df, history_gaps=history_gaps)
    result = ThreatResult()

    candidates = set(events["Domain"].unique()) if not events.empty else set()
    if not ssl_df.empty and "Domain" in ssl_df.columns:
        candidates.update(ssl_df["Domain"].unique())
    candidates.update(enrichment_data.keys())
    anonymizer_ips = by_ip(anonymizers)
    exit_weeks, neighbours, asn_verdicts = vpndb_lookups(vpndb_context)
    tor_networks, tor_prefixes = tor_exit_lookups((vpndb_context or {}).get("tor_overview"))
    candidates.update(ip for ip, row in anonymizer_ips.items() if ip in str(row["Domains"]).split(", "))   # IP targets
    bgp_frames = bgp_frames or {}
    bgp_found = bgp.findings(bgp_frames.get("origins"), bgp_frames.get("asns"), bgp_frames.get("routes"))
    bgp_usual = bgp.main_origins(bgp_frames.get("origins"))
    bgp_moves = bgp.routing_moves(bgp_usual, dict(bgp_frames.get("previous") or {}))
    if not candidates:
        return result

    risk_lookup = build_risk_lookup(risk_df)
    components = risk_components(risk_df)
    tracker_occurrences = build_tracker_occurrences(enrichment_data)
    events_by_domain = {dom: grp.reset_index(drop=True) for dom, grp in events.groupby("Domain")} if not events.empty else {}
    ssl_by_domain = {dom: grp for dom, grp in ssl_df.groupby("Domain")} if not ssl_df.empty and "Domain" in ssl_df.columns else {}
    min_risk = thresholds["risk_score"]
    ip_intel = build_ip_intel(enrichment_data)
    cert_events_df = cert_events_df if cert_events_df is not None else pd.DataFrame()
    cert_events_by_domain = {dom: grp for dom, grp in cert_events_df.groupby("Domain")} if not cert_events_df.empty else {}
    now = pd.Timestamp.now(tz="UTC").tz_localize(None)
    cname_map = build_cname_map(events, cname_chases)
    cname_by_domain = {dom: grp.reset_index(drop=True) for dom, grp in cname_map.groupby("Domain")} if not cname_map.empty else {}
    names = [d for d in candidates if not is_ip_address(d)]
    tree, _ = build_tree(build_index(events, resolutions, pdns_coverage, names), names)
    tree_by_domain = {dom: grp.reset_index(drop=True) for dom, grp in tree.groupby("Domain")} if not tree.empty else {}

    contexts, gated_alerts = {}, []
    for domain in sorted(candidates):
        is_ip = is_ip_address(domain)
        risk_display, numeric_risk, evidence = risk_lookup.get(domain, ("N/A", None, "None"))

        gated = False
        if not is_ip:
            if numeric_risk is None:
                result.unscored_domains.append(domain)
            elif numeric_risk < min_risk:
                result.skipped_domains.append(domain)
                gated = True

        dom_events = events_by_domain.get(domain, pd.DataFrame(columns=events.columns))
        ctx = DomainContext(
            domain=domain,
            is_ip=is_ip,
            thresholds=thresholds,
            risk_display=risk_display,
            numeric_risk=numeric_risk,
            risk_evidence=evidence,
            risk_components=components.get(domain, {}),
            events=dom_events,
            ssl=ssl_by_domain.get(domain, pd.DataFrame()),
            enrichment=enrichment_data.get(domain),
            tracker_occurrences=tracker_occurrences,
            caa_policy=extract_domain_caa_policy(dom_events, domain),
            profile=extract_iris_profile(enrichment_data.get(domain)),
            ip_intel=ip_intel,
            cert_events=cert_events_by_domain.get(domain, pd.DataFrame()),
            cname_map=cname_by_domain.get(domain, cname_map.iloc[0:0]),
            resolution=tree_by_domain.get(domain, tree.iloc[0:0]),
            anonymizers=anonymizer_ips,
            exit_weeks=exit_weeks,
            neighbours=neighbours,
            asn_verdicts=asn_verdicts,
            tor_networks=tor_networks,
            tor_prefixes=tor_prefixes,
            bgp_findings=bgp.for_domain(bgp_found, domain),
            bgp_origins=bgp.origin_numbers(bgp.for_domain(bgp_usual, domain)),
            bgp_moves=[move for move in bgp_moves if move[0] == domain],
            brands=tuple(brands or ()),
            official_domains=tuple(official_domains or ()),
            now=now,
        )
        rule_dga_entropy(ctx)
        if not dom_events.empty:
            for rule in DNS_RULES + CNAME_RULES + RESOLVER_RULES:
                rule(ctx)
        for rule in ENRICHMENT_RULES + INTEL_RULES + LIFECYCLE_RULES + ANONYMIZER_RULES + BGP_RULES + RISK_RULES:
            rule(ctx)
        run_ssl_rules(ctx)
        if gated:
            for rule in COMPOUND_RULES:   # a lookalike's compounds (mail-capable, kit staging) count here too
                rule(ctx)
            apply_popularity(ctx)
            # Below the Min Risk Score only the rules whose evidence stands on its own are kept: a new lookalike or
            # an own domain with a takeover / CAA problem often has a low score
            gated_alerts.extend(alert for alert in ctx.alerts if alert["Threat Type"] in GATE_EXEMPT_RULES)
            continue

        result.evaluated_domains.append(domain)
        contexts[domain] = ctx

    allowlist = parse_allowlist(allowlist) if isinstance(allowlist, str) else allowlist
    result.correlation = correlate(collect_artifacts(events, ssl_df, enrichment_data, ip_intel, allowlist))
    _cluster_alerts(contexts, result.correlation)
    result.hops = detect_domain_hops(ip_observations, thresholds["hop_days"], ip_intel=ip_intel)
    if window_start is not None and not result.hops.empty:
        result.hops = result.hops[pd.to_datetime(result.hops["To First Seen"]) >= window_start].reset_index(drop=True)
    _hop_alerts(contexts, result.hops)
    shared_cname_alerts(contexts, cname_map, cname_rdata)
    shared_exit_alerts(contexts)
    malicious_link_alerts(contexts, result.correlation, verdicts)
    bulk_registration_alerts(contexts)
    campaign_wave_alerts(contexts)
    certificate_anomaly_alerts(contexts, ssl_df, ct_logs)
    for ctx in contexts.values():
        for rule in COMPOUND_RULES:   # last: they read the flags every other rule set
            rule(ctx)
        apply_popularity(ctx)   # after the cross-domain alerts, so they are downgraded on popular domains too

    alerts = gated_alerts + [alert for ctx in contexts.values() for alert in ctx.alerts]
    if allowlist:
        for alert in alerts:
            hit = allowlist.in_text(f"{alert['Threat Logic']}\n{alert['Triggering IOCs']}")
            if hit:
                alert["Confidence"] = "Low"
                alert["Threat Logic"] = f"{alert['Threat Logic']} Names allowlisted infrastructure ({hit}): kept at Low confidence."

    if alerts:
        # Rules evaluated per certificate / record can fire several times per domain: one alert per (domain, rule)
        result.alerts = merge_duplicate_alerts(pd.DataFrame(alerts, columns=ALERT_COLUMNS))
    return result

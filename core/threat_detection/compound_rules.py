"""
Rules over what the other rules found. Per domain: combinations of independent signals (rule flags) that together
describe one attack stage, a lookalike that can send mail, and lure subdomains. Across domains: bulk-registration
cohorts and campaign waves (domains registered and given certificates together). No extra lookups.
"""
from collections import defaultdict

import pandas as pd

from core.helpers import registrable_domain
from core.network_intel import is_large_dns_provider, is_parking_ns, record_types
from core.subdomain_triage import STRONG_SIGNALS, TRIAGE_SIGNALS, name_signals
from core.threat_detection.context import evidence_record, fmt_ts

COHORT_WINDOW = pd.Timedelta(hours=48)     # domains registered this close together at one registrar ...
WAVE_WINDOW = pd.Timedelta(hours=48)       # ... or registered and given a certificate together
WAVE_SETUP = pd.Timedelta(hours=72)        # a domain's first certificate this soon after registration: set up in one go
WAVE_MIN_DOMAINS = 3
LURE_MIN_SCORE = 4                         # the Subdomain Triage Medium score, from the name alone
# Mail domains everyone uses: sharing one says nothing about who registered two domains
COMMON_EMAIL_DOMAINS = frozenset({"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me",
                                  "protonmail.com", "aol.com", "mail.com", "gmx.com", "yandex.ru", "qq.com", "163.com"})


def _any(ctx, *flags):
    return sorted(set(flags) & ctx.flags)


def rule_phishing_kit_staging(ctx):
    lookalike, new, live = _any(ctx, "lookalike"), _any(ctx, "nrd", "reregistered"), \
        _any(ctx, "rapid_weaponization", "cert_staging")
    if lookalike and new and live:
        ctx.add(
            "Phishing Kit Staging", "Critical", "T1583.001 (Acquire Infrastructure: Domains)",
            "A brand lookalike that was just registered (or re-registered) and given a certificate as it went live: "
            "the setup of a phishing site.",
            f"Signals: {', '.join(lookalike + new + live)}", flag="kill_chain", confidence="High",
        )


def rule_weaponized_reactivation(ctx):
    revived, armed = _any(ctx, "parking_exit", "parked_to_weaponized", "reregistered", "transfer_ns"), \
        _any(ctx, "rapid_weaponization", "cert_staging", "backdated_cert")
    if revived and armed:
        ctx.add(
            "Weaponized Reactivation", "High", "T1583.001 (Acquire Infrastructure: Domains)",
            "A dormant, parked, re-registered or transferred domain came back to life with a fresh certificate: "
            "aged domains are bought or hijacked to borrow their reputation.",
            f"Signals: {', '.join(revived + armed)}", flag="kill_chain",
        )


def rule_takeover_in_progress(ctx):
    if _any(ctx, "dangling_cname") and _any(ctx, "cname_retarget"):
        ctx.add(
            "Subdomain Takeover in Progress", "Critical", "T1584.001 (Compromise Infrastructure: Domains)",
            "The domain has a dangling CNAME and a subdomain was just repointed to another provider: a takeover may "
            "already have happened.",
            "Signals: dangling_cname, cname_retarget", flag="kill_chain",
        )


def rule_generated_flux(ctx):
    flux = _any(ctx, "fast_flux", "multi_network_flux")
    if _any(ctx, "dga") and flux:
        ctx.add(
            "Generated Fast-Flux Domain", "Critical", "T1568.001 (Fast Flux DNS)",
            "A generated-looking name rotating through many addresses: the pattern of botnet C2 domains.",
            f"Signals: dga, {', '.join(flux)}", flag="kill_chain", confidence="High",
        )


def rule_bulletproof_new_domain(ctx):
    hosting = _any(ctx, "suspicious_ns", "watchlist_hosting", "anonymizer", "anonymizer_dedicated", "ns_churn")
    if _any(ctx, "nrd") and hosting:
        ctx.add(
            "Bulletproof-Hosted New Domain", "High", "T1583.003 (Acquire Infrastructure: Virtual Private Server)",
            "A newly registered domain on abuse-tolerant DNS or hosting (or behind an anonymizer): set up to resist "
            "takedown from day one.",
            f"Signals: nrd, {', '.join(hosting)}", flag="kill_chain",
        )


def _mail_posture(ctx):
    """(has MX, DMARC record, SPF text) from the Iris profile and passive DNS."""
    ev = ctx.events
    has_mx = bool(ctx.profile.get("mx_hosts")) or (not ev.empty and (record_types(ev) == "MX").any())
    dmarc, spf = None, str(ctx.profile.get("spf") or "")
    if not ev.empty:
        txt = ev[record_types(ev).isin({"TXT", "SPF"})]
        names = txt["RRName"].astype(str).str.lower() if "RRName" in txt.columns else pd.Series("", index=txt.index)
        values = txt["Value"].astype(str)
        dmarc = next((v for n, v in zip(names, values) if n.startswith("_dmarc.") and "v=dmarc1" in v.lower()), None)
        spf = spf or next((v for v in values if "v=spf1" in v.lower()), "")
    return has_mx, dmarc, spf


def rule_mail_capable_lookalike(ctx):
    if not _any(ctx, "lookalike"):
        return
    has_mx, dmarc, spf = _mail_posture(ctx)
    weak_spf = not spf or "-all" not in spf.lower()
    if has_mx and (dmarc is None or weak_spf):
        gaps = (["no DMARC record"] if dmarc is None else []) + (["no SPF record"] if not spf else
                                                                  ["SPF without -all"] if weak_spf else [])
        ctx.add(
            "Mail-Capable Lookalike", "High", "T1566.002 (Phishing: Spearphishing Link)",
            f"A brand lookalike that can receive and send mail ({', '.join(gaps)}): ready for phishing email that "
            "passes as the brand.",
            f"MX: {', '.join(ctx.profile.get('mx_hosts', [])[:3]) or 'from passive DNS'}\nSPF: {spf[:120] or 'none'}\n"
            f"DMARC: {(dmarc or 'none')[:120]}",
            flag="mail_lookalike",
        )


def rule_lure_subdomain(ctx):
    """Subdomains whose names alone score Medium or more in Subdomain Triage, with a strong (phishing) signal."""
    if ctx.is_ip:
        return
    names = set()
    if not ctx.events.empty and "RRName" in ctx.events.columns:
        names |= set(ctx.events["RRName"].dropna().astype(str).str.lower().str.rstrip("."))
    if not ctx.ssl.empty and "Alt Names List" in ctx.ssl.columns:
        for sans in ctx.ssl["Alt Names List"]:
            names |= {str(n).lower().rstrip(".") for n in (sans if isinstance(sans, list) else [])}
    lures = []
    for name in sorted(names):
        if name.startswith(("*.", "_")) or "._" in name or name == ctx.domain or not name.endswith("." + ctx.domain):
            continue
        signals, matched = name_signals(name, ctx.domain)
        score = sum(TRIAGE_SIGNALS[s][0] for s in signals)
        if score >= LURE_MIN_SCORE and set(signals) & set(STRONG_SIGNALS):
            lures.append((score, name, signals, matched))
    if lures:
        lures.sort(key=lambda item: (-item[0], item[1]))
        ctx.add(
            "Lure Subdomain", "Medium", "T1566.002 (Phishing: Spearphishing Link)",
            f"{len(lures)} subdomain(s) named to lure (brand, phishing words, an embedded domain), e.g. {lures[0][1]}.",
            "\n".join(f"{name}: {', '.join(signals)}" + (f" ({', '.join(matched)})" if matched else "")
                      for _, name, signals, matched in lures[:25]),
            flag="lure_subdomain",
            evidence=[evidence_record(None, "Hostname", name, artifact=name) for _, name, _, _ in lures[:50]],
        )


COMPOUND_RULES = (rule_lure_subdomain, rule_mail_capable_lookalike, rule_phishing_kit_staging,
                  rule_weaponized_reactivation, rule_takeover_in_progress, rule_generated_flux,
                  rule_bulletproof_new_domain)


# ---------------------------------------------------------------------------
# Across domains
# ---------------------------------------------------------------------------

def _facets(ctx):
    """Values that tie two registrations to one operator: own name servers, registrant mail domain, hosting ASN."""
    profile = ctx.profile
    facets = {("NS", registrable_domain(ns) or ns) for ns in profile.get("name_servers", [])
              if not is_large_dns_provider(ns) and not is_parking_ns(ns)}
    facets |= {("Email", d) for d in profile.get("email_domains", []) if d not in COMMON_EMAIL_DOMAINS}
    facets |= {("ASN", ip["asn"]) for ip in profile.get("ips", []) if ip.get("asn")}
    return facets


def _windows(items, window):
    """Groups of (time, key) items whose times chain within `window` of each other."""
    groups, current = [], []
    for when, key in sorted(items):
        if current and when - current[-1][0] > window:
            groups.append(current)
            current = []
        current.append((when, key))
    if current:
        groups.append(current)
    return [g for g in groups if len(g) > 1]


def bulk_registration_alerts(contexts):
    """Domains registered within 48 hours at one registrar that also share a name server, mail domain or ASN."""
    by_registrar = defaultdict(list)
    for domain, ctx in contexts.items():
        created, registrar = ctx.profile.get("create_date"), (ctx.profile.get("registrar") or "").strip()
        if registrar and created is not None and pd.notna(created):
            by_registrar[registrar.lower()].append((created, domain))
    for items in by_registrar.values():
        for group in _windows(items, COHORT_WINDOW):
            domains = [d for _, d in group]
            for domain in domains:
                ctx = contexts[domain]
                mates = {other: _facets(ctx) & _facets(contexts[other]) for other in domains if other != domain}
                mates = {other: shared for other, shared in mates.items() if shared}
                if not mates:
                    continue
                shared = sorted({f"{kind} {value}" for values in mates.values() for kind, value in values})
                ctx.add(
                    "Bulk Registration Cohort", "Medium", "T1583.001 (Acquire Infrastructure: Domains)",
                    f"Registered within 48 hours of {len(mates)} other analyzed domain(s) at the same registrar and "
                    f"sharing {', '.join(shared[:3])}: registered together by one operator.",
                    f"Registrar: {ctx.profile.get('registrar')}\nCreated: {fmt_ts(ctx.profile['create_date'], '%Y-%m-%d %H:%M')}\n"
                    f"Cohort: {', '.join(sorted(mates))}\nShared: {', '.join(shared)}",
                    flag="bulk_cohort",
                )


def _setup_time(ctx):
    """(registration time, issuer of the first certificate) when the domain got a certificate within 72 hours of
    registering, else None."""
    created = ctx.profile.get("create_date")
    if created is None or pd.isna(created) or ctx.ssl.empty or "Not Before Date" not in ctx.ssl.columns:
        return None
    issued = pd.to_datetime(ctx.ssl["Not Before Date"], errors="coerce")
    after = ctx.ssl[(issued >= created - pd.Timedelta(hours=1)) & (issued <= created + WAVE_SETUP)]
    if after.empty:
        return None
    first = after.loc[pd.to_datetime(after["Not Before Date"]).idxmin()]
    return created, str(first.get("Issuer Org") or first.get("Issuer") or "").strip() or "unknown issuer"


def campaign_wave_alerts(contexts):
    """Three or more domains registered within 48 hours, each given a certificate by the same CA right away."""
    by_issuer = defaultdict(list)
    for domain, ctx in contexts.items():
        setup = _setup_time(ctx)
        if setup:
            by_issuer[setup[1]].append((setup[0], domain))
    for issuer, items in by_issuer.items():
        for group in _windows(items, WAVE_WINDOW):
            if len(group) < WAVE_MIN_DOMAINS:
                continue
            domains = [d for _, d in group]
            start, end = group[0][0], group[-1][0]
            for domain in domains:
                ctx = contexts[domain]
                ctx.add(
                    "Campaign Wave (Same-Day Setup)", "Medium", "T1583.001 (Acquire Infrastructure: Domains)",
                    f"{len(domains)} analyzed domains were registered between {fmt_ts(start, '%Y-%m-%d %H:%M')} and "
                    f"{fmt_ts(end, '%Y-%m-%d %H:%M')} and each got a {issuer} certificate right away: one campaign "
                    "set up in one go.",
                    f"Issuer: {issuer}\nWave: {', '.join(sorted(domains))}",
                    flag="campaign_wave",
                )


def malicious_link_alerts(contexts, correlation, verdicts):
    """Domains in a Strong infrastructure cluster with a domain you marked Malicious (domain verdict)."""
    malicious = {d for d, status in (verdicts or {}).items() if status == "Malicious"}
    if not malicious:
        return
    for cluster in correlation.clusters:
        if cluster["Strength"] != "Strong":
            continue
        bad = sorted(malicious & set(cluster["Domains"]))
        if not bad:
            continue
        shared = ", ".join(f"{kind}: {', '.join(values[:2])}" for kind, values in cluster["Shared Artifacts"].items())
        for domain in cluster["Domains"]:
            ctx = contexts.get(domain)
            if ctx is None or domain in malicious:
                continue
            ctx.add(
                "Linked to Confirmed-Malicious Domain", "High", "T1583.001 (Acquire Infrastructure: Domains)",
                f"Shares strong infrastructure (cluster {cluster['Cluster']}) with {', '.join(bad)}, which you marked "
                "Malicious: probably the same operator.",
                f"Malicious: {', '.join(bad)}\nShared: {shared}",
                flag="malicious_link",
            )

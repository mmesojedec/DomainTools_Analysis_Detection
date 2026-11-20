"""
BGP routing rules (BGPDB): the findings core.bgp.findings computes for the run's hosting IPs, one alert per finding
kind and domain, and the VPNDB match: an anonymizer exit whose prefix is newly announced or announced without
authorization.
"""
import pandas as pd

from core import bgp
from core.anonymizers import ANONYMIZER_CATEGORIES
from core.threat_detection.context import MAX_IOC_LINES, evidence_record

SEVERITY_ORDER = ("Critical", "High", "Medium-High", "Medium", "Low")


def _rows(ctx, finding):
    found = ctx.bgp_findings
    if found is None or found.empty:
        return found.iloc[0:0] if found is not None else pd.DataFrame()
    return found[found["Finding"] == finding]


def _worst(rows):
    return min(rows["Severity"], key=lambda s: SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 99)


def _iocs(rows):
    lines = [f"{row['Prefix'] or row['ASN']} ({row['IP']}): {row['Detail']}" for _, row in rows.iterrows()]
    return "\n".join(lines[:MAX_IOC_LINES])


def _records(rows):
    return [evidence_record(row["First Seen"] if pd.notna(row["First Seen"]) else None, row["Finding"],
                            row["Detail"], row["Prefix"] or row["ASN"]) for _, row in rows.iterrows()]


def rule_origin_conflict(ctx):
    rows = _rows(ctx, bgp.CONFLICT)
    if rows.empty:
        return
    ctx.add(
        "BGP Origin Conflict (Possible Hijack)", "High" if _worst(rows) == "High" else "Medium",
        "T1557 (Adversary-in-the-Middle)",
        "Another network announced the prefix that hosts this domain without authorization (RPKI / IRR name a "
        "different origin) while the authorized origin was also announcing it: a BGP hijack or route leak, so traffic "
        f"to the domain may have gone to the wrong network while it lasted. {len(rows)} conflict(s) in BGPDB.",
        _iocs(rows), flag="bgp_conflict", evidence=_records(rows))


def rule_unauthorized_origin(ctx):
    rows = _rows(ctx, bgp.UNAUTHORIZED_ORIGIN)
    if rows.empty:
        return
    ctx.add(
        "Unauthorized BGP Origin", "Medium-High", "T1583 (Acquire Infrastructure)",
        "The network that announces this domain's hosting is not the one the registries (RPKI / IRR) authorize for "
        "the prefix, and no authorized origin is seen: squatted, informally leased or hijacked address space.",
        _iocs(rows), flag="bgp_unauthorized", evidence=_records(rows))


def rule_new_prefix(ctx):
    rows = _rows(ctx, bgp.NEW_PREFIX)
    if rows.empty:
        return
    ctx.add(
        "Newly Announced Prefix", "Medium", "T1583 (Acquire Infrastructure)",
        f"The domain is hosted on a prefix that its network only started announcing in the last {bgp.NEW_DAYS} days "
        "(BGPDB): fresh address space comes and goes with short-lived campaign infrastructure.",
        _iocs(rows), flag="bgp_new_prefix", evidence=_records(rows))


def rule_new_origin_network(ctx):
    rows = _rows(ctx, bgp.NEW_ASN)
    if rows.empty:
        return
    ctx.add(
        "Recently Registered Origin Network", "Medium-High" if _worst(rows) == "Medium-High" else "Medium",
        "T1583 (Acquire Infrastructure)",
        "The network (AS) that announces the domain's hosting was registered at its RIR recently: young networks "
        "host a large share of malicious infrastructure (bulletproof and fly-by-night hosting).",
        _iocs(rows), flag="bgp_new_asn", evidence=_records(rows))


def rule_thin_route(ctx):
    rows = _rows(ctx, bgp.THIN_ROUTE)
    if rows.empty:
        return
    ctx.add(
        "Low-Visibility or Single-Upstream Route", "Low", "T1583 (Acquire Infrastructure)",
        "The domain's hosting is barely visible on the internet (few route collectors see the prefix) or its network "
        "hangs off a single upstream: common with small bulletproof hosters, and with many legitimate small networks.",
        _iocs(rows), flag="bgp_thin_route", evidence=_records(rows))


def rule_exit_on_unstable_routing(ctx):
    """
    VPNDB + BGPDB: an anonymizer exit of the domain sits on a prefix that is newly announced, has an unauthorized
    origin or an origin conflict. A VPN / proxy operator on unstable, unregistered space is rarely a mainstream one.
    """
    found = ctx.bgp_findings
    if found is None or found.empty or not ctx.anonymizers:
        return
    hits = []
    for _, row in found[found["Finding"].isin(bgp.UNSTABLE)].iterrows():
        for ip in str(row["IP"]).split(", "):
            verdict = ctx.anonymizers.get(ip)
            if verdict and verdict.get("Category") in ANONYMIZER_CATEGORIES:
                hits.append((ip, verdict, row))
    if not hits:
        return
    lines = [f"{ip} ({verdict['Category']}: {verdict.get('Provider') or 'unknown provider'}) on {row['Prefix']}: "
             f"{row['Finding']}" for ip, verdict, row in hits]
    evidence = [evidence_record(row["First Seen"] if pd.notna(row["First Seen"]) else None,
                                f"{verdict['Category']} exit", f"{ip} on {row['Prefix']}: {row['Finding']}", ip)
                for ip, verdict, row in hits]
    ctx.add(
        "Anonymizer Exit on Unstable Routing", "High", "T1090 (Proxy)",
        "VPNDB names these hosting IPs as VPN / proxy / Tor exits, and BGPDB shows their prefix is newly announced or "
        "announced without authorization: an anonymizer on unstable, unregistered address space is rarely a "
        "mainstream service.",
        "\n".join(lines[:MAX_IOC_LINES]), flag="anonymizer_unstable_routing", evidence=evidence)


BGP_RULES = (rule_origin_conflict, rule_unauthorized_origin, rule_new_prefix, rule_new_origin_network,
             rule_thin_route, rule_exit_on_unstable_routing)

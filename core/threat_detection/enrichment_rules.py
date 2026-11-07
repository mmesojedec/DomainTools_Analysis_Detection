"""
Iris Investigate enrichment rules: live piracy panels, shared web tracker fingerprints, the current MX hosts and SPF
record Iris reports (when passive DNS did not already show them), and the popularity context of a well-known domain.
"""
import re

from config import POPULAR_RANK_MAX
from core.threat_detection.dns_rules import SUSPICIOUS_MX_REGEX
from integrations.enrichment import extract_web_trackers, unwrap_value

PIRACY_TITLE_REGEX = re.compile(
    r"(xtream|stalker|vip\s*iptv|ott\s*panel|stream\s*panel|m3u|reseller\s*panel|iptv\s*server)", re.IGNORECASE
)


def build_tracker_occurrences(enrichment_data):
    """Maps 'Platform: Code' -> list of domains using that tracker."""
    occurrences = {}
    for dom, obj in (enrichment_data or {}).items():
        for tracker in extract_web_trackers(obj):
            occurrences.setdefault(f"{tracker['Platform']}: {tracker['Code']}", []).append(dom)
    return occurrences


def rule_piracy_panel(ctx):
    enr = ctx.enrichment
    if not enr:
        return
    web_title = str(unwrap_value(enr.get("website_title")) or "")
    try:
        web_resp = int(unwrap_value(enr.get("website_response")) or 0)
    except (TypeError, ValueError):
        web_resp = 0
    if web_title and web_resp == 200 and PIRACY_TITLE_REGEX.search(web_title):
        ctx.add(
            "Live Pirate Streaming Panel Detected", "Critical", "T1584.001 (Compromise Infrastructure)",
            f"Active HTTP 200 response returning illegal IPTV management portal title '{web_title}'.",
            f"Domain: {ctx.domain}\nWebsite Title: {web_title}\nHTTP Response: {web_resp}",
        )


def rule_shared_trackers(ctx):
    if not ctx.enrichment:
        return
    for tracker in extract_web_trackers(ctx.enrichment):
        linked = sorted(set(ctx.tracker_occurrences.get(f"{tracker['Platform']}: {tracker['Code']}", [])))
        others = [d for d in linked if d != ctx.domain]
        if others:
            ctx.add(
                "Shared Web Tracker Fingerprint", "High", "T1583.001 (Acquire Infrastructure)",
                f"Domain shares exact {tracker['Platform']} code '{tracker['Code']}' with other analyzed domains ({', '.join(others)}).",
                f"Tracker ID: {tracker['Code']}\nShared Across: {', '.join(linked)}",
            )
            return


def _has(ctx, threat_type):
    return any(alert["Threat Type"] == threat_type for alert in ctx.alerts)


def rule_iris_mail(ctx):
    """The current MX hosts and SPF record from Iris Investigate: they count even when passive DNS has no MX / TXT."""
    profile = ctx.profile or {}
    risky = [host for host in profile.get("mx_hosts", []) if SUSPICIOUS_MX_REGEX.search(host)]
    if risky and not _has(ctx, "High-Risk Mail Provider"):
        ctx.add(
            "High-Risk Mail Provider", "Medium", "T1585.002 (Acquire Email Accounts)",
            "The current MX records (Iris Investigate) point to an offshore, anonymous, or temporary email provider.",
            "Iris Investigate current MX: " + ", ".join(risky),
            evidence=[{"Time": None, "Field": "MX (Iris Investigate)", "Value": host, "Artifact": host} for host in risky],
        )
    spf = profile.get("spf", "")
    if spf and re.search(r"(?<![\w-])\+all\b", spf.lower()) and not _has(ctx, "Highly Permissive SPF (+all)"):
        ctx.add(
            "Highly Permissive SPF (+all)", "High", "T1583.001 (Acquire Infrastructure)",
            "The current SPF record (Iris Investigate) allows ANY IP address (+all) to pass authorization.",
            f"Iris Investigate SPF: {spf[:200]}",
            evidence=[{"Time": None, "Field": "SPF (Iris Investigate)", "Value": spf, "Artifact": None}],
        )


CONFIDENCE_DOWN = {"Medium": "Low", "Medium-High": "Medium"}


def apply_popularity(ctx):
    """
    A domain among the POPULAR_RANK_MAX most popular in Iris (popularity_rank) is far more likely legitimate: the
    confidence of its Medium and Medium-High alerts drops one step, and each alert says why. High-confidence alerts
    (strong evidence) are kept as they are.
    """
    rank = (ctx.profile or {}).get("popularity_rank")
    if not rank or rank > POPULAR_RANK_MAX:
        return
    note = f" Context: popular domain (Iris popularity rank {rank:,}), so more likely legitimate."
    for alert in ctx.alerts:
        alert["Confidence"] = CONFIDENCE_DOWN.get(alert["Confidence"], alert["Confidence"])
        alert["Threat Logic"] = str(alert["Threat Logic"]) + note


ENRICHMENT_RULES = (rule_piracy_panel, rule_shared_trackers, rule_iris_mail)

"""Iris Investigate enrichment rules: live piracy panels and shared web tracker fingerprints."""
import re

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


ENRICHMENT_RULES = (rule_piracy_panel, rule_shared_trackers)

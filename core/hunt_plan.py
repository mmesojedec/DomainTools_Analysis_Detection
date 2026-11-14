"""
Suggested hunt: the hunt tree a run would probably grow, before any lookup is made. Every lead of the run (Pivot
Ranking) is scored from what the run already knows: how few domains share it in Iris, which open alerts it sits in,
what kind of value it is, and whether earlier investigations saw it. Leads that are not worth following (shared
hosting, CDN edges, large DNS providers, values already analyzed) are set aside with the reason. For the best
branches a look-ahead says what following them would bring, from the Iris count, the saved runs and any Iris search
already made. Alerts also give a starting order: which indicators to confirm first.

These are rankings from local data, not predictions of what new lookups will find.
"""
import re
from collections import defaultdict

import pandas as pd

from config import PIVOT_STRONG_MAX
from core.helpers import is_ip_address
from core.network_intel import cdn_for_ip, is_large_dns_provider, is_parking_ns, is_public_ip
from core.pivots import pivot_domains_frame

SEVERITY_POINTS = {"Critical": 30, "High": 22, "Medium-High": 15, "Medium": 10, "Low": 4}
SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium-High": 2, "Medium": 3, "Low": 4}
# how often a kind of value leads to the same operator (a self-signed certificate or a tracker ID rarely is shared by
# chance; a mail server often is)
KIND_POINTS = {
    "SSL certificate (SHA-1)": 12, "SSL email": 10, "Contact email": 10, "WHOIS email": 9, "SOA email": 8,
    "Redirect domain": 9, "Registrant": 7, "Registrant org": 6, "Contact phone": 7, "Contact street": 6,
    "IP address": 6, "SSL subject": 5, "SSL organization": 4, "Name server": 4, "Name server IP": 4,
    "Email domain": 3, "Mail server": 2, "Mail server IP": 2,
}
TRACKER_POINTS = 10   # web tracker codes (GA4, GTM, ...): not in KIND_POINTS by name
STOP_MAX = PIVOT_STRONG_MAX   # a value more domains than this share is shared infrastructure, not one operator
BRANCHES = 5                  # branches the suggested tree draws
LOOKAHEAD = 3                 # of them, how many get a look-ahead
SAMPLE_DOMAINS = 3            # domains named in a look-ahead from an Iris search already made
SHA_RE = re.compile(r"\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b")
JA4X_RE = re.compile(r"\b[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}\b")
HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _alert_text(alert):
    """Everything an alert names (evidence values and artifacts, IOC text), lower case, for matching leads."""
    parts = [str(alert.get("Triggering IOCs") or "")]
    for record in alert.get("Evidence") if isinstance(alert.get("Evidence"), list) else []:
        parts += [str(record.get("Value") or ""), str(record.get("Artifact") or "")]
    return "\n".join(parts).lower()


def alert_mentions(alert, value):
    """Whether an alert names `value` in its evidence or IOCs (values shorter than 4 characters never match)."""
    needle = str(value).lower()
    return len(needle) >= 4 and needle in _alert_text(alert)


def _ties(value, alerts):
    """The open alerts that name `value` in their evidence: [(severity, threat type, domain)]."""
    if alerts is None or alerts.empty:
        return []
    needle = str(value).lower()
    if len(needle) < 4:
        return []
    return [(alert.get("Severity"), alert.get("Threat Type"), alert.get("Domain"))
            for alert in alerts.to_dict("records") if needle in _alert_text(alert)]


def _kind_points(kind):
    return KIND_POINTS.get(kind, TRACKER_POINTS)   # the kinds not listed are web tracker codes


def _specificity(count):
    """Points for how few domains share the value in Iris (fewer: more likely one operator)."""
    if count is None or pd.isna(count) or count <= 1:
        return 0
    if count <= 10:
        return 40
    if count <= 50:
        return 32
    if count <= 200:
        return 24
    return 16 if count <= STOP_MAX else 0


def stop_reason(kind, value, count, analyzed):
    """Why a lead is not worth following (shared infrastructure, already analyzed), or "" when it is."""
    text = str(value).strip().lower()
    if text in analyzed:
        return "Already analyzed in this hunt"
    if kind in ("IP address", "Name server IP", "Mail server IP") or is_ip_address(text):
        if not is_public_ip(text):
            return "Private or reserved address"
        cdn = cdn_for_ip(text)
        if cdn:
            return f"{cdn} edge: shared by unrelated sites"
    if kind == "Name server":
        if is_large_dns_provider(text):
            return "Large DNS provider: hosts millions of domains"
        if is_parking_ns(text):
            return "Parking name server"
    if count is not None and not pd.isna(count) and count > STOP_MAX:
        return f"Shared by {int(count):,} domains in Iris: shared hosting or a service, not one operator"
    return ""


def sightings_index(runs, exclude_keys=()):
    """
    {value (lower case): {target list key: {"domains": {domain: alerts on it}, "label": targets}}} from the saved
    runs' targets and artifacts, leaving out `exclude_keys` (the current target list), for finding where a lead was
    seen.
    """
    index = defaultdict(dict)
    for key, snapshot in runs:
        if key in exclude_keys:
            continue
        alerts = defaultdict(int)
        for alert in snapshot.get("alerts") or []:
            alerts[str(alert.get("Domain", "")).lower()] += 1
        label = ", ".join((snapshot.get("seeds") or snapshot.get("targets") or [])[:3])
        values = [(str(t).lower(), str(t).lower()) for t in snapshot.get("targets") or []]
        for domain, kinds in (snapshot.get("artifacts") or {}).items():
            values += [(str(v).lower(), str(domain).lower()) for vs in (kinds or {}).values() for v in vs or [] if v]
        for value, domain in values:
            entry = index[value].setdefault(key, {"domains": {}, "label": label})
            entry["domains"][domain] = max(entry["domains"].get(domain, 0), alerts.get(domain, 0))
    return index


def _seen(value, index, analyzed=frozenset()):
    """
    Where else a lead was seen: [{"label", "domains": {domain: alerts}, "alerts"}], one per earlier investigation
    (target lists with the same label merged), counting only domains this hunt has not analyzed: an earlier run of the
    same domains is the same investigation, not another one.
    """
    text = str(value).lower()
    found = index.get(text) or index.get(text.split(": ", 1)[-1]) or {}
    merged = {}
    for entry in found.values():
        domains = {d: n for d, n in entry["domains"].items() if d not in analyzed}
        if domains:
            merged.setdefault(entry["label"], {}).update(domains)
    seen = [{"label": label, "domains": domains, "alerts": sum(domains.values())} for label, domains in merged.items()]
    return sorted(seen, key=lambda e: (-e["alerts"], e["label"]))


def score_leads(pivots, alerts=None, analyzed=(), index=None):
    """
    Every lead of the run (rows of the Pivot Ranking that another domain shares), scored 0-100 with the reasons, best
    first: [{"Type", "Value", "Iris Domains", "Run Domains", "Shared With", "Iris Search", "Analyze As", "Score",
    "Reasons", "Stop", "Alerts", "Seen"}]. "Stop" holds why a lead is set aside ("" when it is worth following).
    """
    if pivots is None or pivots.empty:
        return []
    analyzed = {str(a).strip().lower() for a in analyzed}
    index = index or {}
    leads = []
    for row in pivots.to_dict("records"):
        count = row.get("Iris Domains")
        count = None if count is None or pd.isna(count) else int(count)
        if count is not None and count <= 1:   # no other domain has it: nothing to follow
            continue
        reasons, score = [], 0
        points = _specificity(count)
        if points:
            score += points
            reasons.append(f"shared by only {count:,} domains in Iris")
        elif count is None:
            reasons.append("Iris gave no count")
        if row.get("Run Domains", 0) > 1:
            score += min(10, 5 * (row["Run Domains"] - 1))
            reasons.append(f"{row['Run Domains']} of your domains have it")
        ties = _ties(row["Value"], alerts)
        if ties:
            worst = min(ties, key=lambda tie: SEVERITY_RANK.get(tie[0], 9))
            score += min(35, SEVERITY_POINTS.get(worst[0], 0) + 2 * (len(ties) - 1))
            reasons.append(f"named in {len(ties)} open alert(s), worst {worst[0]} ({worst[1]})")
        kind_points = _kind_points(row["Type"])
        score += kind_points
        if kind_points >= 9:
            reasons.append(f"a {row['Type']} value is rarely shared by chance")
        seen = _seen(row["Value"], index, analyzed)
        seen_alerts = sum(entry["alerts"] for entry in seen)
        if seen:
            score += 8 + (4 if seen_alerts else 0)
            reasons.append(f"seen in {len(seen)} other investigation(s)"
                           + (f" with {seen_alerts} alert(s) there" if seen_alerts else ""))
        stop = stop_reason(row["Type"], row["Value"], count, analyzed)
        if not stop and count is not None and count <= int(row.get("Run Domains") or 0):
            stop = "Every domain that has it is already in this run"
        if not stop and count is None and not ties:
            stop = "Iris gave no count: no way to tell how widely it is shared"
        leads.append({**{k: row.get(k) for k in ("Type", "Value", "Run Domains", "Shared With", "Iris Search",
                                                  "Analyze As")},
                      "Iris Domains": count, "Score": min(100, score), "Reasons": reasons, "Stop": stop,
                      "Alerts": len(ties), "Seen": seen})
    return sorted(leads, key=lambda lead: (bool(lead["Stop"]), -lead["Score"], lead["Iris Domains"] or 10**9,
                                           lead["Type"], lead["Value"]))


def lookahead(lead, iris_results=None, index=None):
    """
    What following a lead would bring, from local data only: lines like "about 12 new domains (Iris count)", "seen
    with a.com, b.com in 2 earlier investigations (5 alerts)", and, when its Iris search was already made, the riskiest
    of those domains and how many earlier investigations flagged.
    """
    lines = []
    count = lead.get("Iris Domains")
    if count:
        new = max(0, count - int(lead.get("Run Domains") or 0))
        lines.append(f"about {new:,} domain(s) not in this run (Iris count)")
    for entry in (lead.get("Seen") or [])[:2]:
        domains = sorted(entry["domains"])
        lines.append(f"seen before in *{entry['label']}* with {', '.join(domains[:3])}"
                     + (f" +{len(domains) - 3}" if len(domains) > 3 else "")
                     + (f" ({entry['alerts']} alert(s) there)" if entry["alerts"] else ""))
    result = (iris_results or {}).get(lead.get("Iris Search"))
    if result is not None and getattr(result, "ok", False):
        frame = pivot_domains_frame(result.data)
        if not frame.empty:
            risky = frame.head(SAMPLE_DOMAINS)
            names = ", ".join(f"{d} ({r:.0f})" if pd.notna(r) else d for d, r in zip(risky["Domain"], risky["Risk Score"]))
            flagged = sum(1 for d in frame["Domain"]
                          if any(e["domains"].get(d) for e in (index or {}).get(d, {}).values()))
            lines.append(f"Iris search already made: {len(frame):,} domain(s), riskiest {names}"
                         + (f"; {flagged} flagged in earlier investigations" if flagged else ""))
    return lines


def followed(lead, children):
    """The run started from this lead, if any: `children` are the snapshots whose parent is the current run."""
    value = str(lead.get("Value", "")).lower()
    target = str(lead.get("Analyze As") or "").lower()
    for child in children:
        via = str((child.get("parent") or {}).get("via", "")).lower()
        targets = {str(t).lower() for t in child.get("targets") or []} | {str(t).lower() for t in child.get("seeds") or []}
        if value and (value in via or value in targets or (target and target in targets)):
            return child
    return None


def _indicators(alert):
    """(kind, value) of the indicators an alert names: JA4X, certificate hashes, IPs, then host names."""
    text = _alert_text(alert)
    found = [("JA4X", v) for v in JA4X_RE.findall(text)]
    found += [("Certificate", v) for v in SHA_RE.findall(text)]
    found += [("IP", v) for v in IP_RE.findall(text) if is_ip_address(v)]
    domain = str(alert.get("Domain") or "").lower()
    hosts = [h for h in HOST_RE.findall(text)
             if h != domain and not IP_RE.fullmatch(h) and not is_large_dns_provider(h) and not is_parking_ns(h)]
    found += [("Host", h) for h in hosts]
    return list(dict.fromkeys(found))


KIND_ORDER = {"JA4X": 0, "Certificate": 1, "IP": 2, "Host": 3}
KIND_PAGES = {"JA4X": "certs", "Certificate": "certs", "IP": "dns", "Host": "dns"}


def start_order(alerts, leads=None, limit=6):
    """
    Which indicators to confirm first, from the open alerts: [{"step", "kind", "value", "why", "page", "domains",
    "lead"}]. Indicators behind the most severe alerts come first; within a severity, what identifies the operator
    best goes first (a C2 JA4X, then the certificate, then the IP, then other hosts). An IP or certificate that is
    also a lead adds a step after it: the other domains that share it.
    """
    if alerts is None or alerts.empty:
        return []
    found = {}
    for alert in alerts.to_dict("records"):
        severity = alert.get("Severity")
        for kind, value in _indicators(alert):
            if kind == "IP" and (not is_public_ip(value) or cdn_for_ip(value)):
                continue
            entry = found.setdefault((kind, value), {"rank": 9, "alerts": [], "domains": set()})
            entry["rank"] = min(entry["rank"], SEVERITY_RANK.get(severity, 9))
            entry["alerts"].append((severity, alert.get("Threat Type")))
            entry["domains"].add(str(alert.get("Domain") or ""))
    leads_by_value = {str(lead["Value"]).lower(): lead for lead in leads or [] if not lead["Stop"]}
    ordered = sorted(found.items(), key=lambda item: (item[1]["rank"], KIND_ORDER[item[0][0]], -len(item[1]["alerts"]),
                                                      item[0][1]))
    steps = []
    for (kind, value), entry in ordered:
        if len(steps) >= limit:
            break
        worst = min(entry["alerts"], key=lambda a: SEVERITY_RANK.get(a[0], 9))
        types = sorted({a[1] for a in entry["alerts"]})
        steps.append({"kind": kind, "value": value, "page": KIND_PAGES[kind], "domains": sorted(entry["domains"]),
                      "why": f"{len(entry['alerts'])} alert(s), worst {worst[0]}: {', '.join(types[:2])}"
                             + (f" +{len(types) - 2}" if len(types) > 2 else ""), "lead": None})
        lead = leads_by_value.get(value)
        if lead and len(steps) < limit:
            steps.append({"kind": "Lead", "value": value, "page": "pivots", "domains": [],
                          "why": f"then the {lead['Iris Domains'] or 'other'} domains in Iris that share it",
                          "lead": lead})
    for number, step in enumerate(steps, 1):
        step["step"] = number
    return steps

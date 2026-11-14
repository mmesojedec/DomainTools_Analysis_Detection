"""
Data behind the visual run views: Recent runs on the Start page (timeline, cards with the change since the previous
run and a risk trend, runs per day) and the Hunting graph (runs linked by the lead they came from and by the IPs,
name servers, certificates, JA4X and trackers they share). Everything is read from the saved run snapshots
(dt_runs/), so none of it makes API calls.
"""
from collections import defaultdict
from functools import lru_cache

import pandas as pd

from core.helpers import is_ip_address
from core.network_intel import cdn_for_ip, is_large_dns_provider, is_parking_ns, is_public_ip
from core.run_history import SEVERITY_ORDER, alert_key_set, run_summary, snapshot_alerts

SEVERITY_COLORS = {"Critical": "#b91c1c", "High": "#dc2626", "Medium-High": "#ea580c", "Medium": "#d97706",
                   "Low": "#2563eb", "None": "#9ca3af"}
SHARED_KINDS = ("IP", "Name Server", "Certificate", "JA4X", "Web Tracker", "Email")   # artifact kinds that link runs
COMMON_LISTS = 5          # a value seen in more target lists than this is infrastructure everyone uses, not a link
TREND_RUNS = 8            # runs per target list in a card's risk trend
CALENDAR_WEEKS = 12       # weeks in the runs-per-day calendar
GRAPH_RUNS = 40           # newest runs the Hunting graph draws
GRAPH_SHARE_EDGES = 60    # most shared-artifact links it draws (the strongest first)


def _order(item):
    """Sort key of a (key, snapshot) pair: the run id is a UTC timestamp down to microseconds."""
    return str(item[1].get("id") or item[1].get("created"))


def _created(snapshot):
    return pd.to_datetime((snapshot or {}).get("created"), errors="coerce", utc=True)


def top_severity(summary):
    """The highest severity with alerts in a run's summary, or "None"."""
    by_severity = (summary or {}).get("by_severity") or {}
    return next((s for s in SEVERITY_ORDER if by_severity.get(s)), "None")


@lru_cache(maxsize=65536)
def _significant(kind, value):
    """Whether an artifact can link two investigations: not a CDN IP, a large DNS provider or a parking name server."""
    if kind == "IP" or (kind == "Name Server" and is_ip_address(value)):   # loopback, private and CDN IPs link nothing
        return is_public_ip(value) and cdn_for_ip(value) is None
    if kind == "Name Server":   # recorded as a host name, or as an IP (then a CDN's anycast DNS is common too)
        return not is_large_dns_provider(value) and not is_parking_ns(value) and cdn_for_ip(value) is None
    return True


def _artifact_values(snapshot):
    """{(kind, value): {domains}} of a run's artifacts that can link it to other runs."""
    values = defaultdict(set)
    for domain, kinds in ((snapshot or {}).get("artifacts") or {}).items():
        for kind in SHARED_KINDS:
            for value in kinds.get(kind) or []:
                if value and _significant(kind, value):
                    values[(kind, str(value))].add(str(domain).lower())
    return values


def shared_index(runs):
    """
    {(kind, value): {target list key: {domains}}} for values two to COMMON_LISTS target lists have. Values seen in only
    one list link nothing; values in more are shared hosting or services everyone uses.
    """
    index = defaultdict(lambda: defaultdict(set))
    for key, snapshot in runs:
        for item, domains in _artifact_values(snapshot).items():
            index[item][key] |= domains
    return {item: dict(keys) for item, keys in index.items() if 2 <= len(keys) <= COMMON_LISTS}


def _shared_by_key(runs):
    """
    {target list key: {other key: [(kind, value), ...]}}: values two lists have on different domains. Two lists
    that both analyzed a.com share all of a.com's artifacts; that says nothing, so a value only links the lists when
    the domains it belongs to in one list are not in the other.
    """
    shared = defaultdict(lambda: defaultdict(list))
    for item, keys in shared_index(runs).items():
        for key, domains in keys.items():
            for other, other_domains in keys.items():
                if other != key and not domains & other_domains:
                    shared[key][other].append(item)
    return shared


def recent_overview(runs, limit=10):
    """
    The `limit` newest runs (newest first) with what the visual views need: summary, top severity, alerts new and
    resolved since the previous run of the same target list, its risk trend, and the other target lists it shares
    artifacts with. `runs` is load_all_runs(): (key, snapshot), oldest first.
    """
    by_key = defaultdict(list)
    for key, snapshot in sorted(runs, key=_order):
        by_key[key].append(snapshot)
    shared = _shared_by_key(runs)
    rows = []
    for key, snapshot in sorted(runs, key=_order, reverse=True)[:limit]:
        history = by_key[key]
        position = next(i for i, s in enumerate(history) if s.get("id") == snapshot.get("id"))
        previous = history[position - 1] if position else None
        summary = run_summary(snapshot)
        change = None
        if previous is not None:
            now, before = alert_key_set(snapshot_alerts(snapshot)), alert_key_set(snapshot_alerts(previous))
            change = {"new": len(now - before), "resolved": len(before - now), "previous": previous.get("created")}
        trend = [run_summary(s).get("max_unified_risk") for s in history[max(0, position + 1 - TREND_RUNS):position + 1]]
        rows.append({
            "key": key, "id": snapshot.get("id"), "created": snapshot.get("created"), "name": snapshot.get("name") or "",
            "targets": snapshot.get("targets", []), "seeds": snapshot.get("seeds", []),
            "window": snapshot.get("window") or "", "options": snapshot.get("options") or {}, "summary": summary,
            "alerts": int(summary.get("alerts") or 0), "top_severity": top_severity(summary),
            "max_risk": summary.get("max_unified_risk"),
            "queries": sum((snapshot.get("queries") or {}).values()) if "queries" in snapshot else None,
            "parent": (snapshot.get("parent") or {}).get("id"), "change": change,
            "risk_trend": [None if value is None else float(value) for value in trend],
            "runs_of_list": len(history),
            "shared": {other: sorted(items) for other, items in shared.get(key, {}).items()},
        })
    return rows


def calendar_frame(runs, weeks=CALENDAR_WEEKS, today=None):
    """Runs per day for the last `weeks` weeks ending this week: columns Week (Monday), Weekday (0 = Monday), Date, Runs."""
    now = pd.Timestamp(today) if today is not None else pd.Timestamp.now(tz="UTC")
    today = (now.tz_convert(None) if now.tzinfo else now).normalize()
    start = today - pd.Timedelta(days=today.weekday()) - pd.Timedelta(weeks=weeks - 1)
    days = pd.date_range(start, start + pd.Timedelta(days=7 * weeks - 1), freq="D")
    counts = defaultdict(int)
    for _, snapshot in runs:
        created = _created(snapshot)
        if pd.notna(created):
            counts[created.tz_convert(None).normalize()] += 1
    return pd.DataFrame({"Date": days, "Week": [d - pd.Timedelta(days=d.weekday()) for d in days],
                         "Weekday": [d.weekday() for d in days], "Runs": [counts.get(d, 0) for d in days]})


def hunting_graph(runs, max_runs=GRAPH_RUNS, max_share_edges=GRAPH_SHARE_EDGES):
    """
    (nodes, edges) of the newest `max_runs` runs. Nodes: one per run (key, id, created, targets, alerts, top severity,
    max risk). Edges: {"source", "target", "kind": "lead", "via"} from a run to the run started from one of its leads,
    and {"source", "target", "kind": "shared", "items"} between the newest runs of two target lists that share
    artifacts (CDN IPs, large DNS providers and values in more than COMMON_LISTS lists left out), strongest first.
    """
    newest = sorted(runs, key=_order, reverse=True)[:max_runs]
    nodes = []
    for key, snapshot in sorted(newest, key=_order):
        summary = run_summary(snapshot)
        nodes.append({"id": snapshot.get("id"), "key": key, "created": snapshot.get("created"),
                      "targets": snapshot.get("targets", []), "seeds": snapshot.get("seeds", []),
                      "name": snapshot.get("name") or "", "alerts": int(summary.get("alerts") or 0),
                      "top_severity": top_severity(summary), "max_risk": summary.get("max_unified_risk"),
                      "options": snapshot.get("options") or {}, "window": snapshot.get("window") or "",
                      "parent": (snapshot.get("parent") or {}).get("id"),
                      "via": (snapshot.get("parent") or {}).get("via", "")})
    ids = {node["id"] for node in nodes}
    edges = [{"source": node["parent"], "target": node["id"], "kind": "lead", "via": node["via"]}
             for node in nodes if node["parent"] in ids]
    latest = {}
    for node in nodes:   # oldest first, so the newest run of each list wins
        latest[node["key"]] = node["id"]
    shared = _shared_by_key(newest)
    pairs = []
    for key, others in shared.items():
        for other, items in others.items():
            if key < other and key in latest and other in latest:
                pairs.append({"source": latest[key], "target": latest[other], "kind": "shared", "items": sorted(items)})
    pairs.sort(key=lambda edge: (-len(edge["items"]), edge["source"], edge["target"]))
    return nodes, edges + pairs[:max_share_edges]


def shared_text(items, limit=4):
    """"2 IPs, 1 certificate: 1.2.3.4, 5.6.7.8, …" for a list of (kind, value)."""
    by_kind = defaultdict(list)
    for kind, value in items:
        by_kind[kind].append(value)
    counts = ", ".join(f"{len(values)} {kind}{'s' if len(values) != 1 else ''}" for kind, values in by_kind.items())
    values = [value for _, value in items]
    return counts + ": " + ", ".join(values[:limit]) + (f", +{len(values) - limit} more" if len(values) > limit else "")


def shared_indicators(row, labels=None):
    """
    The indicators one run of recent_overview() shares with other target lists, one per indicator:
    {"Kind", "Indicator", "Lists" (how many other lists), "Also in" (their labels)}, most widely shared first.
    """
    labels = labels or {}
    by_item = defaultdict(list)
    for other, items in (row.get("shared") or {}).items():
        for item in items:
            by_item[tuple(item)].append(labels.get(other, other))
    rows = [{"Kind": kind, "Indicator": value, "Lists": len(others), "Also in": "; ".join(sorted(others))}
            for (kind, value), others in by_item.items()]
    return sorted(rows, key=lambda r: (-r["Lists"], SHARED_KINDS.index(r["Kind"]) if r["Kind"] in SHARED_KINDS
                                       else len(SHARED_KINDS), r["Indicator"]))


def top_shared(runs, labels=None, limit=25):
    """
    Indicators that link two or more target lists across every saved run (on different domains, CDN IPs and large
    DNS providers left out), most widely shared first: {"Kind", "Indicator", "Lists", "Target lists"}.
    """
    labels = labels or {}
    lists = defaultdict(set)
    for key, others in _shared_by_key(runs).items():
        for items in others.values():
            for item in items:
                lists[tuple(item)].add(key)
    rows = [{"Kind": kind, "Indicator": value, "Lists": len(keys),
             "Target lists": "; ".join(sorted(labels.get(key, key) for key in keys))}
            for (kind, value), keys in lists.items()]
    rows.sort(key=lambda r: (-r["Lists"], r["Kind"], r["Indicator"]))
    return rows[:limit]


def run_indicators(snapshot):
    """Every (kind, value) a run recorded (its targets and per-domain artifacts), sorted by kind then value."""
    found = {("Target", str(target)) for target in (snapshot or {}).get("targets") or []}
    for kinds in ((snapshot or {}).get("artifacts") or {}).values():
        for kind, values in (kinds or {}).items():
            found |= {(kind, str(value)) for value in values or [] if value}
    return sorted(found)


def filter_overview(rows, text="", only_alerts=False, only_new=False):
    """Rows of recent_overview() whose targets or name contain `text`, with alerts, or with new alerts since the
    previous run of the same list."""
    text = str(text or "").strip().lower()
    kept = []
    for row in rows:
        haystack = " ".join([*map(str, row.get("targets") or []), *map(str, row.get("seeds") or []),
                             str(row.get("name") or "")]).lower()
        if text and text not in haystack:
            continue
        if only_alerts and not row["alerts"]:
            continue
        if only_new and not (row["change"] is None and row["alerts"] or (row["change"] or {}).get("new")):
            continue
        kept.append(row)
    return kept

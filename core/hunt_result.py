"""
Where a hunt stands and what it found, from its saved runs (core.hunt_tree.hunt_members): what each run added to the
hunt (new domains, new alerts), whether the hunt is still growing, which runs stay linked to the starting point
through shared infrastructure, and the result: the cluster of domains linked to the start, the indicators most of them
share, and the alerts by type. No API calls.
"""
from collections import Counter, defaultdict

from core.run_history import SEVERITY_ORDER
from core.run_views import SHARED_KINDS, _significant

CONVERGE_DOMAINS = 2      # a run adding this many new domains or fewer, and no new kind of alert: converging
MAX_DEPTH = 4             # default hunt limits: runs deep, domains in the hunt
MAX_DOMAINS = 100
HIGH = {"Critical", "High"}
ROLE_MAILBOXES = {"abuse", "dns", "hostmaster", "postmaster", "webmaster", "admin", "noc", "support", "domains",
                  "domain", "privacy", "registrar", "info", "security", "compliance"}
PRIVACY_MAIL = ("withheldforprivacy", "contactprivacy", "privacyguardian", "domainsbyproxy", "whoisguard",
                "redacted", "proxy")
CORE_MIN = 2              # a core indicator is shared by at least this many cluster domains
STATUS_LABELS = {"growing": "Growing", "converging": "Converging", "done": "Done", "closed": "Closed"}


def norm(value):
    """A value as followed or recorded: lower case, without a `sha256:` / `sha1:` prefix."""
    text = str(value or "").strip().lower()
    for prefix in ("sha256:", "sha1:"):
        if text.startswith(prefix):
            return text[len(prefix):]
    return text


def followed_values(snapshots):
    """Every value a run of the hunt analyzed or started from (targets and certificate seeds), normalized."""
    return {norm(v) for snapshot in snapshots for v in [*(snapshot.get("targets") or []), *(snapshot.get("seeds") or [])]}


def linkable(kind, value):
    """Whether a value can tie two domains to one operator (not a CDN, large DNS provider, role or privacy mailbox)."""
    if kind not in SHARED_KINDS or not _significant(kind, value):
        return False
    if kind == "Email":
        local, _, domain = str(value).lower().partition("@")
        return local not in ROLE_MAILBOXES and not any(word in domain for word in PRIVACY_MAIL)
    return True


def domain_values(snapshot):
    """{domain: {(kind, value)}} of the linkable values a run recorded per domain."""
    values = {}
    for domain, kinds in (snapshot.get("artifacts") or {}).items():
        values[domain] = {(kind, norm(v)) for kind, items in kinds.items() for v in items or [] if linkable(kind, v)}
    return values


def _alert_keys(snapshot):
    return {(a.get("Domain"), a.get("Threat Type")): a.get("Severity") for a in snapshot.get("alerts") or []}


def _created(snapshot):
    return str(snapshot.get("created") or "")


def run_yield(snapshots):
    """
    {run id: {"new_domains", "new_alerts", "new_high", "new_types"}}: what each run added to the hunt beyond the runs
    made before it (new domains, new domain/threat-type alerts, how many of them Critical or High, new threat types).
    """
    seen_domains, seen_alerts, seen_types, result = set(), set(), set(), {}
    for snapshot in sorted(snapshots, key=_created):
        domains = set(snapshot.get("targets") or [])
        alerts = _alert_keys(snapshot)
        new_alerts = {key: severity for key, severity in alerts.items() if key not in seen_alerts}
        types = {key[1] for key in alerts}
        result[snapshot["id"]] = {"new_domains": len(domains - seen_domains), "new_alerts": len(new_alerts),
                                  "new_high": sum(severity in HIGH for severity in new_alerts.values()),
                                  "new_types": len(types - seen_types)}
        seen_domains |= domains
        seen_alerts |= set(alerts)
        seen_types |= types
    return result


def hunt_status(snapshots, depths, open_steps, max_depth=MAX_DEPTH, max_domains=MAX_DOMAINS, closed=None):
    """
    (status, reason): closed (a verdict was saved), done (no open step left, or a hunt limit reached), converging (the
    newest run added few domains and no new kind of alert) or growing.
    """
    if closed:
        return "closed", f"closed as {closed.get('verdict', 'done')}"
    newest = max(snapshots, key=_created)
    yields = run_yield(snapshots)[newest["id"]]
    domains = len({d for snapshot in snapshots for d in snapshot.get("targets") or []})
    if not open_steps:
        added = (f"; the newest run added {yields['new_domains']} new domain(s)" if len(snapshots) > 1 else "")
        return "done", "no open step left to follow" + added
    if max(depths) + 1 >= max_depth:
        return "done", f"{max(depths) + 1} runs deep (limit {max_depth})"
    if domains >= max_domains:
        return "done", f"{domains} domains in the hunt (limit {max_domains})"
    if len(snapshots) > 1 and yields["new_domains"] <= CONVERGE_DOMAINS and not yields["new_types"]:
        return "converging", (f"the newest run added {yields['new_domains']} new domain(s) and no new kind of alert: "
                              "following more steps is unlikely to find much")
    return "growing", ("the newest run added " f"{yields['new_domains']} new domain(s), {yields['new_alerts']} new "
                       f"alert(s)" if len(snapshots) > 1 else "the first run: its steps are still to follow")


def start_links(snapshots, root):
    """
    {run id: Counter of kinds, or None}: what each later run's new domains share with the first run's domains
    (certificates, IPs, name servers, trackers, emails). An empty Counter: no link (the hunt drifted); None: the run
    has no domain the first run didn't have.
    """
    root_domains = set(root.get("targets") or [])
    start = set().union(*domain_values(root).values()) if root.get("artifacts") else set()
    links = {}
    for snapshot in snapshots:
        if snapshot["id"] == root["id"]:
            continue
        new = {d: v for d, v in domain_values(snapshot).items() if d not in root_domains}
        if not new:
            links[snapshot["id"]] = None
            continue
        links[snapshot["id"]] = Counter(kind for kind, _ in set().union(*new.values()) & start)
    return links


def link_text(counter, limit=3):
    """'4 Certificate, 1 IP' for a start link."""
    return ", ".join(f"{count} {kind}" for kind, count in counter.most_common(limit))


def hunt_result(snapshots, root):
    """
    {"cluster": [{"Domain", "Linked by", "First run"}], "core": [{"Kind", "Value", "Domains"}], "alerts": [{"Threat
    Type", "Domains", "Worst"}], "drifted": [run ids]}: the domains linked to the first run (its own domains, and every
    later domain sharing a value with them), the values most of them share, and the alerts across the hunt.
    """
    ordered = sorted(snapshots, key=_created)
    values, first_run = {}, {}
    for snapshot in ordered:
        for domain, items in domain_values(snapshot).items():
            values.setdefault(domain, set()).update(items)
            first_run.setdefault(domain, snapshot["id"])
    root_domains = set(root.get("targets") or [])
    for domain in root_domains:   # a starting domain is in the cluster even with nothing recorded
        values.setdefault(domain, set())
        first_run.setdefault(domain, root["id"])
    start = set().union(*(values.get(d, set()) for d in root_domains)) if root_domains else set()
    cluster = []
    for domain in sorted(values, key=lambda d: (first_run[d], d)):
        shared = values[domain] & start
        if domain in root_domains or shared:
            kinds = Counter(kind for kind, _ in shared)
            cluster.append({"Domain": domain, "Linked by": "starting point" if domain in root_domains else
                            link_text(kinds), "First run": first_run[domain]})
    members = {row["Domain"] for row in cluster}
    holders = defaultdict(set)
    for domain in members:
        for item in values.get(domain, ()):
            holders[item].add(domain)
    core = [{"Kind": kind, "Value": value, "Domains": len(domains), "Shared by": sorted(domains)}
            for (kind, value), domains in holders.items() if len(domains) >= CORE_MIN]
    core.sort(key=lambda row: (-row["Domains"], row["Kind"], row["Value"]))
    alerts = {}
    for snapshot in ordered:
        alerts.update(_alert_keys(snapshot))
    by_type = defaultdict(list)
    for (domain, kind), severity in alerts.items():
        by_type[kind].append((domain, severity))
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    alert_rows = [{"Threat Type": kind, "Domains": len({d for d, _ in rows}),
                   "Worst": min((s for _, s in rows), key=lambda s: rank.get(s, 99))}
                  for kind, rows in by_type.items()]
    alert_rows.sort(key=lambda row: (rank.get(row["Worst"], 99), -row["Domains"], row["Threat Type"]))
    links = start_links(snapshots, root)
    return {"cluster": cluster, "core": core, "alerts": alert_rows,
            "drifted": [run_id for run_id, counter in links.items() if counter is not None and not counter]}


def top_types(snapshot, limit=2):
    """[(threat type, domain count)] of a run's most common alerts."""
    counts = Counter(kind for _, kind in _alert_keys(snapshot))
    return counts.most_common(limit)

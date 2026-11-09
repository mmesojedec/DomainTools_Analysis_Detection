"""
CNAME chains: which hostnames of the run point elsewhere by CNAME, where each chain ends (as in DNSDB Scout's CNAME
chasing) and what kind of service the targets run on (dynamic DNS or tunnel, takeover-prone, free hosting, CDN).
A chain is first followed through the run's own passive DNS; where it leaves the collected data, a DNSDB chase
(integrations.dnsdb.chase_cname) of that name continues it.
"""
import pandas as pd

from config import CNAME_CHASE_MAX_STEPS
from core.hostnames import apex_of, clean_hostname
from core.intel_data import (
    CDN_CNAME_SUFFIXES,
    DYNAMIC_DNS_CNAME_SUFFIXES,
    PARKING_CNAME_SUFFIXES,
    SHARED_PLATFORMS,
    TAKEOVER_CNAME_SUFFIXES,
)

CNAME_COLUMNS = ["Domain", "Hostname", "Target", "Current", "First Seen", "Last Seen", "Count", "Target Domain",
                 "External", "Service Type", "Service", "Chain", "Hops", "Outcome", "Final", "Final Last Seen", "Note",
                 "Chased At", "From Cache"]
# Chased At: when its DNSDB lookups were made (UTC; for cached lookups, when they were first fetched);
# From Cache: every lookup of the chase came from the cache (Settings → Lookup cache)
CHASE_COLUMNS = ["Start", "Path", "Hops", "Outcome", "Final", "Final Last Seen", "Note", "Chased At", "From Cache"]
# service type -> explanation; checked in this order (a tunnel service that is also a shared platform is a tunnel)
SERVICE_TYPES = {
    "Dynamic DNS / tunnel": "Dynamic DNS or tunnelling service: the name follows a home or attacker machine, or exposes "
                            "a local service (ngrok, Cloudflare quick tunnels, Duck DNS, No-IP, ...)",
    "Takeover-prone": "Service where a deleted resource leaves the CNAME claimable by anyone (S3, Azure, Heroku, GitHub "
                      "Pages, Shopify, ...): subdomain takeover if the chain dead-ends",
    "Free hosting": "Free or self-service hosting platform anyone can publish on (pages.dev, workers.dev, Vercel, ...)",
    "CDN": "Content delivery network in front of the real origin",
    "Parking": "Domain parking or for-sale page (Namecheap, Porkbun, Sedo, Bodis, ...): shared by thousands of "
               "unrelated domains",
}
# shared by unrelated customers: links through these are weak and reverse lookups of them are noise
SHARED_SERVICE_TYPES = ("CDN", "Parking")
NOT_CHASED = "Not chased"
QUERY_LIMIT = "Query limit"    # a chase stopped at its domain's query budget; the next chase continues where it stopped
COLLECTED = "Collected data"   # chain resolved inside the run's own passive DNS, no chase needed
CURRENT_SLACK = pd.Timedelta(days=1)


def _suffix_match(name, suffixes):
    return next((suffixes[s] for s in suffixes if name == s or name.endswith("." + s)), None)


def classify_target(name):
    """(service type, service name) of a CNAME target; ("", "") for an ordinary domain."""
    name = clean_hostname(name)
    for kind, suffixes in (("Dynamic DNS / tunnel", DYNAMIC_DNS_CNAME_SUFFIXES), ("Takeover-prone", TAKEOVER_CNAME_SUFFIXES),
                           ("CDN", CDN_CNAME_SUFFIXES), ("Parking", PARKING_CNAME_SUFFIXES)):
        service = _suffix_match(name, suffixes)
        if service:
            return kind, service
    if ".s3." in f".{name}" and name.endswith(".amazonaws.com") or ".s3-website" in name:   # regional S3 endpoints
        return "Takeover-prone", "AWS S3"
    platform = _suffix_match(name, {p: p for p in SHARED_PLATFORMS})
    return ("Free hosting", platform) if platform else ("", "")


def _typed(pdns, rrtypes):
    columns = ["Domain", "RRName", "Value", "First Seen", "Last Seen", "Count", "Collection"]
    if pdns is None or pdns.empty or not {"Domain", "Field", "Value", "RRName"} <= set(pdns.columns):
        return pd.DataFrame(columns=columns)
    fields = pdns["Field"].astype(str).str.upper().str.replace(r"^(?:PDNS|DH):\s*", "", regex=True)
    rows = pdns.loc[fields.isin(rrtypes)].reindex(columns=columns)
    if "First Seen" not in pdns.columns and "Date" in pdns.columns:   # event frames without pDNS dates
        rows["First Seen"] = pdns.loc[rows.index, "Date"]
    rows["RRName"] = rows["RRName"].map(clean_hostname)
    rows["Value"] = rows["Value"].astype(str).str.split("\n")
    rows = rows.explode("Value")
    rows["Value"] = rows["Value"].map(clean_hostname)
    rows["Last Seen"] = pd.to_datetime(rows["Last Seen"], errors="coerce").fillna(pd.to_datetime(rows["First Seen"], errors="coerce"))
    return rows[rows["Value"] != ""]


def latest_values(rows):
    """{name: (latest Last Seen, values seen within a day of it)} for typed passive DNS rows."""
    if rows.empty:
        return {}
    newest = rows.groupby("RRName")["Last Seen"].transform("max")
    recent = rows[rows["Last Seen"] >= newest - CURRENT_SLACK]
    return {name: (group["Last Seen"].max(), list(dict.fromkeys(group.sort_values("Last Seen", ascending=False)["Value"])))
            for name, group in recent.groupby("RRName")}


def walk_chain(hostname, target, cnames, addresses, chases, max_steps=CNAME_CHASE_MAX_STEPS):
    """
    Follows `hostname` → `target` through the collected records (`cnames` / `addresses` from latest_values) and, where
    they end, the DNSDB chase of that name (`chases`: start name -> chase dict). Returns a dict with Chain (names),
    Hops (CNAMEs followed), Outcome, Final, Final Last Seen and Note, plus Chased At and From Cache of the DNSDB chase
    used (NaT / False when none was).
    """
    chain, name = [hostname, target], target
    meta = {"Chased At": pd.NaT, "From Cache": False}

    def done(**fields):
        return {**fields, **meta}

    for _ in range(max_steps):
        chase = chases.get(name)
        if chase is not None:
            meta = {"Chased At": pd.to_datetime(chase.get("Chased At"), errors="coerce"),
                    "From Cache": bool(chase.get("From Cache") is True)}
        if chase is not None and chase["Outcome"] == QUERY_LIMIT:
            further = [n for n in str(chase["Path"]).split(" → ")[1:] if n]
            if further:   # a partial chase: carry on from where it stopped (collected data or a later chase)
                chain += further
                name = further[-1]
                continue
            chase = None
        if chase is not None:
            chain += [n for n in str(chase["Path"]).split(" → ")[1:] if n]
            return done(Chain=chain, Hops=len(chain) - 1, Outcome=chase["Outcome"], Final=chase["Final"],
                        **{"Final Last Seen": chase["Final Last Seen"]}, Note=chase["Note"])
        cname_seen, next_names = cnames.get(name, (pd.NaT, []))
        addr_seen, addrs = addresses.get(name, (pd.NaT, []))
        if next_names and (pd.isna(addr_seen) or cname_seen >= addr_seen):
            if next_names[0] in chain:
                return done(Chain=chain + [next_names[0]], Hops=len(chain), Outcome="Loop", Final="",
                            **{"Final Last Seen": pd.NaT}, Note=f"{name} points back to {next_names[0]}")
            chain.append(next_names[0])
            name = next_names[0]
            continue
        if addrs:
            return done(Chain=chain, Hops=len(chain) - 1, Outcome="Resolves", Final=", ".join(addrs),
                        **{"Final Last Seen": addr_seen}, Note=COLLECTED)
        return done(Chain=chain, Hops=len(chain) - 1, Outcome=NOT_CHASED, Final="", **{"Final Last Seen": pd.NaT},
                    Note=f"{name} is not in the collected passive DNS")
    return done(Chain=chain, Hops=len(chain) - 1, Outcome="Step limit", Final="", **{"Final Last Seen": pd.NaT},
                Note=f"Stopped after {max_steps} steps")


def chases_by_start(chases):
    if chases is None or chases.empty:
        return {}
    return {row["Start"]: row for row in chases.to_dict("records")}


def build_cname_map(pdns, chases=None, max_steps=CNAME_CHASE_MAX_STEPS):
    """
    One row (CNAME_COLUMNS) per (domain, hostname, CNAME target) in the passive DNS, with where its chain ends.
    `Current` marks the targets a hostname pointed to most recently (and not replaced by A / AAAA records since).
    Current rows first, then by last seen.
    """
    cname_rows = _typed(pdns, ("CNAME",))
    if cname_rows.empty:
        return pd.DataFrame(columns=CNAME_COLUMNS)
    addr_rows = _typed(pdns, ("A", "AAAA"))
    cnames, addresses = latest_values(cname_rows), latest_values(addr_rows)
    chase_index = chases_by_start(chases)
    grouped = cname_rows.groupby(["Domain", "RRName", "Value"], sort=False).agg(
        **{"First Seen": ("First Seen", "min"), "Last Seen": ("Last Seen", "max")}).reset_index()
    # DNSDB count (times the record was seen): the main lookup holds time slices of a record and the CNAME lookup
    # one aggregated record, so the larger of the two sums, not both
    aggregated = cname_rows["Collection"].astype(str).str.contains("lookup|supplement", case=False)
    counts = pd.to_numeric(cname_rows["Count"], errors="coerce").fillna(0).groupby(
        [cname_rows["Domain"], cname_rows["RRName"], cname_rows["Value"], aggregated]).sum() \
        .groupby(level=[0, 1, 2]).max()
    rows, walked = [], {}
    for rec in grouped.to_dict("records"):
        domain, hostname, target = rec["Domain"], rec["RRName"], rec["Value"]
        cname_seen, current_targets = cnames.get(hostname, (pd.NaT, []))
        addr_seen = addresses.get(hostname, (pd.NaT, []))[0]
        current = target in current_targets and (pd.isna(addr_seen) or addr_seen <= cname_seen + CURRENT_SLACK)
        if target not in walked:
            walked[target] = walk_chain(hostname, target, cnames, addresses, chase_index, max_steps)
        walk = walked[target]
        chain = [hostname] + walk["Chain"][1:]
        kind, service = classify_target(target)
        dom = clean_hostname(domain)
        external = not (target == dom or target.endswith("." + dom))
        if kind == "Free hosting" and not external:   # a name on the analyzed platform itself (pages.dev → pages.dev)
            kind, service = "", ""
        rows.append({
            "Domain": domain, "Hostname": hostname, "Target": target, "Current": bool(current),
            "First Seen": pd.to_datetime(rec["First Seen"], errors="coerce"), "Last Seen": rec["Last Seen"],
            "Count": int(counts.get((domain, hostname, target), 0)), "Target Domain": apex_of(target), "External": external,
            "Service Type": kind, "Service": service, "Chain": " → ".join(chain), "Hops": walk["Hops"],
            "Outcome": walk["Outcome"], "Final": walk["Final"], "Final Last Seen": walk["Final Last Seen"],
            "Note": walk["Note"], "Chased At": walk["Chased At"], "From Cache": walk["From Cache"],
        })
    frame = pd.DataFrame(rows, columns=CNAME_COLUMNS)
    return frame.sort_values(["Current", "Last Seen", "Hostname"], ascending=[False, False, True], na_position="last",
                             kind="stable").reset_index(drop=True)


CHASE_PRIORITY = {"Dynamic DNS / tunnel": 0, "Takeover-prone": 1, "Free hosting": 2, "": 3, "CDN": 4, "Parking": 4}
INTERNAL_PRIORITY = 5
HISTORY_PRIORITY = 10   # earlier targets after every current one


def chase_plan(cname_map, rechase=False, chases=None):
    """
    What a chase click looks up, per domain: {domain: [names]} for the rows (`cname_map`, already narrowed to the
    selected or shown hostnames) whose chain leaves the collected data, starting where it leaves it. Within a domain:
    dynamic DNS, takeover-prone and free hosting targets first (the detections need their outcome), then other
    external targets, CDNs and parking, then targets inside the analyzed domain the capped lookup missed, earlier
    (no longer current) targets after current ones; the name most hostnames lead to first within each. A name shared
    by several domains is chased once, for the first. With `rechase`, rows already chased in DNSDB are chased again
    from where their chase started (`chases`, CHASE_COLUMNS).
    """
    if cname_map is None or cname_map.empty:
        return {}
    open_rows = cname_map[cname_map["Outcome"] == NOT_CHASED]
    if rechase and chases is not None and not chases.empty:
        starts = set(chases["Start"])
        redo = cname_map[(cname_map["Note"] != COLLECTED) & (cname_map["Outcome"] != NOT_CHASED)]
        first = redo["Chain"].str.split(" → ").map(lambda names: next((n for n in names[1:] if n in starts), None))
        redo = redo.assign(Chain=redo["Chain"].str.split(" → ").str[0] + " → " + first)[first.notna()]
        open_rows = pd.concat([open_rows, redo])
    if open_rows.empty:
        return {}
    rank = open_rows["Service Type"].map(CHASE_PRIORITY).where(open_rows["External"], INTERNAL_PRIORITY) \
        + (~open_rows["Current"].astype(bool)) * HISTORY_PRIORITY
    ranked = open_rows.assign(_start=open_rows["Chain"].str.split(" → ").str[-1], _rank=rank)
    ranked = ranked.groupby(["Domain", "_start"], sort=False).agg(
        _rank=("_rank", "min"), _hosts=("Hostname", "nunique"), _seen=("Last Seen", "max")).reset_index()
    ranked = ranked.sort_values(["_rank", "_hosts", "_seen"], ascending=[True, False, False], kind="stable") \
        .drop_duplicates("_start")
    order = list(dict.fromkeys(cname_map["Domain"]))
    return {domain: list(ranked.loc[ranked["Domain"] == domain, "_start"])
            for domain in order if (ranked["Domain"] == domain).any()}


def full_path(domain, chain, final="", outcome=""):
    """A chain as read from the analyzed domain: domain → hostname → targets → final addresses (or the outcome)."""
    names = str(chain).split(" → ")
    domain = clean_hostname(domain)
    path = " → ".join(([domain] if domain and names[0] != domain else []) + names)
    if final:
        return f"{path} → {final}"
    return f"{path} ({outcome})" if outcome and outcome != "Resolves" else path


def order_by_domain(cname_map, domains=()):
    """Rows grouped by domain (in the order of `domains`, then alphabetically), current first, then most recent."""
    if cname_map is None or cname_map.empty:
        return cname_map
    order = {clean_hostname(d): i for i, d in enumerate(domains)}
    rank = cname_map["Domain"].map(lambda d: (order.get(clean_hostname(d), len(order)), clean_hostname(d)))
    return cname_map.assign(_d=rank).sort_values(["_d", "Current", "Last Seen", "Hostname"],
                                                 ascending=[True, False, False, True], na_position="last",
                                                 kind="stable").drop(columns="_d").reset_index(drop=True)


LINK_KINDS = {
    "CNAME into analyzed domain": "A hostname of one analyzed domain points by CNAME (directly or further down the "
                                  "chain) to a name of another analyzed domain",
    "Shared CNAME": "Chains of several analyzed domains pass through the same name outside all of them",
    "Shared final address": "Chains of several analyzed domains end at the same IP address",
}
LINK_COLUMNS = ["Link", "Kind", "Service Type", "Service", "Domains", "Domain Count", "Hostnames", "Examples"]


def _owner(name, domains):
    return next((d for d in domains if name == d or name.endswith("." + d)), None)


def cname_links(cname_map, domains=(), rdata=None):
    """
    Cross-domain CNAME connections (LINK_COLUMNS), from every name and final address in the chains: names of one
    analyzed domain (`domains` plus the domains of the map) reached from another, and names or addresses outside them
    that 2+ analyzed domains reach. Reverse CNAME results (`rdata`, RDATA_COLUMNS) add the analyzed domains DNSDB saw
    pointing to a name that the collected passive DNS missed.
    Service Type "CDN" or "Parking" marks links through a shared service (weak: unrelated customers share them).
    """
    if cname_map is None or cname_map.empty:
        return pd.DataFrame(columns=LINK_COLUMNS)
    domains = sorted({clean_hostname(d) for d in [*cname_map["Domain"], *domains]} - {""}, key=len, reverse=True)
    hits = []   # (link, kind, linked domain, hostname, chain, through CDN)
    for row in cname_map.to_dict("records"):
        names = str(row["Chain"]).split(" → ")[1:]
        source = clean_hostname(row["Domain"])
        via_cdn = next((kind for kind in (classify_target(n)[0] for n in names) if kind in SHARED_SERVICE_TYPES), "")
        for name in dict.fromkeys(names):
            owner = _owner(name, domains)
            if owner is None:
                hits.append((name, "Shared CNAME", source, row["Hostname"], row["Chain"], ""))
            elif owner != source:
                hits += [(name, "CNAME into analyzed domain", d, row["Hostname"], row["Chain"], "")
                         for d in (source, owner)]
        for address in filter(None, str(row["Final"] or "").split(", ")):
            hits.append((address, "Shared final address", source, row["Hostname"], row["Chain"], via_cdn))
    if rdata is not None and not rdata.empty:
        for row in rdata[rdata["Analyzed"]].to_dict("records"):
            owner = _owner(row["Target"], domains)
            kind = "Shared CNAME" if owner is None else "CNAME into analyzed domain"
            hits += [(row["Target"], kind, d, row["Hostname"], f"{row['Hostname']} → {row['Target']}", "")
                     for d in {row["Apex"], owner} - {None}]
    if not hits:
        return pd.DataFrame(columns=LINK_COLUMNS)
    hits = [h for h in hits if h[2] in domains]
    frame = pd.DataFrame(hits, columns=["Link", "Kind", "Domain", "Hostname", "Chain", "CDN"])
    if frame.empty:
        return pd.DataFrame(columns=LINK_COLUMNS)
    rows = []
    for (link, kind), group in frame.groupby(["Link", "Kind"], sort=False):
        linked = sorted(set(group["Domain"]))
        if len(linked) < 2:
            continue
        kind_type, service = classify_target(link) if kind != "Shared final address" else \
            (next((kind for kind in group["CDN"] if kind), ""), "")
        rows.append({"Link": link, "Kind": kind, "Service Type": kind_type, "Service": service,
                     "Domains": ", ".join(linked), "Domain Count": len(linked),
                     "Hostnames": group["Hostname"].nunique(),
                     "Examples": "\n".join(list(dict.fromkeys(group["Chain"]))[:3])})
    if not rows:
        return pd.DataFrame(columns=LINK_COLUMNS)
    order = {kind: i for i, kind in enumerate(LINK_KINDS)}
    links = pd.DataFrame(rows, columns=LINK_COLUMNS)
    return links.assign(_k=links["Kind"].map(order), _cdn=links["Service Type"].isin(SHARED_SERVICE_TYPES)) \
        .sort_values(["_cdn", "_k", "Domain Count", "Hostnames"], ascending=[True, True, False, False], kind="stable") \
        .drop(columns=["_k", "_cdn"]).reset_index(drop=True)


def merge_chases(old, new):
    """
    Chase rows of `old` and `new`, one per start name: the most recently chased (Chased At) wins, `new` on a tie or
    when either has no time.
    """
    frames = [f for f in (old, new) if f is not None and not f.empty]
    if not frames:
        return pd.DataFrame(columns=CHASE_COLUMNS)
    merged = pd.concat(frames, ignore_index=True).reindex(columns=CHASE_COLUMNS)
    seen = pd.to_datetime(merged["Chased At"], errors="coerce")
    if seen.notna().all():
        merged = merged.assign(_seen=seen).sort_values("_seen", kind="stable").drop(columns="_seen")
    return merged.drop_duplicates(subset="Start", keep="last").reset_index(drop=True)


def dataset_cname_map(ds):
    """The CNAME map of a Dataset (analysis window, filters and hostname focus applied), built once per set of chases."""
    key = ("cname_map", id(ds.cname_chases))
    if key not in ds.derived:
        ds.derived = {k: v for k, v in ds.derived.items() if not (isinstance(k, tuple) and k[0] == "cname_map")}
        ds.derived[key] = build_cname_map(ds.pdns_utc, ds.cname_chases)
    return ds.derived[key]


RDATA_COLUMNS = ["Target", "Hostname", "Apex", "Analyzed", "First Seen", "Last Seen", "Count", "Truncated"]
RDATA_TARGET_COLUMNS = ["Target", "Other Domains", "Names", "Analyzed Domains", "First Seen", "Last Seen", "Truncated"]
RELATED_COLUMNS = ["Domain", "Analyzed", "Targets", "Target Shared By", "Hostnames", "Examples", "First Seen", "Last Seen"]


def rdata_rows(target, records, analyzed_domains=(), truncated=False):
    """
    RDATA_COLUMNS rows of a reverse CNAME lookup: one per name DNSDB saw pointing to `target` by CNAME (its records
    across sensors and zones merged). `truncated`: the lookup stopped at its limit, more names exist.
    """
    analyzed = {clean_hostname(d) for d in analyzed_domains}
    rows = []
    for rec in records or []:
        if str(rec.get("rrtype", "CNAME")).upper() != "CNAME":
            continue
        hostname = clean_hostname(rec.get("rrname", ""))
        first, last = rec.get("time_first") or rec.get("zone_time_first"), rec.get("time_last") or rec.get("zone_time_last")
        apex = apex_of(hostname)
        rows.append({"Target": clean_hostname(target), "Hostname": hostname, "Apex": apex, "Analyzed": apex in analyzed,
                     "First Seen": pd.to_datetime(first, unit="s", errors="coerce"),
                     "Last Seen": pd.to_datetime(last, unit="s", errors="coerce"), "Count": rec.get("count") or 0,
                     "Truncated": bool(truncated)})
    if not rows:
        return pd.DataFrame(columns=RDATA_COLUMNS)
    return pd.DataFrame(rows).groupby(["Target", "Hostname"], sort=False, as_index=False).agg(
        {"Apex": "first", "Analyzed": "first", "First Seen": "min", "Last Seen": "max", "Count": "sum",
         "Truncated": "first"})[RDATA_COLUMNS]


def merge_rdata(old, new):
    """Reverse CNAME rows of `old` and `new`; a newer lookup of the same target replaces the older one."""
    frames = [f for f in (old, new) if f is not None and not f.empty]
    if not frames:
        return pd.DataFrame(columns=RDATA_COLUMNS)
    if len(frames) == 2:
        frames[0] = frames[0][~frames[0]["Target"].isin(set(frames[1]["Target"]))]
    return pd.concat(frames, ignore_index=True)


def rdata_summary(rdata, cname_map=None):
    """
    One row (RDATA_TARGET_COLUMNS) per looked-up target: how many names and other domains point to it. Analyzed
    domains include those whose own chains (`cname_map`) pass through the target, also when a truncated lookup missed
    them.
    """
    if rdata is None or rdata.empty:
        return pd.DataFrame(columns=RDATA_TARGET_COLUMNS)
    chains = [] if cname_map is None or cname_map.empty else \
        list(zip(cname_map["Domain"], cname_map["Chain"].str.split(" → ").str[1:]))
    rows = []
    for target, group in rdata.groupby("Target", sort=False):
        analyzed = set(group.loc[group["Analyzed"], "Apex"]) | {clean_hostname(d) for d, names in chains if target in names}
        rows.append({"Target": target, "Other Domains": group.loc[~group["Analyzed"], "Apex"].nunique(),
                     "Names": group["Hostname"].nunique(), "Analyzed Domains": ", ".join(sorted(analyzed)),
                     "First Seen": group["First Seen"].min(), "Last Seen": group["Last Seen"].max(),
                     "Truncated": bool(group["Truncated"].fillna(False).any())})
    return pd.DataFrame(rows, columns=RDATA_TARGET_COLUMNS).sort_values("Other Domains", kind="stable") \
        .reset_index(drop=True)


def related_domains(rdata):
    """
    One row (RELATED_COLUMNS) per registrable domain DNSDB saw pointing to the looked-up targets: other domains first,
    those pointing to several of the targets first, then those on the most dedicated target (fewest domains share it,
    `Target Shared By`).
    """
    if rdata is None or rdata.empty:
        return pd.DataFrame(columns=RELATED_COLUMNS)
    shared_by = rdata.groupby("Target")["Apex"].nunique()
    rows = []
    for apex, group in rdata.groupby("Apex", sort=False):
        hostnames = list(dict.fromkeys(group.sort_values("Last Seen", ascending=False)["Hostname"]))
        rows.append({"Domain": apex, "Analyzed": bool(group["Analyzed"].any()),
                     "Targets": ", ".join(sorted(set(group["Target"]))),
                     "Target Shared By": int(shared_by[list(set(group["Target"]))].min()), "Hostnames": len(hostnames),
                     "Examples": ", ".join(hostnames[:3]) + (f" +{len(hostnames) - 3} more" if len(hostnames) > 3 else ""),
                     "First Seen": group["First Seen"].min(), "Last Seen": group["Last Seen"].max()})
    frame = pd.DataFrame(rows, columns=RELATED_COLUMNS)
    return frame.assign(_n=frame["Targets"].str.count(", ")).sort_values(
        ["Analyzed", "_n", "Target Shared By", "Last Seen"], ascending=[True, False, True, False], kind="stable") \
        .drop(columns="_n").reset_index(drop=True)


def rdata_candidates(cname_map, max_targets, skip_shared=True):
    """
    Chain names worth a reverse CNAME lookup: external names, one per domain first; without CDN and parking targets
    (`skip_shared`), whose reverse lookups only list unrelated customers.
    """
    if cname_map is None or cname_map.empty or max_targets <= 0:
        return []
    picks = []
    for row in cname_map.sort_values(["Current", "Last Seen"], ascending=[False, False]).to_dict("records"):
        domain = clean_hostname(row["Domain"])
        for turn, name in enumerate(str(row["Chain"]).split(" → ")[1:]):
            if not (name == domain or name.endswith("." + domain)) and \
                    not (skip_shared and classify_target(name)[0] in SHARED_SERVICE_TYPES):
                picks.append((turn, domain, name))
    ordered, seen_per_domain = [], {}
    for turn, domain, name in picks:
        seen_per_domain[domain] = seen_per_domain.get(domain, -1) + 1
        ordered.append((seen_per_domain[domain], turn, name))
    return list(dict.fromkeys(name for *_, name in sorted(ordered, key=lambda x: (x[0], x[1]))))[:max_targets]

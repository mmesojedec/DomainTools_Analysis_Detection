"""Cross-domain correlation: shared-infrastructure clusters and domain hopping on shared IPs."""
from dataclasses import dataclass, field
from itertools import combinations

import pandas as pd

from config import COMMON_LINK_MIN, PIVOT_STRONG_MAX, RARE_LINK_MAX
from core.cert_utils import publicly_trusted
from core.cname import classify_target
from core.helpers import is_ip_address, registrable_domain
from core.network_intel import (
    cdn_for_cname,
    cdn_for_ip,
    explode_ip_events,
    is_large_dns_provider,
    is_parking_ns,
    is_public_ip,
    record_types,
)
from integrations.enrichment import extract_iris_profile, extract_web_trackers

STRONG_ARTIFACTS = {"Certificate", "Public Key", "Web Tracker", "JA4X"}
WEAK_ARTIFACTS = {"IP", "Name Server", "CNAME Target"}
ARTIFACT_COLUMNS = ["Domain", "Type", "Value"]
# Iris counts how many domains use an IP, a name server or a tracker: a value on few domains links its domains
# strongly, one on very many links nothing (shared hosting, big DNS providers, a common analytics account)
MAX_DOMAINS_PER_ARTIFACT = 200
NS_FIELDS = {"NS", "NAME_SERVER"}


@dataclass
class Correlation:
    artifacts: pd.DataFrame = field(default_factory=lambda: pd.DataFrame(columns=ARTIFACT_COLUMNS))
    shared: pd.DataFrame = field(default_factory=pd.DataFrame)
    pairs: pd.DataFrame = field(default_factory=pd.DataFrame)
    clusters: list = field(default_factory=list)
    domain_cluster: dict = field(default_factory=dict)


def link_strength(kind, count):
    """
    "strong", "weak" or None (no link) for a shared value of `kind` that Iris sees on `count` domains (None: unknown).
    """
    if count is not None and count > COMMON_LINK_MIN:
        return None
    if kind in ("IP", "Name Server"):
        return "strong" if count is not None and count <= RARE_LINK_MAX else "weak"
    if kind == "Web Tracker":
        return "strong" if count is None or count <= PIVOT_STRONG_MAX else "weak"
    return "strong" if kind in STRONG_ARTIFACTS else "weak"


def artifact_counts(enrichment):
    """{(type, value): domains in Iris} for the IPs, name servers and web trackers of the Iris records."""
    counts = {}
    for obj in (enrichment or {}).values():
        profile = extract_iris_profile(obj)
        for entry in profile["ips"]:
            if isinstance(entry.get("count"), int):
                counts[("IP", entry["ip"])] = entry["count"]
        for host, count in profile.get("name_server_counts", {}).items():
            counts[("Name Server", host)] = count
        for tracker in extract_web_trackers(obj):
            if isinstance(tracker.get("Count"), int):
                counts[("Web Tracker", f"{tracker['Platform']}: {tracker['Code']}")] = tracker["Count"]
    return counts


def collect_artifacts(events, ssl, enrichment, ip_intel, allowlist=None):
    """
    Distinct (domain, artifact type, value) triples. CDN IPs, private IPs, large DNS providers and values Iris sees on
    more than COMMON_LINK_MIN domains are excluded. A JA4X counts only off public CAs (theirs are shared by design).
    """
    rows = set()
    if events is not None and not events.empty:
        for _, row in explode_ip_events(events).iterrows():
            if is_public_ip(row["IP"]) and not cdn_for_ip(row["IP"], ip_intel):
                rows.add((row["Domain"], "IP", row["IP"]))
        ns_rows = events[record_types(events).isin(NS_FIELDS)]
        for domain, value in zip(ns_rows["Domain"], ns_rows["Value"].astype(str)):
            for host in value.split("\n"):
                host = host.strip().lower().rstrip(".")
                if host and not is_large_dns_provider(host) and not is_parking_ns(host):
                    rows.add((domain, "Name Server", host))
        cname_rows = events[record_types(events) == "CNAME"]
        for domain, value in zip(cname_rows["Domain"], cname_rows["Value"].astype(str)):
            target = value.strip().lower().rstrip(".")
            if target and not cdn_for_cname(target) and classify_target(target)[0] != "Parking" \
                    and not target.endswith("." + str(domain).lower()):
                rows.add((domain, "CNAME Target", target))
    for domain, obj in (enrichment or {}).items():
        profile = extract_iris_profile(obj)
        for entry in profile["ips"]:
            if is_public_ip(entry["ip"]) and not cdn_for_ip(entry["ip"], ip_intel):
                rows.add((domain, "IP", entry["ip"]))
        for host in profile["name_servers"]:
            if not is_large_dns_provider(host) and not is_parking_ns(host):
                rows.add((domain, "Name Server", host))
        for tracker in extract_web_trackers(obj):
            rows.add((domain, "Web Tracker", f"{tracker['Platform']}: {tracker['Code']}"))
    if ssl is not None and not ssl.empty:
        for col, kind in (("Hash", "Certificate"), ("Public Key SHA256", "Public Key")):
            if col in ssl.columns:
                for domain, value in zip(ssl["Domain"], ssl[col]):
                    if pd.notna(value) and str(value).strip():
                        rows.add((domain, kind, str(value).strip()))
        if "JA4X" in ssl.columns:
            for _, cert in ssl.iterrows():
                value = str(cert.get("JA4X") or "").strip()
                if value and value.lower() != "nan" and publicly_trusted(cert) is not True:
                    rows.add((cert["Domain"], "JA4X", value))
    counts = artifact_counts(enrichment)
    rows = {row for row in rows if link_strength(row[1], counts.get((row[1], row[2]))) is not None}
    if allowlist:   # your own infrastructure links nothing
        rows = {row for row in rows
                if not allowlist.artifact(row[1], row[2], (ip_intel or {}).get(row[2], {}).get("asn"))}
    return pd.DataFrame(sorted(rows), columns=ARTIFACT_COLUMNS).assign(
        **{"Iris Count": lambda f: [counts.get((t, v)) for t, v in zip(f["Type"], f["Value"])]})


class _UnionFind:
    def __init__(self):
        self.parent = {}

    def find(self, item):
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, a, b):
        self.parent[self.find(a)] = self.find(b)


def correlate(artifacts):
    """
    Links domain pairs that share a strong artifact (certificate, public key, tracker) or two different
    weak artifact types (IP + name server), then groups linked domains into clusters.
    """
    result = Correlation(artifacts=artifacts)
    if artifacts.empty:
        return result
    grouped = artifacts.groupby(["Type", "Value"])["Domain"].apply(lambda x: sorted(set(x))).reset_index()
    grouped["Domain Count"] = grouped["Domain"].map(len)
    shared = grouped[grouped["Domain Count"] > 1].rename(columns={"Domain": "Domains"})
    result.shared = shared.reset_index(drop=True)
    if shared.empty:
        return result

    counts = {} if "Iris Count" not in artifacts.columns else {
        (t, v): c for t, v, c in zip(artifacts["Type"], artifacts["Value"], artifacts["Iris Count"]) if pd.notna(c)}
    strength = {(t, v): link_strength(t, counts.get((t, v))) for t, v in zip(shared["Type"], shared["Value"])}
    pair_types, pair_strong = {}, set()
    for _, row in shared.iterrows():
        domains = row["Domains"][:MAX_DOMAINS_PER_ARTIFACT]
        for a, b in combinations(domains, 2):
            pair_types.setdefault((a, b), {}).setdefault(row["Type"], []).append(row["Value"])
            if strength[(row["Type"], row["Value"])] == "strong":
                pair_strong.add((a, b))

    uf, pair_rows = _UnionFind(), []
    for (a, b), types in pair_types.items():
        linked = (a, b) in pair_strong or len(WEAK_ARTIFACTS & set(types)) >= 2
        pair_rows.append({"Domain A": a, "Domain B": b, "Shared Types": ", ".join(sorted(types)),
                          "Shared Artifacts": sum(len(v) for v in types.values()), "Linked": linked})
        if linked:
            uf.union(a, b)
    result.pairs = pd.DataFrame(pair_rows)

    members = {}
    for a, b in (key for key, row in zip(pair_types, pair_rows) if row["Linked"]):
        for dom in (a, b):
            members.setdefault(uf.find(dom), set()).add(dom)
    for idx, domains in enumerate(sorted(members.values(), key=lambda s: (-len(s), sorted(s))), start=1):
        domains = sorted(domains)
        member_set = set(domains)
        cluster_shared = shared[shared["Domains"].map(lambda ds, members=member_set: len(set(ds) & members) > 1)]
        strong = any(strength[(t, v)] == "strong" for t, v in zip(cluster_shared["Type"], cluster_shared["Value"]))
        result.clusters.append({
            "Cluster": f"C{idx}",
            "Domains": domains,
            "Size": len(domains),
            "Strength": "Strong" if strong else "Moderate",
            "Shared Artifacts": {t: sorted(g["Value"]) for t, g in cluster_shared.groupby("Type")},
        })
        for dom in domains:
            result.domain_cluster[dom] = f"C{idx}"
    return result


# ---------------------------------------------------------------------------
# Domain hopping
# ---------------------------------------------------------------------------

def build_ip_observations(pdns, ip_pivots):
    """Hostnames observed on IPs: pDNS rows for IP targets plus optional DNSDB reverse-IP pivots."""
    frames = []
    if pdns is not None and not pdns.empty and "RRName" in pdns.columns:
        ip_rows = pdns[pdns["Domain"].map(is_ip_address)]
        if not ip_rows.empty:
            frames.append(pd.DataFrame({
                "IP": ip_rows["Domain"], "RRName": ip_rows["RRName"], "First Seen": ip_rows["First Seen"],
                "Last Seen": ip_rows["Last Seen"], "Related": ip_rows["Domain"],
            }))
    if ip_pivots is not None and not ip_pivots.empty:
        frames.append(ip_pivots[["IP", "RRName", "First Seen", "Last Seen", "Related"]])
    if not frames:
        return pd.DataFrame(columns=["IP", "RRName", "First Seen", "Last Seen", "Related"])
    return pd.concat(frames, ignore_index=True)


def ip_domain_timeline(observations, ip):
    """Per registrable domain first/last seen on one IP."""
    obs = observations[observations["IP"] == ip].copy()
    if obs.empty:
        return pd.DataFrame(columns=["Registrable Domain", "First Seen", "Last Seen", "Hostnames"])
    obs["Registrable Domain"] = obs["RRName"].astype(str).str.rstrip(".").map(registrable_domain)
    obs["Last Seen"] = pd.to_datetime(obs["Last Seen"], errors="coerce").fillna(pd.to_datetime(obs["First Seen"], errors="coerce"))
    timeline = obs.groupby("Registrable Domain").agg(
        **{"First Seen": ("First Seen", "min"), "Last Seen": ("Last Seen", "max"), "Hostnames": ("RRName", "nunique")}
    ).reset_index()
    return timeline.sort_values("First Seen").reset_index(drop=True)


def detect_domain_hops(observations, hop_days, max_domains_per_ip=50, ip_intel=None):
    """
    A hop is a new registrable domain appearing on an IP within `hop_days` after every earlier domain went dark.
    IPs with more than `max_domains_per_ip` domains (shared hosting) and CDN IPs are ignored.
    """
    columns = ["IP", "From Domain", "From Last Seen", "To Domain", "To First Seen", "Gap Days", "Related"]
    if observations is None or observations.empty:
        return pd.DataFrame(columns=columns)
    rows = []
    for ip, obs in observations.groupby("IP"):
        if cdn_for_ip(ip, ip_intel) or not is_public_ip(ip):
            continue
        timeline = ip_domain_timeline(observations, ip)
        if len(timeline) < 2 or len(timeline) > max_domains_per_ip:
            continue
        related = sorted({r.strip() for value in obs["Related"].astype(str) for r in value.split(",") if r.strip()})
        latest_end, latest_domain = timeline.loc[0, "Last Seen"], timeline.loc[0, "Registrable Domain"]
        for _, row in timeline.iloc[1:].iterrows():
            gap = (row["First Seen"] - latest_end).total_seconds() / 86400.0
            if 0 < gap <= hop_days:
                rows.append({"IP": ip, "From Domain": latest_domain, "From Last Seen": latest_end,
                             "To Domain": row["Registrable Domain"], "To First Seen": row["First Seen"],
                             "Gap Days": round(gap, 1), "Related": ", ".join(related)})
            if row["Last Seen"] > latest_end:
                latest_end, latest_domain = row["Last Seen"], row["Registrable Domain"]
    return pd.DataFrame(rows, columns=columns)

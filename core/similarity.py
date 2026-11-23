"""
Infrastructure similarity of domains: how alike two domains are built (hosting, DNS, registration, certificates,
naming, DIF parts, risk shape), as a 0-100 % score with the reasons, so a campaign's domains can be grouped even when
their exact DIF differs.

- Features per domain come from the loaded run (domain_features): Iris Investigate, passive DNS, certificates, TXT
  apps, BGPDB and the risk profiles.
- A shared value counts by how rare it is (rarity): an IP Iris sees on 3 domains links far more than a CDN address or
  Let's Encrypt. Counts come from Iris (domains per IP / name server), the run itself and every saved run.
- pair_scores scores every pair; clusters groups them (average linkage, cut at a threshold).
- similar_in_runs finds the domains of earlier saved runs that look like one domain (MinHash / LSH over the artifacts
  saved runs keep, rescored with the same rarity weights).
- learn_weights fits the group weights to the analyst's domain verdicts (Malicious pairs vs Malicious / Benign pairs).

It measures infrastructure similarity, not attribution: bulletproof hosting or a shared phishing kit can make
unrelated operators look alike.
"""
import hashlib
import ipaddress
import math
import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from core.anonymizers import ANONYMIZER_CATEGORIES
from core.bgp import BYOIP_NETWORKS, main_origins, main_upstreams
from core.cert_utils import issuer_family
from core.helpers import extract_ip_addresses, is_ip_address
from core.hostnames import apex_of
from core.network_intel import cdn_for_ip, record_types
from core.risk_profile import VECTOR_COLUMNS
from integrations.enrichment import extract_iris_profile

GROUPS = ("Hosting", "DNS", "Certificates", "Registration", "Naming", "DIF", "Risk shape")
DEFAULT_WEIGHTS = {"Hosting": 25, "DNS": 20, "Certificates": 20, "Registration": 10, "Naming": 15, "DIF": 5,
                   "Risk shape": 5}
GROUP_HELP = {
    "Hosting": "IPs, their /24, the origin network (BGPDB, else Iris ASN) and announced prefix",
    "DNS": "Name servers and their domain, MX hosts, TXT apps",
    "Certificates": "CA family, validation level, key type and size, JA4X, public key, certificate hash",
    "Registration": "Registrar, TLD, creation dates within 3 days (30 days: half)",
    "Naming": "The name's shape (letters / digits layout, e.g. llllnll) and shared 3-letter pieces",
    "DIF": "The readable DIF parts that match (flux, server, validation, CA, key, apps); the hash is ignored",
    "Risk shape": "Cosine similarity of the risk vectors (how risky, not how built: low weight)",
}
DEFAULT_THRESHOLD = 60      # % for a pair to count as similar
RARE_DOMAINS = 50           # a value on this many domains or fewer is a rare shared value
MIN_GROUPS = 2              # groups both domains have data for, below which a pair is not scored
COMMON_MARK = 0.1           # rarity of a CDN address, a BYOIP / CDN network or a free mass CA

_KIND_GROUP = {"ip": "Hosting", "net24": "Hosting", "asn": "Hosting", "prefix": "Hosting",
               "ns": "DNS", "nsdom": "DNS", "mx": "DNS", "txt": "DNS",
               "ca": "Certificates", "val": "Certificates", "key": "Certificates", "ja4x": "Certificates",
               "pubkey": "Certificates", "cert": "Certificates"}
KIND_LABELS = {"ip": "IP", "net24": "/24", "asn": "network", "prefix": "prefix", "ns": "name server",
               "nsdom": "name server domain", "mx": "MX", "txt": "TXT app", "ca": "CA", "val": "validation",
               "key": "key", "ja4x": "JA4X", "pubkey": "public key", "cert": "certificate"}
_MASS_CAS = {"letsencrypt", "zerossl", "google_trust", "cloudflare"}   # issuer_family keys of free / mass CAs
_DIF_TLS = re.compile(r"^(?P<val>[A-Z]{2})?(?P<iss>LE|ZS|SS|UN)(?:\d+|U)?-(?P<key>[RE]\d+|U)$")


@dataclass
class DomainFeatures:
    domain: str
    tokens: set = field(default_factory=set)       # {(kind, value)}: the set-valued features of every group
    registrar: str = ""
    tld: str = ""
    created: pd.Timestamp = pd.NaT
    shape: str = ""
    grams: set = field(default_factory=set)
    dif: tuple = ()                                 # (flux, server, validation, issuer, key, apps) or ()
    vector: tuple = ()                              # risk vectors (NaN as 0), () without a profile
    extra: set = field(default_factory=set)        # {(kind, value)}: shown as shared indicators, never scored


# ---- features ---------------------------------------------------------------------------------------------------------

def name_shape(domain):
    """The layout of the first label: letters l, digits n, hyphens -, plus the TLD ("xwfa3ak.cc" → "llllnll.cc")."""
    label, _, tld = str(domain).lower().partition(".")
    shape = "".join("n" if c.isdigit() else "-" if c == "-" else "l" for c in label)
    return f"{shape}.{tld}" if tld else shape


def name_grams(domain, size=3):
    label = str(domain).lower().split(".")[0]
    return {label[i:i + size] for i in range(max(0, len(label) - size + 1))}


def dif_parts(fingerprint):
    """(flux, server, validation, issuer, key, apps) of a DIF, the hash left out; () when it does not parse."""
    parts = str(fingerprint or "").split("_")
    if len(parts) != 4:
        return ()
    hosting, tls, apps, _ = parts
    flux, _, server = hosting.partition("-")
    if tls == "NOCERT":
        return flux, server, "NOCERT", "NOCERT", "NOCERT", apps
    match = _DIF_TLS.match(tls)
    if not match:
        return flux, server, tls, "", "", apps
    return flux, server, match.group("val") or "", match.group("iss"), match.group("key"), apps


def _net24(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return str(ipaddress.ip_network(f"{ip}/{24 if address.version == 4 else 48}", strict=False))


def domain_features(ds, profiles=None, domains=None):
    """{domain: DomainFeatures} for the run's domains (IP and CIDR targets left out)."""
    domains = [d for d in (domains or ds.selected_domains) if not is_ip_address(d) and "/" not in str(d)]
    feats = {d: DomainFeatures(d, tld=str(d).rsplit(".", 1)[-1].lower(), shape=name_shape(d), grams=name_grams(d))
             for d in domains}
    iris_counts = {}
    for domain in domains:
        iris = extract_iris_profile((ds.enrichment or {}).get(domain, {}))
        f = feats[domain]
        f.registrar = iris["registrar"].lower()
        f.created = pd.to_datetime(iris["create_date"], errors="coerce")
        for entry in iris["ips"]:
            f.tokens |= {("ip", entry["ip"]), ("net24", _net24(entry["ip"]))}
            iris_counts[("ip", entry["ip"])] = entry.get("count") or 0
            if entry.get("asn"):
                f.tokens.add(("asn", f"AS{entry['asn']}"))
        for host in iris["name_servers"]:
            f.tokens |= {("ns", host.lower()), ("nsdom", apex_of(host))}
        for host, count in (iris.get("name_server_counts") or {}).items():
            iris_counts[("ns", str(host).lower())] = count or 0
        f.tokens |= {("mx", h.lower()) for h in iris["mx_hosts"]}
        f.extra |= {("registrar", iris["registrar"]), ("tld", f.tld), ("shape", f.shape),
                    ("server", iris["server_type"]), ("redirect", iris["redirect_domain"])}
        f.extra |= {("email", e) for e in iris["email_domains"]}
        f.extra |= {("country", e["country"]) for e in iris["ips"]} | {("isp", e["isp"]) for e in iris["ips"]}
        if pd.notna(f.created):
            f.extra.add(("created", f.created.strftime("%Y-%m-%d")))
    pdns = getattr(ds, "pdns_utc", None)
    if pdns is not None and not pdns.empty:
        types = record_types(pdns)
        for domain, rtype, value in zip(pdns["Domain"], types, pdns["Value"].astype(str)):
            if domain not in feats:
                continue
            if rtype in ("A", "AAAA"):
                for ip in extract_ip_addresses(value):
                    feats[domain].tokens |= {("ip", ip), ("net24", _net24(ip))}
            elif rtype == "NS":
                for host in value.split("\n"):
                    host = host.strip().lower().rstrip(".")
                    if host:
                        feats[domain].tokens |= {("ns", host), ("nsdom", apex_of(host))}
            elif rtype == "MX" and value.split():
                feats[domain].tokens.add(("mx", value.split()[-1].lower().rstrip(".")))
    txt = getattr(ds, "txt_apps", None)
    if txt is not None and not txt.empty and "Application / Tag" in txt.columns:
        for domain, app in zip(txt["Domain"], txt["Application / Tag"].astype(str)):
            if domain in feats and app:
                feats[domain].tokens.add(("txt", app.lower()))
    origins = getattr(ds, "bgp_origins", None)
    if origins is not None and not origins.empty:
        upstreams = main_upstreams(getattr(ds, "bgp_routes", None))
        for _, row in main_origins(origins).iterrows():
            for domain in _domains_of(row, feats):
                feats[domain].tokens |= {("asn", str(row["Origin"]).upper()),
                                         ("prefix", str(row["Prefix"]).rstrip("+"))}
                feats[domain].extra |= {("upstream", str(upstreams.get(row["Prefix"], "")).upper()),
                                        ("route", str(row.get("Status") or "")),
                                        ("asname", str(row.get("AS Name") or ""))}
    anonymizers = getattr(ds, "anonymizers", None)
    if anonymizers is not None and not anonymizers.empty and "Category" in anonymizers.columns:
        for _, row in anonymizers[anonymizers["Category"].isin(ANONYMIZER_CATEGORIES)].iterrows():
            for domain in _domains_of(row, feats):
                feats[domain].extra |= {("anon", str(row["Category"])),
                                        ("provider", f"{row.get('Provider') or 'unnamed'} ({row['Category']})")}
    ssl = getattr(ds, "ssl_all_utc", None)
    if ssl is None or ssl.empty:
        ssl = getattr(ds, "ssl", None)
    if ssl is not None and not ssl.empty:
        for _, cert in ssl.iterrows():
            domain = cert.get("Domain")
            if domain not in feats:
                continue
            tokens = feats[domain].tokens
            tokens.add(("ca", issuer_family(cert)[0] if issuer_family(cert)[0] != "other"
                        else str(cert.get("Issuer") or "").lower()))
            if str(cert.get("Validation Level") or "").strip():
                tokens.add(("val", str(cert["Validation Level"]).lower()))
            bits = pd.to_numeric(cert.get("Public Key Bits"), errors="coerce")
            if pd.notna(bits):
                tokens.add(("key", f"{str(cert.get('Public Key Algo') or '').upper()[:2]}{int(bits)}"))
            for kind, column in (("ja4x", "JA4X"), ("pubkey", "Public Key SHA256"), ("cert", "Hash")):
                value = str(cert.get(column) or "").strip().lower()
                if value and value != "nan":
                    tokens.add((kind, value))
    if profiles is not None and not profiles.empty:
        vectors = [c for c in VECTOR_COLUMNS if c in profiles.columns]
        for _, row in profiles.iterrows():
            if row["Domain"] in feats:
                feats[row["Domain"]].dif = dif_parts(row.get("DIF Fingerprint"))
                feats[row["Domain"]].extra.add(("dif", str(row.get("DIF Fingerprint") or "")))
                feats[row["Domain"]].vector = tuple(float(v) if pd.notna(v) else 0.0 for v in row[vectors])
    for f in feats.values():
        f.tokens = {(k, v) for k, v in f.tokens if v}
        f.extra = {(k, v) for k, v in f.extra if v and str(v).lower() not in ("nan", "none")}
    return feats, iris_counts


def _domains_of(row, feats):
    return [d for d in (x.strip() for x in str(row.get("Domains") or "").split(",")) if d in feats]


# ---- rarity -----------------------------------------------------------------------------------------------------------

def value_counts(feats, iris_counts=None, runs=None):
    """
    {(kind, value): domains that have it}: the largest of Iris's count (IPs, name servers), the run's own domains and
    the domains of every saved run (`runs`: load_all_runs() pairs) with that artifact.
    """
    counts = {}
    for f in feats.values():
        for token in f.tokens:
            counts[token] = counts.get(token, 0) + 1
    seen = {}
    for _, snapshot in runs or []:
        for domain, kinds in (snapshot.get("artifacts") or {}).items():
            for token in artifact_tokens(kinds):
                seen.setdefault(token, set()).add(domain)
    for token, domains in seen.items():
        counts[token] = max(counts.get(token, 0), len(domains))
    for token, count in (iris_counts or {}).items():
        counts[token] = max(counts.get(token, 0), int(count or 0))
    return counts


def rarity(token, counts):
    """0-1: how much sharing `token` links two domains (1: unique to them; 0.1: CDN, BYOIP network, mass CA)."""
    kind, value = token
    if (kind == "ip" and cdn_for_ip(value)) or (kind == "asn" and value.upper() in BYOIP_NETWORKS) \
            or (kind == "ca" and value in _MASS_CAS):
        return COMMON_MARK
    n = max(1, counts.get(token, 1))
    return 1 / (1 + math.log10(n))


# ---- pair scores ------------------------------------------------------------------------------------------------------

def _weighted_jaccard(a, b, counts):
    """
    (0-1, shared tokens rarest first): the mean of the rarity-weighted overlap over the union (Jaccard) and over the
    smaller side (overlap coefficient), so a domain with a bigger footprint that holds all of the other's rare values
    still scores high, while sharing only common values scores low.
    """
    union = a | b
    if not union:
        return None, []
    shared = a & b
    weight = {t: rarity(t, counts) for t in union}
    common = sum(weight[t] for t in shared)
    total = sum(weight.values())
    smaller = min(sum(weight[t] for t in a), sum(weight[t] for t in b))
    jaccard = common / total if total else 0.0
    overlap = common / smaller if smaller else 0.0
    return (jaccard + overlap) / 2, sorted(shared, key=lambda t: -weight[t])


def _levenshtein(a, b):
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def group_scores(a, b, counts):
    """({group: 0-1 or None (no data)}, shared tokens rarest first) for two DomainFeatures."""
    scores, shared = {}, []
    for group in ("Hosting", "DNS", "Certificates"):
        mine = {t for t in a.tokens if _KIND_GROUP[t[0]] == group}
        theirs = {t for t in b.tokens if _KIND_GROUP[t[0]] == group}
        if mine and theirs:
            scores[group], found = _weighted_jaccard(mine, theirs, counts)
            shared += found
        else:
            scores[group] = None
    parts = []
    if a.registrar and b.registrar:
        parts.append(1.0 if a.registrar == b.registrar else 0.0)
    if a.tld and b.tld:
        parts.append(1.0 if a.tld == b.tld else 0.0)
    if pd.notna(a.created) and pd.notna(b.created):
        days = abs((a.created - b.created).days)
        parts.append(1.0 if days <= 3 else 0.5 if days <= 30 else 0.0)
    scores["Registration"] = sum(parts) / len(parts) if parts else None
    shape = 1 - _levenshtein(a.shape, b.shape) / max(len(a.shape), len(b.shape), 1)
    grams = len(a.grams & b.grams) / len(a.grams | b.grams) if a.grams | b.grams else 0.0
    scores["Naming"] = 0.7 * shape + 0.3 * grams
    scores["DIF"] = sum(x == y for x, y in zip(a.dif, b.dif)) / len(a.dif) if a.dif and b.dif else None
    if a.vector and b.vector and len(a.vector) == len(b.vector):
        va, vb = np.array(a.vector), np.array(b.vector)
        norm = np.linalg.norm(va) * np.linalg.norm(vb)
        scores["Risk shape"] = float(va @ vb / norm) if norm else (1.0 if not va.any() and not vb.any() else 0.0)
    else:
        scores["Risk shape"] = None
    return scores, shared


def combine(scores, weights):
    """Weighted mean of the groups both domains have data for, as a 0-100 %; None below MIN_GROUPS groups."""
    used = [(weights.get(g, 0), s) for g, s in scores.items() if s is not None and weights.get(g, 0) > 0]
    if len(used) < MIN_GROUPS or not sum(w for w, _ in used):
        return None
    return round(100 * sum(w * s for w, s in used) / sum(w for w, _ in used), 1)


PAIR_COLUMNS = ["Domain A", "Domain B", "Similarity %", "Rare Shared", "Matched", "Shared Values", "Differs",
                *GROUPS]


def _token_text(token):
    kind, value = token
    return f"{KIND_LABELS.get(kind, kind)} {value[:24] + '…' if len(value) > 26 else value}"


def pair_scores(feats, counts, weights=None):
    """PAIR_COLUMNS: one row per pair of domains, most similar first, with what matched and what differs."""
    weights = weights or DEFAULT_WEIGHTS
    names = sorted(feats)
    rows = []
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            scores, shared = group_scores(feats[a], feats[b], counts)
            score = combine(scores, weights)
            if score is None:
                continue
            rare = [t for t in shared if counts.get(t, 1) <= RARE_DOMAINS and rarity(t, counts) > COMMON_MARK]
            matched = [g for g in GROUPS if scores.get(g) is not None and scores[g] >= 0.6 and weights.get(g, 0)]
            differs = [g for g in GROUPS if scores.get(g) is not None and scores[g] < 0.3 and weights.get(g, 0)]
            rows.append({"Domain A": a, "Domain B": b, "Similarity %": score, "Rare Shared": len(rare),
                         "Matched": ", ".join(matched), "Shared Values": ", ".join(_token_text(t) for t in shared[:6]),
                         "Differs": ", ".join(differs),
                         **{g: round(100 * scores[g]) if scores.get(g) is not None else None for g in GROUPS}})
    frame = pd.DataFrame(rows, columns=PAIR_COLUMNS)
    return frame.sort_values("Similarity %", ascending=False).reset_index(drop=True)


def passing(pairs, threshold=DEFAULT_THRESHOLD, min_rare=0):
    """The pairs at or above `threshold` % with at least `min_rare` rare shared values."""
    if pairs.empty:
        return pairs
    return pairs[(pairs["Similarity %"] >= threshold) & (pairs["Rare Shared"] >= min_rare)].reset_index(drop=True)


def matrix(pairs, domains):
    """Domain × domain similarity % (100 on the diagonal, blank where a pair was not scored)."""
    frame = pd.DataFrame(np.nan, index=domains, columns=domains)
    for d in domains:
        frame.loc[d, d] = 100.0
    for _, row in pairs.iterrows():
        frame.loc[row["Domain A"], row["Domain B"]] = frame.loc[row["Domain B"], row["Domain A"]] = row["Similarity %"]
    return frame


# ---- clusters ---------------------------------------------------------------------------------------------------------

def clusters(pairs, domains, threshold=DEFAULT_THRESHOLD, min_rare=0):
    """
    Groups by average linkage: the two groups whose pairs are most alike on average merge while that average is at
    least `threshold` %; a pair below `min_rare` rare shared values counts as 0. [[domains]] with 2+ members, largest
    first.
    """
    domains = list(domains)
    index = {d: i for i, d in enumerate(domains)}
    n = len(domains)
    if n < 2:
        return []
    sim = np.zeros((n, n))
    for _, row in pairs.iterrows():
        if row["Rare Shared"] >= min_rare and row["Domain A"] in index and row["Domain B"] in index:
            i, j = index[row["Domain A"]], index[row["Domain B"]]
            sim[i, j] = sim[j, i] = row["Similarity %"]
    members = {i: [i] for i in range(n)}
    active = list(range(n))
    while len(active) > 1:
        best, pair = -1.0, None
        for x in range(len(active)):
            for y in range(x + 1, len(active)):
                i, j = active[x], active[y]
                if sim[i, j] > best:
                    best, pair = sim[i, j], (i, j)
        if pair is None or best < threshold:
            break
        i, j = pair
        size_i, size_j = len(members[i]), len(members[j])
        for k in active:   # Lance-Williams update for average linkage
            if k not in (i, j):
                sim[i, k] = sim[k, i] = (size_i * sim[i, k] + size_j * sim[j, k]) / (size_i + size_j)
        members[i] += members.pop(j)
        active.remove(j)
    groups = [sorted(domains[m] for m in members[i]) for i in active if len(members[i]) > 1]
    return sorted(groups, key=lambda g: (-len(g), g))


# ---- shared indicators of a cluster --------------------------------------------------------------------------------

# kind: (type shown, category, source). Scored kinds first, then the indicators only shown (DomainFeatures.extra).
INDICATORS = {
    "ip": ("IP", "Hosting", "Iris / passive DNS"), "net24": ("/24 range", "Hosting", "Iris / passive DNS"),
    "asn": ("Network (ASN)", "Hosting", "Iris / BGPDB"), "prefix": ("Announced prefix", "Routing", "BGPDB"),
    "upstream": ("Upstream network", "Routing", "BGPDB"), "route": ("Route status", "Routing", "BGPDB"),
    "asname": ("Origin AS name", "Routing", "BGPDB"), "country": ("IP country", "Hosting", "Iris"),
    "isp": ("ISP", "Hosting", "Iris"), "server": ("Web server", "Hosting", "Iris"),
    "anon": ("Anonymizer exit", "Anonymizers", "VPNDB"), "provider": ("Anonymizer provider", "Anonymizers", "VPNDB"),
    "ns": ("Name server", "DNS", "Iris / passive DNS"), "nsdom": ("Name server domain", "DNS", "Iris / passive DNS"),
    "mx": ("MX", "DNS", "Iris / passive DNS"), "txt": ("TXT app / tag", "DNS", "Passive DNS"),
    "ca": ("CA", "Certificates", "Certificates"), "val": ("Validation level", "Certificates", "Certificates"),
    "key": ("Key type", "Certificates", "Certificates"), "ja4x": ("JA4X", "Certificates", "Certificates"),
    "pubkey": ("Public key SHA256", "Certificates", "Certificates"),
    "cert": ("Certificate SHA256", "Certificates", "Certificates"),
    "registrar": ("Registrar", "Registration", "Iris"), "created": ("Created on", "Registration", "Iris"),
    "email": ("Registration email domain", "Registration", "Iris"), "tld": ("TLD", "Naming", "Domain"),
    "shape": ("Name shape", "Naming", "Domain"), "redirect": ("Redirects to", "Hosting", "Iris"),
    "dif": ("DIF fingerprint", "DIF", "Risk profile"),
}
CATEGORY_COLORS = {"Hosting": "#1e88e5", "Routing": "#8e24aa", "Anonymizers": "#e53935", "DNS": "#00897b",
                   "Certificates": "#f9a825", "Registration": "#6d4c41", "Naming": "#546e7a", "DIF": "#3949ab"}
INDICATOR_COLUMNS = ["Category", "Type", "Indicator", "Source", "Domains", "Share %", "Seen On", "Rarity",
                     "Domain List"]
CLUSTER_PAIR_COLUMNS = ["Domain A", "Domain B", "Similarity %", "Shared", "Shared %", "Shared Indicators"]


def _all_indicators(f):
    return f.tokens | f.extra


def cluster_indicators(group, feats, counts=None):
    """
    INDICATOR_COLUMNS: every indicator at least two of the cluster's domains share (IPs, ranges, networks, prefixes,
    upstreams and route status, VPNDB exits and providers, name servers, MX, TXT, certificates, registrar, dates,
    naming, DIF), with the share of the cluster holding it and how many domains it is seen on overall. Most shared,
    then rarest, first; `Domain List` names the cluster domains holding it.
    """
    counts = counts or {}
    holders = {}
    for domain in group:
        for token in _all_indicators(feats[domain]):
            holders.setdefault(token, []).append(domain)
    rows = []
    for (kind, value), domains in holders.items():
        if len(domains) < 2:
            continue
        label, category, source = INDICATORS.get(kind, (kind, "Other", ""))
        scored = (kind, value) in feats[domains[0]].tokens
        rows.append({"Category": category, "Type": label, "Indicator": value, "Source": source,
                     "Domains": len(domains), "Share %": round(100 * len(domains) / len(group)),
                     "Seen On": counts.get((kind, value)) if scored else None,
                     "Rarity": round(rarity((kind, value), counts), 2) if scored else None,
                     "Domain List": sorted(domains)})
    frame = pd.DataFrame(rows, columns=INDICATOR_COLUMNS)
    if frame.empty:
        return frame
    frame["_r"] = frame["Rarity"].fillna(0)
    return frame.sort_values(["Domains", "_r", "Category"], ascending=[False, False, True]) \
        .drop(columns="_r").reset_index(drop=True)


def cluster_pairs(group, feats, pairs):
    """
    CLUSTER_PAIR_COLUMNS: every pair of the cluster with all the indicators the two share (not only the scored ones)
    and Shared % = shared over the indicators either of them has.
    """
    lookup = {}
    for _, row in pairs.iterrows():
        lookup[(row["Domain A"], row["Domain B"])] = lookup[(row["Domain B"], row["Domain A"])] = row["Similarity %"]
    rows = []
    names = sorted(group)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            mine, theirs = _all_indicators(feats[a]), _all_indicators(feats[b])
            shared = sorted(mine & theirs, key=lambda t: (list(INDICATORS).index(t[0]) if t[0] in INDICATORS
                                                          else len(INDICATORS), t[1]))
            union = mine | theirs
            rows.append({"Domain A": a, "Domain B": b, "Similarity %": lookup.get((a, b)), "Shared": len(shared),
                         "Shared %": round(100 * len(shared) / len(union)) if union else 0,
                         "Shared Indicators": "; ".join(f"{INDICATORS.get(k, (k,))[0]} {v}" for k, v in shared)})
    frame = pd.DataFrame(rows, columns=CLUSTER_PAIR_COLUMNS)
    return frame.sort_values(["Similarity %", "Shared"], ascending=False, na_position="last").reset_index(drop=True)


def closest_dif(profiles):
    """{domain: "DIF (k/6 parts)"}: the other domain's DIF sharing the most readable parts (none: "")."""
    if profiles is None or profiles.empty or "DIF Fingerprint" not in profiles.columns:
        return {}
    difs = dict(zip(profiles["Domain"], profiles["DIF Fingerprint"].astype(str)))
    out = {}
    for domain, fingerprint in difs.items():
        mine = dif_parts(fingerprint)
        best, label = 0, ""
        for other, theirs in difs.items():
            if other == domain or not mine:
                continue
            parts = dif_parts(theirs)
            same = sum(x == y for x, y in zip(mine, parts)) if parts else 0
            if same > best:
                best, label = same, f"{theirs} ({other}, {same}/{len(mine)} parts)"
        out[domain] = label
    return out


# ---- earlier runs: MinHash / LSH --------------------------------------------------------------------------------------

_ARTIFACT_KINDS = {"IP": "ip", "Name Server": "ns", "MX": "mx", "Prefix": "prefix", "ASN": "asn", "JA4X": "ja4x",
                   "Certificate": "cert", "Web Tracker": "tracker"}
PERMUTATIONS, BANDS = 64, 16   # 16 bands of 4 rows: pairs with ~50 % weighted overlap or more meet as candidates


def artifact_tokens(kinds):
    """{(kind, value)} from a saved run's artifacts of one domain (as collect_run_artifacts keeps them)."""
    tokens = set()
    for kind, values in (kinds or {}).items():
        short = _ARTIFACT_KINDS.get(kind)
        if short:
            tokens |= {(short, str(v).upper() if short == "asn" else str(v).lower()) for v in values or ()}
    for ip in [v for k, v in tokens if k == "ip"]:
        tokens.add(("net24", _net24(ip)))
    return {t for t in tokens if t[1]}


def _hash(seed, token):
    return int.from_bytes(hashlib.blake2b(f"{seed}|{token[0]}|{token[1]}".encode(), digest_size=8).digest(), "big")


def minhash(tokens):
    return tuple(min(_hash(seed, t) for t in tokens) for seed in range(PERMUTATIONS)) if tokens else ()


def _bands(signature):
    rows = PERMUTATIONS // BANDS
    return [(b, signature[b * rows:(b + 1) * rows]) for b in range(BANDS)]


@dataclass
class RunIndex:
    """LSH buckets over the domains of saved runs: {(band, rows): {(run id, domain)}}, with each entry's tokens."""
    buckets: dict = field(default_factory=dict)
    entries: dict = field(default_factory=dict)   # (run id, domain) -> (tokens, created, run name)


def build_index(runs):
    """A RunIndex of every (run, domain) with artifacts in `runs` (load_all_runs() pairs), latest run per domain kept
    once per run."""
    index = RunIndex()
    for _, snapshot in runs or []:
        run_id = snapshot.get("id")
        for domain, kinds in (snapshot.get("artifacts") or {}).items():
            tokens = artifact_tokens(kinds) | {("shape", name_shape(domain))}
            if len(tokens) < 2:
                continue
            key = (run_id, domain)
            index.entries[key] = (tokens, snapshot.get("created"), snapshot.get("name") or "")
            for band in _bands(minhash(tokens)):
                index.buckets.setdefault(band, set()).add(key)
    return index


SIMILAR_RUN_COLUMNS = ["Domain", "Similarity %", "Run", "Run Name", "Rare Shared", "Shared Values"]


def similar_in_runs(domain, tokens, index, counts, exclude_run=None, threshold=40, limit=20):
    """
    SIMILAR_RUN_COLUMNS: domains of earlier saved runs that look like `domain` (its artifact tokens): LSH candidates
    rescored by rarity-weighted overlap, at or above `threshold` %, the same domain and `exclude_run` left out.
    """
    tokens = set(tokens) | {("shape", name_shape(domain))}
    candidates = set()
    for band in _bands(minhash(tokens)):
        candidates |= index.buckets.get(band, set())
    best = {}
    for key in candidates:
        run_id, other = key
        if other == domain or run_id == exclude_run:
            continue
        theirs, created, name = index.entries[key]
        score, shared = _weighted_jaccard(tokens, theirs, counts)
        score = round(100 * (score or 0), 1)
        if score >= threshold and score > best.get(other, (0,))[0]:
            rare = [t for t in shared if counts.get(t, 1) <= RARE_DOMAINS and rarity(t, counts) > COMMON_MARK
                    and t[0] != "shape"]
            best[other] = (score, created, name, len(rare), ", ".join(_token_text(t) if t[0] != "shape"
                                                                      else f"name shape {t[1]}" for t in shared[:5]))
    rows = [{"Domain": d, "Similarity %": s, "Run": str(c)[:16].replace("T", " "), "Run Name": n, "Rare Shared": r,
             "Shared Values": v} for d, (s, c, n, r, v) in best.items()]
    frame = pd.DataFrame(rows, columns=SIMILAR_RUN_COLUMNS)
    return frame.sort_values("Similarity %", ascending=False).head(limit).reset_index(drop=True)


# ---- learned weights --------------------------------------------------------------------------------------------------

MIN_LABELLED = 10   # pairs of each kind needed before weights are learned


def labelled_pairs(pairs, verdicts):
    """
    The pairs both of whose domains have a verdict: label 1 when both are Malicious (analysed together: likely the
    same campaign), 0 when one is Malicious and the other Benign. Pairs of two Benign domains say nothing.
    """
    verdicts = verdicts or {}
    rows = []
    for _, row in pairs.iterrows():
        a, b = verdicts.get(row["Domain A"]), verdicts.get(row["Domain B"])
        if a == b == "Malicious":
            rows.append((row, 1))
        elif {a, b} == {"Malicious", "Benign"}:
            rows.append((row, 0))
    return rows


def learn_weights(pairs, verdicts, steps=3000, rate=0.5, l2=0.01):
    """
    (weights {group: 0-100} or None, report): a logistic regression of the label on each group's similarity (missing
    as 0), its coefficients clipped at 0 and scaled to sum 100. None with fewer than MIN_LABELLED pairs of each kind.
    """
    rows = labelled_pairs(pairs, verdicts)
    positives = sum(label for _, label in rows)
    negatives = len(rows) - positives
    report = {"positives": positives, "negatives": negatives}
    if positives < MIN_LABELLED or negatives < MIN_LABELLED:
        return None, report
    x = np.array([[(row[g] or 0) / 100 if pd.notna(row[g]) else 0.0 for g in GROUPS] for row, _ in rows])
    y = np.array([label for _, label in rows], dtype=float)
    w, bias = np.zeros(len(GROUPS)), 0.0
    for _ in range(steps):
        p = 1 / (1 + np.exp(-(x @ w + bias)))
        w -= rate * (x.T @ (p - y) / len(y) + l2 * w)
        bias -= rate * float(np.mean(p - y))
    p = 1 / (1 + np.exp(-(x @ w + bias)))
    report["accuracy"] = round(float(np.mean((p >= 0.5) == (y == 1))) * 100, 1)
    clipped = np.clip(w, 0, None)
    if not clipped.sum():
        return None, {**report, "note": "no group separates the labelled pairs"}
    return {g: int(round(100 * v / clipped.sum())) for g, v in zip(GROUPS, clipped)}, report

"""
BGP routing of the run's hosting IPs (BGPDB): who announces each address, since when, whether the registries allow it,
through which networks, and what else is announced next to it. Turns BGPDB answers into tables and computes the routing
findings once, for the BGP page, the Summary, the detection rules (core.threat_detection.bgp_rules), the VPNDB match
and the Hunt map.

BGPDB keeps about the last 30 days: a `First Seen` on the first day of that window means "at least that old", not
"new" (data_start / is_new).
"""
import ipaddress
import re

import pandas as pd

from core.anonymizers import anonymizer_rows
from core.network_intel import cdn_for_ip, is_public_ip

ORIGIN_COLUMNS = ["IP", "Domains", "Prefix", "Origin", "AS Name", "Status", "First Seen", "Last Seen", "Updates",
                  "Collectors", "Core", "IRR", "RPKI", "RIR", "RIR Date", "RIR Country", "Score"]
ASN_COLUMNS = ["ASN", "AS Name", "Role", "Domains", "RIR", "Registered", "RIR Country", "First Seen", "Last Seen",
               "Updates", "Collectors", "Core", "Upstreams", "Downstreams"]
ROUTE_COLUMNS = ["Prefix", "Path", "Hops", "Origin", "Upstream", "First Seen", "Last Seen", "Updates", "Collectors",
                 "Peers"]
NEIGHBOUR_COLUMNS = ["Covering Range", "Run Prefix", "Prefix", "Origin", "Same Origin", "Status", "First Seen",
                     "Last Seen", "Collectors", "RIR Date", "RIR Country"]
FINDING_COLUMNS = ["Finding", "Severity", "Domains", "IP", "Prefix", "ASN", "AS Name", "Detail", "First Seen",
                   "Last Seen"]
IP_COLUMNS = ["IP", "Domains", "Prefix", "Origin", "AS Name", "Status", "Origins", "Announced Since", "Collectors",
              "RIR", "RIR Country", "Iris Country", "Upstream", "Findings"]
RAW_COLUMNS = ["Command", "Argument", "Status", "Records", "Detail", "URL", "Response"]

VALID, UNAUTHORIZED, UNVERIFIED = "Valid", "Unauthorized", "Not in RPKI / IRR"
STATUS_COLORS = {VALID: "#43a047", UNAUTHORIZED: "#e53935", UNVERIFIED: "#9e9e9e"}

# Findings (also the detection rules' names)
CONFLICT = "BGP Origin Conflict (Possible Hijack)"
UNAUTHORIZED_ORIGIN = "Unauthorized BGP Origin"
NEW_PREFIX = "Newly Announced Prefix"
NEW_ASN = "Recently Registered Origin Network"
THIN_ROUTE = "Low-Visibility or Single-Upstream Route"
EXIT_ON_UNSTABLE = "Anonymizer Exit on Unstable Routing"
FINDINGS = (CONFLICT, UNAUTHORIZED_ORIGIN, NEW_PREFIX, NEW_ASN, THIN_ROUTE)
# A finding about the prefix itself (not the network's age): what the VPNDB match calls unstable routing
UNSTABLE = (CONFLICT, UNAUTHORIZED_ORIGIN, NEW_PREFIX)

NEW_DAYS = 14             # a prefix first announced this recently (and after the data window began) is new
WINDOW_MARGIN_DAYS = 2    # ... but not within this many days of the window's first day (it may be older)
RECENT_CONFLICT_DAYS = 7  # an unauthorized origin seen this recently makes a conflict High
NEW_ASN_DAYS = 365        # an origin network registered at its RIR within this many days is young
VERY_NEW_ASN_DAYS = 90
LOW_COLLECTORS = 10       # a prefix seen by fewer route collectors is barely visible (well-routed: 50+)
RIR_PATTERN = re.compile(r"^(?P<rir>[A-Z]+)\s+(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<country>[A-Z]{2}|ZZ)?")


def _empty(columns):
    return pd.DataFrame(columns=columns)


def _ts(value):
    stamp = pd.to_datetime(value, errors="coerce", utc=True)
    return stamp.tz_localize(None) if pd.notna(stamp) else pd.NaT


def _asn(value):
    text = str(value or "").strip().upper()
    return text if text.startswith("AS") else f"AS{text}" if text.isdigit() else text


def _rir(entries):
    """(RIR, allocation date, country) of the first RIR line: "APNIC 2011-08-11 AU 266e3933"."""
    for entry in entries or []:
        match = RIR_PATTERN.match(str(entry).strip())
        if match:
            return match["rir"], _ts(match["date"]), match["country"] or ""
    return "", pd.NaT, ""


def _validity(record, kind):
    """valid / invalid origin / not found for "irr" or "rpki". A record can carry both flags (one IRR route object
    matches the origin, another names someone else): an object that authorizes the origin wins."""
    if record.get(f"{kind}_valid"):
        return "valid"
    if record.get(f"{kind}_invalid_origin") or record.get(f"{kind}_invalid"):
        return "invalid origin"
    return "not found"


def origin_status(irr, rpki):
    """
    RPKI decides when it has an answer (it is cryptographically signed); IRR only when RPKI has none. Valid: the
    registry authorizes the origin; Unauthorized: it names another origin; else not registered.
    """
    deciding = rpki if rpki != "not found" else irr
    if deciding == "valid":
        return VALID
    if "invalid" in deciding:
        return UNAUTHORIZED
    return UNVERIFIED


def prefix_network(prefix):
    """The network of a BGPDB prefix; "1.2.3.0/24+" (an entry for the more-specifics inside it) counts as the block."""
    try:
        return ipaddress.ip_network(str(prefix).strip().rstrip("+"), strict=False)
    except ValueError:
        return None


# ---- BGPDB answers -> rows --------------------------------------------------------------------------------------------

def origin_rows(ip, domains, records):
    """ORIGIN_COLUMNS rows from an `ip/{ip}` (or `prefix/…`) answer: one per (prefix, origin)."""
    rows = []
    for record in records or []:
        irr, rpki = _validity(record, "irr"), _validity(record, "rpki")
        rir, rir_date, country = _rir(record.get("rir_prefix"))
        rows.append({"IP": ip, "Domains": ", ".join(sorted(domains)), "Prefix": record.get("prefix", ""),
                     "Origin": _asn(record.get("origin")), "AS Name": "", "Status": origin_status(irr, rpki),
                     "First Seen": _ts(record.get("first")), "Last Seen": _ts(record.get("last")),
                     "Updates": int(record.get("count") or 0), "Collectors": int(record.get("collectors") or 0),
                     "Core": int(record.get("core") or 0), "IRR": irr, "RPKI": rpki, "RIR": rir,
                     "RIR Date": rir_date, "RIR Country": country,
                     "Score": record.get("score") if record.get("score") is not None else pd.NA})
    return rows


def asn_row(record, role, domains=()):
    """An ASN_COLUMNS row from an `asn/{asn}` answer."""
    rir, registered, country = _rir(record.get("rir_asn"))
    names = record.get("asname") or []
    return {"ASN": _asn(record.get("asn")), "AS Name": str(names[0]) if names else "", "Role": role,
            "Domains": ", ".join(sorted(domains)), "RIR": rir, "Registered": registered, "RIR Country": country,
            "First Seen": _ts(record.get("first")), "Last Seen": _ts(record.get("last")),
            "Updates": int(record.get("count") or 0), "Collectors": int(record.get("collectors") or 0),
            "Core": int(record.get("core") or 0),
            "Upstreams": int(record["hop_upstream"]) if record.get("hop_upstream") is not None else pd.NA,
            "Downstreams": int(record["hop_downstream"]) if record.get("hop_downstream") is not None else 0}


def route_rows(prefix, records):
    """ROUTE_COLUMNS rows from a `route/{prefix}` answer: one per AS path."""
    rows = []
    for record in records or []:
        path = [_asn(hop) for hop in record.get("path") or []]
        rows.append({"Prefix": record.get("route") or prefix, "Path": " → ".join(path), "Hops": len(path),
                     "Origin": path[-1] if path else "", "Upstream": path[-2] if len(path) > 1 else "",
                     "First Seen": _ts(record.get("first")), "Last Seen": _ts(record.get("last")),
                     "Updates": int(record.get("count") or 0), "Collectors": int(record.get("collectors") or 0),
                     "Peers": int(record.get("peers") or 0)})
    return rows


def neighbour_rows(covering, run_prefixes, run_origins, records):
    """
    NEIGHBOUR_COLUMNS rows from a `prefix/{covering range}` answer: the other prefixes announced in the range around
    the run's prefixes, and whether one of the run's own origins announces them.
    """
    rows = []
    for record in records or []:
        prefix = record.get("prefix", "")
        if prefix in run_prefixes:
            continue
        origin = _asn(record.get("origin"))
        irr, rpki = _validity(record, "irr"), _validity(record, "rpki")
        _, rir_date, country = _rir(record.get("rir_prefix"))
        rows.append({"Covering Range": covering, "Run Prefix": ", ".join(sorted(run_prefixes)), "Prefix": prefix,
                     "Origin": origin, "Same Origin": origin in run_origins, "Status": origin_status(irr, rpki),
                     "First Seen": _ts(record.get("first")), "Last Seen": _ts(record.get("last")),
                     "Collectors": int(record.get("collectors") or 0), "RIR Date": rir_date, "RIR Country": country})
    return rows


def covering_range(prefix):
    """
    The range whose prefixes are the neighbourhood: the /20 around an IPv4 prefix, the /40 around an IPv6 one. None for
    a prefix that size or larger: an aggregate (a carrier's /9) is not one operator's neighbourhood.
    """
    network = prefix_network(prefix)
    if network is None:
        return None
    size = 20 if network.version == 4 else 40
    return str(network.supernet(new_prefix=size)) if network.prefixlen > size else None


# ---- which IPs ---------------------------------------------------------------------------------------------------------

def select_ips(domains, pdns, enrichment, ip_targets=(), max_ips=200, per_domain=50):
    """
    {ip: {domains}} to look up: the IP targets, then per domain its current Iris IPs and its passive DNS addresses,
    most recently seen first, up to `per_domain` each and `max_ips` in all. Public IPv4 and IPv6, no CDN addresses
    (their routing is the CDN's, the same for every customer).
    """
    from core.helpers import extract_ip_addresses
    from integrations.enrichment import extract_iris_profile

    chosen = {}

    def keep(ip):
        return is_public_ip(ip) and not cdn_for_ip(ip)

    for ip in ip_targets:
        if keep(ip) and len(chosen) < max_ips:
            chosen.setdefault(str(ip), set()).add(str(ip))
    addresses = {}
    if pdns is not None and not pdns.empty and {"Domain", "Value"} <= set(pdns.columns):
        frame = pdns
        if "Last Seen" in frame.columns:
            frame = frame.assign(_seen=pd.to_datetime(frame["Last Seen"], errors="coerce")).sort_values(
                "_seen", ascending=False, na_position="last")
        for domain, value in zip(frame["Domain"], frame["Value"].astype(str)):
            for ip in extract_ip_addresses(value):
                addresses.setdefault(domain, []).append(ip)
    for domain in domains:
        candidates = [e["ip"] for e in extract_iris_profile((enrichment or {}).get(domain))["ips"]]
        candidates += addresses.get(domain, [])
        picked = 0
        for ip in dict.fromkeys(str(c) for c in candidates):
            if picked >= per_domain:
                break
            if not keep(ip) or (ip not in chosen and len(chosen) >= max_ips):
                continue
            chosen.setdefault(ip, set()).add(domain)
            picked += 1
    return chosen


# ---- analysis ----------------------------------------------------------------------------------------------------------

def _frame(frame, columns):
    return frame if frame is not None and not frame.empty else _empty(columns)


def data_start(origins, routes=None):
    """The first day BGPDB's data covers in this run (the oldest First Seen): older announcements start here too."""
    stamps = [pd.to_datetime(f["First Seen"], errors="coerce").min() for f in (origins, routes)
              if f is not None and not f.empty]
    stamps = [s for s in stamps if pd.notna(s)]
    return min(stamps) if stamps else pd.NaT


def data_end(origins, routes=None):
    stamps = [pd.to_datetime(f["Last Seen"], errors="coerce").max() for f in (origins, routes)
              if f is not None and not f.empty]
    stamps = [s for s in stamps if pd.notna(s)]
    return max(stamps) if stamps else pd.NaT


def is_new(first_seen, start, end, days=NEW_DAYS):
    """First announced within `days` of the data's end, and not on the window's first days (it could be older)."""
    first = pd.to_datetime(first_seen, errors="coerce")
    if pd.isna(first) or pd.isna(start) or pd.isna(end):
        return False
    return first >= start + pd.Timedelta(days=WINDOW_MARGIN_DAYS) and first >= end - pd.Timedelta(days=days)


def with_names(origins, asns):
    """The origins with the AS names the `asn` lookups gave."""
    if origins is None or origins.empty or asns is None or asns.empty:
        return origins
    names = dict(zip(asns["ASN"], asns["AS Name"]))
    return origins.assign(**{"AS Name": origins["Origin"].map(names).fillna(origins["AS Name"])})


def is_more_specific_entry(prefix):
    """BGPDB's "1.2.3.0/24+": announcements of more-specific prefixes inside the block, not the block itself."""
    return str(prefix).endswith("+")


def main_origins(origins):
    """
    Per (IP, prefix), the origin with the most updates: the network that normally announces the address. Entries for
    more-specifics inside a block ("/24+") are left out when the IP has an announcement of its own.
    """
    if origins is None or origins.empty:
        return _empty(ORIGIN_COLUMNS)
    extra = origins["Prefix"].map(is_more_specific_entry)
    own = set(origins.loc[~extra, "IP"])
    origins = origins[~extra | ~origins["IP"].isin(own)]
    ranked = origins.sort_values(["IP", "Prefix", "Updates", "Collectors"], ascending=[True, True, False, False])
    return ranked.drop_duplicates(["IP", "Prefix"]).reset_index(drop=True)


def _most_specific(frame):
    """Per IP, the row of its most specific prefix (the one traffic follows)."""
    if frame.empty:
        return frame
    lengths = frame["Prefix"].astype(str).str.extract(r"/(\d+)\+?$")[0].astype(float)
    return frame.assign(_len=lengths).sort_values(["IP", "_len", "Updates"], ascending=[True, False, False]) \
        .drop_duplicates("IP").drop(columns="_len").reset_index(drop=True)


def main_upstreams(routes):
    """{prefix: the upstream AS of its most-seen path}."""
    if routes is None or routes.empty:
        return {}
    ranked = routes[routes["Upstream"].astype(str) != ""].sort_values(["Prefix", "Collectors", "Updates"],
                                                                       ascending=[True, False, False])
    return dict(zip(ranked.drop_duplicates("Prefix")["Prefix"], ranked.drop_duplicates("Prefix")["Upstream"]))


def findings(origins, asns=None, routes=None, now=None):
    """
    FINDING_COLUMNS: the routing findings of the run's IPs, one row per (finding, prefix or network):
    - CONFLICT: a prefix with an authorized origin and another, unauthorized one (RPKI / IRR name someone else)
    - UNAUTHORIZED_ORIGIN: the prefix's usual origin itself is unauthorized
    - NEW_PREFIX: the usual origin started announcing the prefix in the last NEW_DAYS
    - NEW_ASN: the origin network was registered at its RIR in the last NEW_ASN_DAYS
    - THIN_ROUTE: the prefix is seen by few route collectors, or its origin has a single upstream
    """
    origins, asns, routes = _frame(origins, ORIGIN_COLUMNS), _frame(asns, ASN_COLUMNS), _frame(routes, ROUTE_COLUMNS)
    if origins.empty:
        return _empty(FINDING_COLUMNS)
    now = pd.Timestamp(now) if now is not None else pd.Timestamp.now(tz="UTC").tz_localize(None)
    start, end = data_start(origins, routes), data_end(origins, routes)
    names = dict(zip(asns["ASN"], asns["AS Name"])) if not asns.empty else {}
    rows = []

    def add(finding, severity, group, prefix, asn, detail, first=pd.NaT, last=pd.NaT):
        rows.append({"Finding": finding, "Severity": severity,
                     "Domains": ", ".join(sorted({d.strip() for v in group["Domains"] for d in str(v).split(",")
                                                  if d.strip()})),
                     "IP": ", ".join(sorted(set(group["IP"]))), "Prefix": prefix, "ASN": asn,
                     "AS Name": names.get(asn, ""), "Detail": detail, "First Seen": first, "Last Seen": last})

    usual = main_origins(origins)
    blocks = origins["Prefix"].astype(str).str.rstrip("+")   # a "/24+" entry belongs with its /24
    for prefix, group in origins.groupby(blocks):
        mains = usual[usual["Prefix"].astype(str).str.rstrip("+") == prefix]
        main = (mains if not mains.empty else group).sort_values("Updates", ascending=False).iloc[0]
        bad = group[group["Status"] == UNAUTHORIZED].drop_duplicates("Origin")
        good = group[group["Status"] == VALID]
        if not bad.empty and not good.empty:
            for _, row in bad.iterrows():
                if row["Origin"] in set(good["Origin"]):
                    continue
                recent = pd.notna(end) and row["Last Seen"] >= end - pd.Timedelta(days=RECENT_CONFLICT_DAYS)
                what = f"a more-specific prefix inside {prefix}" if is_more_specific_entry(row["Prefix"]) else prefix
                add(CONFLICT, "High" if recent else "Medium", group, prefix, row["Origin"],
                    f"{row['Origin']} announced {what} without authorization ({_why(row)}) while "
                    f"{', '.join(sorted(set(good['Origin'])))} is the authorized origin; seen by {row['Collectors']} "
                    f"collector(s), {row['Updates']} update(s), {row['First Seen']:%Y-%m-%d %H:%M} → "
                    f"{row['Last Seen']:%Y-%m-%d %H:%M} UTC", row["First Seen"], row["Last Seen"])
        elif main["Status"] == UNAUTHORIZED:
            add(UNAUTHORIZED_ORIGIN, "Medium-High", group, prefix, main["Origin"],
                f"{main['Origin']} announces {prefix} but {_why(main)}: no registry authorizes it",
                main["First Seen"], main["Last Seen"])
        if is_new(main["First Seen"], start, end):
            add(NEW_PREFIX, "Medium", group, prefix, main["Origin"],
                f"{main['Origin']} first announced {prefix} on {main['First Seen']:%Y-%m-%d} (BGPDB's data starts "
                f"{start:%Y-%m-%d}); seen by {main['Collectors']} collector(s)", main["First Seen"], main["Last Seen"])
        if 0 < main["Collectors"] < LOW_COLLECTORS:
            add(THIN_ROUTE, "Low", group, prefix, main["Origin"],
                f"{prefix} is seen by only {main['Collectors']} route collector(s): barely visible on the internet",
                main["First Seen"], main["Last Seen"])
    if not asns.empty:
        origin_groups = {asn: grp for asn, grp in usual.groupby("Origin")}
        for _, net in asns[asns["Role"] == "origin"].iterrows():
            group = origin_groups.get(net["ASN"])
            if group is None:
                continue
            registered = net["Registered"]
            if pd.notna(registered) and registered >= now - pd.Timedelta(days=NEW_ASN_DAYS):
                age = (now - registered).days
                add(NEW_ASN, "Medium-High" if age <= VERY_NEW_ASN_DAYS else "Medium", group, "", net["ASN"],
                    f"{net['ASN']} {net['AS Name']} was registered at {net['RIR'] or 'its RIR'} on "
                    f"{registered:%Y-%m-%d} ({age} days ago)" + (f", {net['RIR Country']}" if net["RIR Country"] else ""),
                    registered)
            if pd.notna(net["Upstreams"]) and int(net["Upstreams"]) == 1 and int(net["Downstreams"] or 0) == 0:
                add(THIN_ROUTE, "Low", group, "", net["ASN"],
                    f"{net['ASN']} {net['AS Name']} reaches the internet through a single upstream network and serves "
                    "no other network", net["First Seen"], net["Last Seen"])
    return pd.DataFrame(rows, columns=FINDING_COLUMNS).drop_duplicates(["Finding", "Prefix", "ASN", "Detail"]) \
        .reset_index(drop=True)


def _why(row):
    parts = [f"{name}: {row[name]}" for name in ("RPKI", "IRR") if "invalid" in str(row[name])]
    return ", ".join(parts) or "not authorized"


def ip_table(origins, routes=None, found=None, enrichment=None):
    """IP_COLUMNS: one row per IP: its most specific prefix and usual origin, the other origins seen, the upstream,
    the RIR next to Iris Investigate's country, and the findings naming it."""
    origins = _frame(origins, ORIGIN_COLUMNS)
    if origins.empty:
        return _empty(IP_COLUMNS)
    from integrations.enrichment import extract_iris_profile
    iris_country = {}
    for obj in (enrichment or {}).values():
        for entry in extract_iris_profile(obj)["ips"]:
            if entry.get("country"):
                iris_country.setdefault(entry["ip"], entry["country"])
    upstream = main_upstreams(routes)
    best = _most_specific(main_origins(origins))
    found = _frame(found, FINDING_COLUMNS)
    rows = []
    for _, row in best.iterrows():
        others = sorted(set(origins.loc[origins["IP"] == row["IP"], "Origin"]) - {row["Origin"]})
        names = sorted({f for f, ips in zip(found["Finding"], found["IP"]) if row["IP"] in str(ips).split(", ")}) \
            if not found.empty else []
        rows.append({"IP": row["IP"], "Domains": row["Domains"], "Prefix": row["Prefix"], "Origin": row["Origin"],
                     "AS Name": row["AS Name"], "Status": row["Status"],
                     "Origins": 1 + len(others), "Announced Since": row["First Seen"], "Collectors": row["Collectors"],
                     "RIR": row["RIR"], "RIR Country": row["RIR Country"], "Iris Country": iris_country.get(row["IP"], ""),
                     "Upstream": upstream.get(row["Prefix"], ""), "Findings": ", ".join(names)})
    return pd.DataFrame(rows, columns=IP_COLUMNS)


def summary(origins, asns=None, routes=None, found=None):
    """Counts for the Summary page and the run snapshot (Hunt map)."""
    origins, found = _frame(origins, ORIGIN_COLUMNS), _frame(found, FINDING_COLUMNS)
    if origins.empty:
        return {}
    by_kind = found["Finding"].value_counts().to_dict() if not found.empty else {}
    usual = main_origins(origins)
    return {"ips": int(origins["IP"].nunique()), "prefixes": int(origins["Prefix"].nunique()),
            "origins": int(usual["Origin"].nunique()), "unauthorized": int((origins["Status"] == UNAUTHORIZED).sum()),
            "conflicts": int(by_kind.get(CONFLICT, 0)), "new_prefixes": int(by_kind.get(NEW_PREFIX, 0)),
            "new_asns": int(by_kind.get(NEW_ASN, 0)), "thin": int(by_kind.get(THIN_ROUTE, 0)),
            "unauthorized_main": int(by_kind.get(UNAUTHORIZED_ORIGIN, 0)),
            "upstreams": len(set(main_upstreams(routes).values())), "findings": int(len(found))}


# ---- VPNDB match ------------------------------------------------------------------------------------------------------

VPNDB_IP_COLUMNS = ["IP", "Domains", "Category", "Provider", "Sharing", "Prefix", "Origin", "AS Name", "Status",
                    "Announced Since", "Findings"]
VPNDB_ASN_COLUMNS = ["ASN", "AS Name", "Registered", "Upstreams", "Downstreams", "Collectors", "Exits in run",
                     "Providers in run", "VPNDB Known Exits", "VPNDB Top Provider", "Single Tenant"]


def vpndb_ip_match(ips, anonymizers):
    """VPNDB_IP_COLUMNS: the run's VPN / proxy / Tor exits with their routing; exits on unstable routing first."""
    flagged = anonymizer_rows(anonymizers) if anonymizers is not None and not anonymizers.empty else pd.DataFrame()
    if ips is None or ips.empty or flagged.empty:
        return _empty(VPNDB_IP_COLUMNS)
    joined = flagged[["IP", "Category", "Provider", "Sharing"]].merge(ips, on="IP", how="inner")
    if joined.empty:
        return _empty(VPNDB_IP_COLUMNS)
    joined["_unstable"] = joined["Findings"].astype(str).map(lambda f: any(u in f for u in UNSTABLE))
    return joined.sort_values(["_unstable", "IP"], ascending=[False, True])[VPNDB_IP_COLUMNS].reset_index(drop=True)


def vpndb_asn_match(asns, anonymizers, hosting_asns=None):
    """
    VPNDB_ASN_COLUMNS: the origin networks that carry anonymizer exits (in this run, or per VPNDB's /asn verdict),
    with their BGP age and connectivity. A young or single-homed network full of exits is often a provider's own.
    """
    if asns is None or asns.empty:
        return _empty(VPNDB_ASN_COLUMNS)
    flagged = anonymizer_rows(anonymizers) if anonymizers is not None and not anonymizers.empty else pd.DataFrame()
    exits = {}
    if not flagged.empty and "ASN" in flagged.columns:
        for asn, group in flagged.groupby(flagged["ASN"].map(lambda a: _asn(str(a).split(".")[0]) if pd.notna(a) else "")):
            exits[asn] = (len(group), ", ".join(sorted({str(p) for p in group["Provider"] if p})))
    verdicts = {}
    if hosting_asns is not None and not hosting_asns.empty:
        for row in hosting_asns.to_dict("records"):
            verdicts[_asn(str(row.get("ASN", "")).split(".")[0])] = row
    rows = []
    for _, net in asns[asns["Role"] == "origin"].iterrows():
        count, providers = exits.get(net["ASN"], (0, ""))
        verdict = verdicts.get(net["ASN"], {})
        known = verdict.get("Known Exits")
        if not count and not (pd.notna(known) and known):
            continue
        rows.append({"ASN": net["ASN"], "AS Name": net["AS Name"], "Registered": net["Registered"],
                     "Upstreams": net["Upstreams"], "Downstreams": net["Downstreams"], "Collectors": net["Collectors"],
                     "Exits in run": count, "Providers in run": providers, "VPNDB Known Exits": known,
                     "VPNDB Top Provider": verdict.get("Top Provider", ""),
                     "Single Tenant": verdict.get("Single Tenant", "")})
    return pd.DataFrame(rows, columns=VPNDB_ASN_COLUMNS)


# ---- per domain (rules, Hunt map) -------------------------------------------------------------------------------------

def for_domain(frame, domain):
    """The rows of `frame` (with a Domains column) that name `domain`."""
    if frame is None or frame.empty or "Domains" not in frame.columns:
        return frame.iloc[0:0] if frame is not None else pd.DataFrame()
    return frame[frame["Domains"].astype(str).map(lambda v: domain in {d.strip() for d in v.split(",")})]


def domain_artifacts(origins):
    """{domain: {"Prefix": {...}, "ASN": {...}}} of the usual routing of each domain's IPs (for the run snapshot)."""
    out = {}
    for _, row in main_origins(origins).iterrows():
        for domain in str(row["Domains"]).split(","):
            domain = domain.strip()
            if domain:
                out.setdefault(domain, {}).setdefault("Prefix", set()).add(str(row["Prefix"]).lower())
                out[domain].setdefault("ASN", set()).add(str(row["Origin"]).lower())
    return out

"""
VPN, residential proxy and Tor attribution of the run's hosting IPs (VPNDB): which IPs are checked, one table row per
IP from the bulk answer and the full verdicts, and what an IP is worth as an indicator.

A shared exit (a VPN or proxy address many customers leave through) identifies the service, not the actor: VPNDB's
sharing level and IOC value say so, and the confirmed-indicator export uses them to keep such IPs out of block lists.
"""
import ipaddress

import pandas as pd

from core.helpers import registrable_domain
from core.network_intel import cdn_for_ip, explode_ip_events, is_public_ip
from integrations.enrichment import extract_iris_profile

COLUMNS = ["IP", "Domains", "Category", "Provider", "Types", "Infrastructure", "Confidence", "Method", "Tor", "Sharing",
           "IOC Value", "ASN", "AS Organization", "Country", "Last Seen", "Feeds", "Basis", "Attribution", "Network",
           "Geo Mismatch", "Tor Exit First Seen", "Tor Exit Last Seen", "Tor Exit Current", "Tor Relays",
           "Tor Exit Probability", "Tor Family", "Tor Reached Via", "Note"]
CONFIDENCE_LABELS = {3: "High", 2: "Medium", 1: "Low", 0: "Very low"}
TOR, RESIDENTIAL, VPN, PROXY = "Tor", "Residential proxy", "VPN", "Proxy"
ANONYMIZER_CATEGORIES = (TOR, RESIDENTIAL, VPN, PROXY, "Relay")
NOT_ANONYMOUS, NOT_OBSERVED, NOT_CHECKED = "Not anonymous", "Not observed", "Not checked"


def is_ipv4(ip):
    try:
        return ipaddress.ip_address(str(ip)).version == 4
    except ValueError:
        return False


def select_ips(domains, pdns, enrichment, ip_targets=(), max_ips=500, per_domain=100):
    """
    {ip: {domains}} to check: the IP targets, then per domain its current Iris IPs and its passive DNS addresses, most
    recently seen first, up to `per_domain` each and `max_ips` in all. Public IPv4 only (VPNDB does not collect IPv6),
    without CDN addresses (shared by every customer of the CDN, never an anonymizer exit).
    """
    chosen = {}

    def keep(ip):
        return is_ipv4(ip) and is_public_ip(ip) and not cdn_for_ip(ip)

    for ip in ip_targets:
        if keep(ip) and len(chosen) < max_ips:
            chosen.setdefault(str(ip), set()).add(str(ip))
    ip_rows = explode_ip_events(pdns) if pdns is not None and not pdns.empty else pd.DataFrame()
    if not ip_rows.empty:
        ip_rows = ip_rows.assign(_seen=pd.to_datetime(ip_rows["Last Seen"], errors="coerce").fillna(ip_rows["Date"]))
        ip_rows = ip_rows.sort_values("_seen", ascending=False)
    for domain in domains:
        candidates = [e["ip"] for e in extract_iris_profile((enrichment or {}).get(domain))["ips"]]
        if not ip_rows.empty:
            candidates += list(ip_rows.loc[ip_rows["Domain"] == domain, "IP"])
        picked = 0
        for ip in dict.fromkeys(str(c) for c in candidates):
            if picked >= per_domain:
                break
            if not keep(ip) or (ip not in chosen and len(chosen) >= max_ips):
                continue
            chosen.setdefault(ip, set()).add(domain)
            picked += 1
    return chosen


def _tor_text(tor):
    """'Exit (current)', 'Exit until 2026-01-04', 'Relay (guard)' from a verdict's tor block."""
    if not isinstance(tor, dict):
        return ""
    parts = []
    exit_info = tor.get("exit") or {}
    if exit_info:
        parts.append("Exit (current)" if exit_info.get("current") else f"Exit until {exit_info.get('lastSeen', '?')}")
    roles = sorted({relay.get("role", "") for relay in tor.get("relays") or [] if relay.get("role")})
    if roles:
        parts.append(f"Relay ({', '.join(roles)})")
    via = [v.get("provider") for v in tor.get("reachedVia") or [] if v.get("provider")]
    if via:
        parts.append(f"Tor via {', '.join(via)}")
    return "; ".join(parts)


def tor_fields(tor):
    """The Tor columns of a row from a verdict's tor block (Tor Project data via VPNDB): exit dates, relays, family."""
    tor = tor if isinstance(tor, dict) else {}
    exit_info, relays = tor.get("exit") or {}, tor.get("relays") or []
    return {
        "Tor Exit First Seen": exit_info.get("firstSeen") or "", "Tor Exit Last Seen": exit_info.get("lastSeen") or "",
        "Tor Exit Current": bool(exit_info.get("current")),
        "Tor Relays": "; ".join(f"{r.get('nickname') or r.get('fingerprint', '')[:8]} ({r.get('role', '?')}"
                                + (f": {', '.join(r['flags'])}" if r.get("flags") else "")
                                + f"; since {r.get('firstSeen', '?')})" for r in relays),
        "Tor Exit Probability": sum(r.get("exitProbability") or 0 for r in relays) or None,
        "Tor Family": max((r.get("familySize") or 0 for r in relays), default=0) or None,
        "Tor Reached Via": ", ".join(v.get("provider", "") for v in tor.get("reachedVia") or [] if v.get("provider")),
    }


def _attribution_text(attribution):
    """'nordvpn 62% (High), surfshark 38% (Low)': every provider VPNDB attributes the IP to, strongest first."""
    return ", ".join(f"{a.get('provider')} {a.get('weight', 0):.0%}"
                     + (f" ({CONFIDENCE_LABELS[a['confidence']]})" if a.get("confidence") in CONFIDENCE_LABELS else "")
                     for a in attribution or [] if a.get("provider"))


def _geo_text(mismatch):
    if not isinstance(mismatch, dict) or not mismatch.get("observed"):
        return ""
    return f"claims {mismatch.get('claimed', '?')}, exits in {mismatch['observed']}"


def category(anonymous, types, infrastructure, tor_text=""):
    """The one label a row is shown and alerted under (Tor first: it is the strongest statement)."""
    types = set(types or ())
    if "TOR" in types or tor_text.startswith(("Exit", "Relay")):
        return TOR
    if not anonymous:
        return NOT_ANONYMOUS
    if infrastructure in ("RESIDENTIAL", "MOBILE"):
        return RESIDENTIAL
    if "VPN" in types:
        return VPN
    if "PROXY" in types:
        return PROXY
    if "RELAY" in types:
        return "Relay"
    return "Hosting"


def _confidence(value):
    return CONFIDENCE_LABELS.get(value, "") if isinstance(value, int) else ""


def build_rows(candidates, bulk, details=None):
    """
    The table (COLUMNS) from the bulk answer's `results`, completed by full verdicts (`details`: {ip: /ip answer})
    where they were fetched; `candidates` ({ip: {domains}}) names the domains of each IP.
    """
    details = details or {}
    rows = []
    for item in (bulk or {}).get("results", []):
        ip = item.get("ip")
        verdict = details.get(ip) or {}
        sharing = verdict.get("sharing") or {}
        asn = (verdict.get("asn") or {})
        location = verdict.get("location") or {}
        tor = _tor_text(verdict.get("tor"))
        anonymous = bool(verdict.get("anonymous", item.get("anonymous")))
        types = verdict.get("types") or item.get("types") or []
        infrastructure = verdict.get("infrastructure") or item.get("infrastructure") or ""
        attribution = verdict.get("attribution") or []
        provider = item.get("provider") or (attribution[0].get("provider") if attribution else "")
        note = item.get("note") or (NOT_OBSERVED if not anonymous and not item.get("method") else "")
        rows.append({
            "IP": ip, "Domains": ", ".join(sorted(candidates.get(ip, ()))),
            "Category": note if note == NOT_OBSERVED else NOT_CHECKED if item.get("note") and not anonymous
                        else category(anonymous, types, infrastructure, tor),   # a note: VPNDB could not look it up
            "Provider": provider or "", "Types": ", ".join(types), "Infrastructure": infrastructure,
            "Confidence": _confidence(verdict.get("confidence", item.get("confidence"))),
            "Method": item.get("method") or ", ".join((verdict.get("evidence") or {}).get("methods") or []),
            "Tor": tor, "Sharing": sharing.get("level", ""), "IOC Value": sharing.get("iocValue", ""),
            "ASN": asn.get("number") or item.get("asn"), "AS Organization": asn.get("organization") or item.get("asnOrganization") or "",
            "Country": location.get("country") or item.get("country") or "",
            "Last Seen": (item.get("latest") or {}).get("day") or item.get("lastSeen") or "",
            "Feeds": ", ".join(item.get("feeds") or []),
            "Basis": ((verdict.get("evidence") or {}).get("confidenceBasis") or {}).get("explanation")
                     or item.get("confidenceBasis") or "",
            "Attribution": _attribution_text(attribution), "Network": verdict.get("network") or "",
            "Geo Mismatch": _geo_text(verdict.get("geoMismatch")), **tor_fields(verdict.get("tor")),
            "Note": note if note != NOT_OBSERVED else "",
        })
    frame = pd.DataFrame(rows, columns=COLUMNS)
    frame["ASN"] = pd.to_numeric(frame["ASN"], errors="coerce").astype("Int64")
    return frame


def anonymizer_rows(table):
    """The rows VPNDB attributes to a VPN, proxy, residential proxy, relay or Tor."""
    if table is None or table.empty:
        return pd.DataFrame(columns=COLUMNS)
    return table[table["Category"].isin(ANONYMIZER_CATEGORIES)]


def for_domains(table, domains):
    """The rows of IPs these domains used."""
    if table is None or table.empty:
        return pd.DataFrame(columns=COLUMNS)
    wanted = set(domains)
    return table[table["Domains"].astype(str).map(lambda d: bool(wanted & {x.strip() for x in d.split(",")}))]


def shared_exit(row):
    """True when the IP identifies the service, not the actor: VPNDB rates its IOC value low or its sharing high."""
    return row.get("IOC Value") == "LOW" or row.get("Sharing") == "HIGH"


def dedicated_exit(row):
    """True when VPNDB rates the exit as few-user (sharing LOW) or a strong actor indicator (IOC value HIGH)."""
    return row.get("Sharing") == "LOW" or row.get("IOC Value") == "HIGH"


def by_ip(table):
    """{ip: row dict} for the rule engine."""
    if table is None or table.empty:
        return {}
    return {row["IP"]: row for row in table.to_dict("records")}


# ---- CIDR ranges (VPNDB /prefix): looked up in VPNDB only ----------------------------------------------------------

PREFIX_COLUMNS = ["CIDR", "Category", "Top Provider", "Providers", "Provider Count", "Single Tenant", "Infrastructure",
                  "Known Exits", "Size", "Coverage", "Confidence", "Announced", "Contained Prefixes", "Covering Prefix",
                  "ASN", "AS Organization", "Countries", "Feeds", "Basis", "Note"]
ADDRESS_COLUMNS = ["CIDR", "IP", "Category", "Top Provider", "Providers", "Shared", "Methods", "Pool", "First Seen",
                   "Last Seen", "Observations", "Interpolated"]


NO_KNOWN_EXITS = "No known exits"   # VPNDB answered for the range but knows no VPN / proxy exit in it


def _prefix_category(verdict):
    infrastructure = verdict.get("infrastructure") or ""
    if not verdict.get("observedIps"):
        return NO_KNOWN_EXITS
    if infrastructure in ("RESIDENTIAL", "MOBILE"):
        return RESIDENTIAL
    return "VPN / proxy exits"


def prefix_row(cidr, verdict, note=""):
    """One PREFIX_COLUMNS row from a /prefix answer (a miss or an error: the category and note say so)."""
    verdict = verdict if isinstance(verdict, dict) else {}
    if verdict.get("observed") is False or not verdict:
        return {**dict.fromkeys(PREFIX_COLUMNS, ""), "CIDR": cidr, "Category": NOT_OBSERVED if verdict else NOT_CHECKED,
                "Note": note}
    attribution = verdict.get("attribution") or []
    asn = verdict.get("asn") or {}
    networks = verdict.get("networks") or []
    prefixes = verdict.get("prefixes") or {}
    size, known = verdict.get("networkSize"), verdict.get("observedIps") or 0
    countries = ((verdict.get("countries") or {}).get("countries") or [])[:5]
    return {
        "CIDR": cidr, "Category": _prefix_category(verdict),
        "Top Provider": attribution[0].get("provider", "") if attribution else "",
        "Providers": _attribution_text(attribution), "Provider Count": verdict.get("providerCount"),
        "Single Tenant": verdict.get("singleTenant"), "Infrastructure": verdict.get("infrastructure") or "",
        "Known Exits": known, "Size": size, "Coverage": f"{known / size:.1%}" if size else "",
        "Confidence": _confidence(max((a.get("confidence", -1) for a in attribution), default=None)),
        "Announced": verdict.get("exact"),
        "Contained Prefixes": len(prefixes.get("contained") or []),
        "Covering Prefix": ", ".join(p.get("prefix", "") for p in prefixes.get("covering") or []),
        "ASN": asn.get("number") or (networks[0].get("number") if networks else None),
        "AS Organization": asn.get("organization") or (networks[0].get("organization", "") if networks else ""),
        "Countries": ", ".join(f"{c['country']} {c.get('share', 0):.0%}" for c in countries if c.get("country")),
        "Feeds": ", ".join(f.get("sourceName", "") for f in verdict.get("feeds") or []),
        "Basis": ((verdict.get("evidence") or {}).get("confidenceBasis") or {}).get("explanation", ""),
        "Note": note or verdict.get("degraded") or "",
    }


def _flags(frame, *columns):
    """True / False columns (a miss leaves them blank, which Arrow cannot mix with booleans)."""
    for column in columns:
        frame[column] = frame[column].map(lambda v: v is True)
    return frame


def prefix_frame(rows):
    frame = _flags(pd.DataFrame(rows, columns=PREFIX_COLUMNS), "Single Tenant", "Announced")
    frame["ASN"] = pd.to_numeric(frame["ASN"], errors="coerce").astype("Int64")
    return frame


def address_rows(cidr, page):
    """ADDRESS_COLUMNS rows from a /prefix/{cidr}/addresses answer: every address probing reached in the window."""
    rows = []
    for item in (page or {}).get("addresses", []):
        providers = item.get("providers") or []
        pool = item.get("pool") or ""
        rows.append({
            "CIDR": cidr, "IP": item.get("ip"),
            "Category": RESIDENTIAL if pool == "residential" else VPN if providers else "",
            "Top Provider": providers[0].get("provider", "") if providers else "",
            "Providers": ", ".join(f"{p.get('provider')} {p.get('weight', 0):.0%}" for p in providers),
            "Shared": bool(item.get("shared")), "Methods": ", ".join(item.get("methods") or []), "Pool": pool,
            "First Seen": item.get("firstSeen"), "Last Seen": item.get("lastSeen"),
            "Observations": item.get("observations"), "Interpolated": bool(item.get("interpolated")),
        })
    return rows


# ---- What the other sources add (Iris Investigate, passive DNS) --------------------------------------------------

CROSSCHECK_COLUMNS = ["IP", "Domains", "Category", "Provider", "Sharing", "IOC Value", "Iris Domains", "Pivot Value",
                      "Iris ASN", "VPNDB ASN", "Iris ISP", "VPNDB Organization", "Iris Country", "VPNDB Country",
                      "Disagreement"]
LARGE_IRIS_COUNT = 1000   # an IP with more domains than this in Iris is shared hosting or a shared exit


def pivot_value(row, iris_count):
    """How useful the exit is as a pivot: VPNDB's sharing, then how many domains Iris has on it."""
    if row["Category"] not in ANONYMIZER_CATEGORIES:
        return ""
    if shared_exit(row) or (iris_count or 0) > LARGE_IRIS_COUNT:
        return "Noise: shared exit"
    if dedicated_exit(row) or (iris_count is not None and iris_count <= 50):
        return "Strong pivot"
    return "Check"


def crosscheck(table, enrichment):
    """
    One row per checked IP Iris Investigate also reports for a run domain: how many domains Iris has on it, and where
    Iris and VPNDB disagree on the network or the country (a VPN's virtual location, or a re-assigned address).
    """
    iris = {}
    for obj in (enrichment or {}).values():
        for entry in extract_iris_profile(obj)["ips"]:
            iris.setdefault(entry["ip"], entry)
    rows = []
    for row in (table.to_dict("records") if table is not None and not table.empty else []):
        entry = iris.get(row["IP"])
        if not entry:
            continue
        vpndb_asn = None if pd.isna(row["ASN"]) else int(row["ASN"])
        issues = []
        if entry["asn"] and vpndb_asn and entry["asn"] != vpndb_asn:
            issues.append(f"network AS{entry['asn']} vs AS{vpndb_asn}")
        if entry["country"] and row["Country"] and entry["country"] != str(row["Country"]).upper():
            issues.append(f"country {entry['country']} vs {str(row['Country']).upper()}")
        rows.append({"IP": row["IP"], "Domains": row["Domains"], "Category": row["Category"],
                     "Provider": row["Provider"], "Sharing": row["Sharing"], "IOC Value": row["IOC Value"],
                     "Iris Domains": entry.get("count"), "Pivot Value": pivot_value(row, entry.get("count")),
                     "Iris ASN": entry["asn"], "VPNDB ASN": vpndb_asn, "Iris ISP": entry["isp"],
                     "VPNDB Organization": row["AS Organization"], "Iris Country": entry["country"],
                     "VPNDB Country": str(row["Country"] or "").upper(), "Disagreement": "; ".join(issues)})
    frame = pd.DataFrame(rows, columns=CROSSCHECK_COLUMNS)
    for column in ("Iris Domains", "Iris ASN", "VPNDB ASN"):
        frame[column] = pd.to_numeric(frame[column], errors="coerce").astype("Int64")
    return frame


EXIT_WEEK_COLUMNS = ["IP", "Week", "Status", "Provider", "Weight"]
EXIT_STATUSES = ("probe", "scan", "interpolated")   # weeks VPNDB holds evidence the address was an exit


def exit_week_rows(histories):
    """EXIT_WEEK_COLUMNS rows from /ip/{ip}/history answers: the weeks each exit has evidence for (status not none)."""
    rows = []
    for ip, history in (histories or {}).items():
        for week in (history or {}).get("weeks") or []:
            if week.get("status") not in EXIT_STATUSES:
                continue
            providers = week.get("providers") or []
            rows.append({"IP": ip, "Week": pd.to_datetime(week.get("week"), errors="coerce"), "Status": week["status"],
                         "Provider": providers[0].get("provider", "") if providers else "",
                         "Weight": providers[0].get("weight") if providers else None})
    return pd.DataFrame(rows, columns=EXIT_WEEK_COLUMNS).dropna(subset=["Week"])


def use_intervals(events, ip, current=False, now=None):
    """[(start, end)] when the domain's passive DNS `events` resolved to `ip`, plus the last two weeks when it is a
    current Iris IP."""
    spans = []
    if events is not None and not events.empty:
        rows = explode_ip_events(events)
        rows = rows[rows["IP"].astype(str) == ip]
        for row in rows.to_dict("records"):
            start = pd.to_datetime(row.get("Date"), errors="coerce")
            end = pd.to_datetime(row.get("Last Seen"), errors="coerce")
            if pd.notna(start):
                spans.append((start, end if pd.notna(end) and end >= start else start))
    if current:
        now = now if now is not None else pd.Timestamp.now(tz="UTC").tz_localize(None)
        spans.append((now - pd.Timedelta(days=14), now))
    return spans


def exit_during_use(spans, weeks):
    """The exit weeks (Mondays) that overlap a use interval; [] when none does."""
    hits = []
    for week in weeks:
        week_end = week + pd.Timedelta(days=7)
        if any(start < week_end and end >= week for start, end in spans):
            hits.append(week)
    return hits


def vpndb_lookups(context):
    """({ip: [exit weeks]}, {/24: row}, {asn: row}) for the rule engine from the collect_anonymizer_context frames."""
    context = context or {}
    weeks, ranges, asns = (context.get(k) for k in ("exit_weeks", "neighbour_ranges", "hosting_asns"))
    exit_weeks = {ip: list(group["Week"]) for ip, group in weeks.groupby("IP")} \
        if weeks is not None and not weeks.empty else {}
    neighbours = {row["CIDR"]: row for row in ranges.to_dict("records")} if ranges is not None and not ranges.empty else {}
    networks = {int(row["ASN"]): row for row in asns.to_dict("records")} if asns is not None and not asns.empty else {}
    return exit_weeks, neighbours, networks


def tor_window(row, now=None):
    """(start, end) of the IP's time as a Tor exit (Tor Project exit lists), or None when not known."""
    first = pd.to_datetime(row.get("Tor Exit First Seen") or None, errors="coerce")   # NaN / "" become NaT
    last = pd.to_datetime(row.get("Tor Exit Last Seen") or None, errors="coerce")
    if pd.isna(first):
        return None
    now = now if now is not None else pd.Timestamp.now(tz="UTC").tz_localize(None)
    end = now if row.get("Tor Exit Current") is True or pd.isna(last) else last + pd.Timedelta(days=1)
    return first, end


def tor_exit_lookups(overview):
    """({asn: exitNetworks entry}, [(network, exitPrefixes entry)]) from the /tor overview, for the rule engine."""
    networks = {int(e["asn"]): e for e in (overview or {}).get("exitNetworks") or [] if e.get("asn")}
    prefixes = []
    for entry in (overview or {}).get("exitPrefixes") or []:
        try:
            prefixes.append((ipaddress.ip_network(entry.get("prefix", ""), strict=False), entry))
        except ValueError:
            continue
    return networks, prefixes


def neighbour_cidr(ip):
    """The /24 around an IPv4 address ('' for anything else)."""
    return str(ipaddress.ip_network(f"{ip}/24", strict=False)) if is_ipv4(ip) else ""


def neighbour_cidrs(table, max_ranges=30):
    """{a.b.c.0/24: {"ips", "domains"}} around the checked IPv4 addresses (not exits), most domains first."""
    ranges = {}
    for row in (table.to_dict("records") if table is not None and not table.empty else []):
        if not is_ipv4(row["IP"]):
            continue
        cidr = neighbour_cidr(row["IP"])
        entry = ranges.setdefault(cidr, {"ips": set(), "domains": set()})
        entry["ips"].add(row["IP"])
        entry["domains"] |= {d.strip() for d in str(row["Domains"]).split(",") if d.strip()}
    ordered = sorted(ranges.items(), key=lambda item: (-len(item[1]["domains"]), item[0]))
    return dict(ordered[:max_ranges])


NEIGHBOUR_COLUMNS = ["CIDR", "Hosting IPs", "Domains", "Category", "Top Provider", "Providers", "Known Exits",
                     "Coverage", "Single Tenant", "Infrastructure", "Confidence", "ASN", "AS Organization"]


def neighbour_frame(verdicts, ranges):
    """NEIGHBOUR_COLUMNS: VPNDB's verdict on each /24 around the run's hosting IPs, ranges with known exits first."""
    rows = []
    for cidr, entry in (ranges or {}).items():
        row = prefix_row(cidr, (verdicts or {}).get(cidr))
        rows.append({**{k: row.get(k, "") for k in NEIGHBOUR_COLUMNS}, "Hosting IPs": ", ".join(sorted(entry["ips"])),
                     "Domains": ", ".join(sorted(entry["domains"]))})
    frame = _flags(pd.DataFrame(rows, columns=NEIGHBOUR_COLUMNS), "Single Tenant")
    frame["Known Exits"] = pd.to_numeric(frame["Known Exits"], errors="coerce").fillna(0).astype(int)
    frame["ASN"] = pd.to_numeric(frame["ASN"], errors="coerce").astype("Int64")
    return frame.sort_values("Known Exits", ascending=False, kind="stable").reset_index(drop=True)


def hosting_asns(enrichment, domains, max_asns=20):
    """{asn: {domains}} of the run's current Iris IPs, most domains first."""
    asns = {}
    for domain in domains:
        for entry in extract_iris_profile((enrichment or {}).get(domain))["ips"]:
            if entry["asn"]:
                asns.setdefault(entry["asn"], set()).add(domain)
    ordered = sorted(asns.items(), key=lambda item: (-len(item[1]), item[0]))
    return dict(ordered[:max_asns])


ASN_COLUMNS = ["ASN", "AS Organization", "Country", "Domains", "Known Exits", "Networks", "Provider Count",
               "Single Tenant", "Top Provider", "Providers", "Non-anonymous Share", "Network Type", "Note"]


def asn_frame(verdicts, asns):
    """ASN_COLUMNS: the VPN / proxy providers VPNDB knows on each hosting network (/asn answers)."""
    rows = []
    for asn, domains in (asns or {}).items():
        verdict = (verdicts or {}).get(asn) or {}
        attribution = verdict.get("attribution") or []
        collateral = verdict.get("collateral") or {}
        share = collateral.get("nonAnonymousShare")
        rows.append({"ASN": asn, "AS Organization": verdict.get("organization", ""),
                     "Country": verdict.get("country", ""), "Domains": ", ".join(sorted(domains)),
                     "Known Exits": verdict.get("observedIps") or 0, "Networks": verdict.get("networkCount"),
                     "Provider Count": verdict.get("providerCount"), "Single Tenant": verdict.get("singleTenant"),
                     "Top Provider": attribution[0].get("provider", "") if attribution else "",
                     "Providers": _attribution_text(attribution[:5]),
                     "Non-anonymous Share": f"{share:.0%}" if isinstance(share, (int, float)) else "",
                     "Network Type": collateral.get("networkType", ""),
                     "Note": collateral.get("note", "") if verdict else NOT_CHECKED})
    frame = _flags(pd.DataFrame(rows, columns=ASN_COLUMNS), "Single Tenant")
    frame["Known Exits"] = pd.to_numeric(frame["Known Exits"], errors="coerce").fillna(0).astype(int)
    return frame.sort_values("Known Exits", ascending=False, kind="stable").reset_index(drop=True)


EXIT_NEIGHBOUR_COLUMNS = ["IP", "Name", "Domain", "First Seen", "Last Seen", "Analyzed"]


def exit_neighbour_rows(frames, analyzed):
    """EXIT_NEIGHBOUR_COLUMNS: the other names DNSDB saw resolving to each dedicated exit, newest first."""
    analyzed = set(analyzed)
    rows = []
    for ip, frame in (frames or {}).items():
        if frame is None or frame.empty:
            continue
        for record in frame.to_dict("records"):
            name = str(record["RRName"]).rstrip(".").lower()
            apex = registrable_domain(name) or name
            rows.append({"IP": ip, "Name": name, "Domain": apex, "First Seen": record.get("First Seen"),
                         "Last Seen": record.get("Last Seen"), "Analyzed": apex in analyzed})
    frame = pd.DataFrame(rows, columns=EXIT_NEIGHBOUR_COLUMNS)
    if frame.empty:
        return frame
    return frame.sort_values("Last Seen", ascending=False).drop_duplicates(["IP", "Name"]).reset_index(drop=True)


# ---- Tor network (VPNDB /tor) and VPNDB answers as tables -------------------------------------------------------------

def tor_tables(overview):
    """{"Networks", "Countries", "Prefixes"}: where Tor exit traffic leaves, from the /tor overview (shares in %)."""
    tables = {}
    for name, key in (("Networks", "exitNetworks"), ("Countries", "exitCountries"), ("Prefixes", "exitPrefixes")):
        rows = (overview or {}).get(key) or []
        frame = pd.json_normalize(rows, sep=".") if rows else pd.DataFrame()
        if "exitShare" in frame:
            frame["exitShare"] = (frame["exitShare"] * 100).round(2)
            frame = frame.rename(columns={"exitShare": "Exit share %"}).sort_values("Exit share %", ascending=False)
        tables[name] = frame.reset_index(drop=True)
    return tables


def tor_context(overview, ip, asn=None, country=None):
    """Where `ip` sits in the Tor network: [(what, text)] for its network, prefix and country among Tor exits."""
    found = []
    for entry in (overview or {}).get("exitNetworks") or []:
        if asn and entry.get("asn") == asn:
            found.append(("Network", f"AS{asn} {entry.get('organization', '')}: {entry.get('exitAddresses', 0):,} Tor "
                                     f"exit address(es), {entry.get('exitShare', 0):.2%} of all Tor exit traffic"))
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        address = None
    for entry in (overview or {}).get("exitPrefixes") or []:
        try:
            inside = address is not None and address in ipaddress.ip_network(entry.get("prefix", ""), strict=False)
        except ValueError:
            inside = False
        if inside:
            found.append(("Prefix", f"{entry['prefix']}: {entry.get('exitAddresses', 0):,} Tor exit address(es), "
                                    f"{entry.get('exitShare', 0):.2%} of Tor exit traffic"))
    for entry in (overview or {}).get("exitCountries") or []:
        if country and str(entry.get("country", "")).upper() == str(country).upper():
            found.append(("Country", f"{entry['country']}: {entry.get('exitAddresses', 0):,} Tor exit address(es), "
                                     f"{entry.get('exitShare', 0):.2%} of Tor exit traffic"))
    return found


ANSWER_LIST_KEYS = ("results", "addresses", "weeks", "networks", "attribution", "relays")   # rows of an answer


def answer_tables(response):
    """
    A VPNDB answer as tables: {name: DataFrame}. "Fields" holds the scalar fields flattened (`asn.number`,
    `sharing.level`), and each list of records (bulk `results`, `addresses`, history `weeks`, `attribution`, ...) its own
    table, one row per item with nested fields flattened.
    """
    if not isinstance(response, dict):
        return {"Fields": pd.DataFrame([{"Field": "response", "Value": "" if response is None else str(response)}])}
    tables, scalars = {}, {}
    for key, value in response.items():
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            tables[key] = pd.json_normalize(value, sep=".")
        elif isinstance(value, dict):
            flat = pd.json_normalize(value, sep=".").to_dict("records")
            for name, item in (flat[0] if flat else {}).items():
                if isinstance(item, list) and item and all(isinstance(x, dict) for x in item):
                    tables[f"{key}.{name}"] = pd.json_normalize(item, sep=".")
                else:
                    scalars[f"{key}.{name}"] = item
        else:
            scalars[key] = value
    fields = pd.DataFrame([{"Field": k, "Value": ", ".join(map(str, v)) if isinstance(v, list) else
                            ("" if v is None else str(v))} for k, v in scalars.items()])
    ordered = sorted(tables, key=lambda name: (name.split(".")[-1] not in ANSWER_LIST_KEYS, name))
    return {"Fields": fields, **{name: tables[name] for name in ordered}}

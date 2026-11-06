"""
High-level numbers of a run for the Summary page: what the run covers, alerts by category, the infrastructure its
domains share, week-by-week activity, domains and certificates that are new or about to expire, how the lookups went,
and the clusters of linked domains. Everything is built from the dataset; nothing is looked up.
"""
import pandas as pd

from core.helpers import extract_ip_addresses
from core.self_signed import self_signed_certificates
from integrations.enrichment import extract_iris_profile

SEVERITY_ORDER = ["Critical", "High", "Medium-High", "Medium", "Low"]
RECENT_DAYS = 30           # "registered recently" and "expiring soon"
ACTIVITY_WEEKS = 52        # weeks the activity chart shows (ending at the newest event)
SHARED_TOP = 5             # values per infrastructure type
IP_FIELDS = ("A", "AAAA", "IP")
ACTIVITY_KINDS = ["Registration", "Name server change", "IP change", "New certificate", "New hostname"]


def _now(now):
    return pd.Timestamp.now(tz="UTC").tz_localize(None) if now is None else now


def _clean(value):
    return str(value or "").strip().lower().rstrip(".")


def _profiles(ds):
    return {domain: extract_iris_profile(obj) for domain, obj in (ds.enrichment or {}).items()}


def _ip_values(pdns):
    if pdns is None or pdns.empty:
        return set()
    rows = pdns[pdns["Field"].astype(str).str.upper().isin(IP_FIELDS)]
    return {ip for value in rows["Value"].astype(str) for ip in extract_ip_addresses(value)}


def _ns_rows(pdns):
    """(domain, name server) of the NS records of the analyzed names themselves (not of their subdomains)."""
    if pdns is None or pdns.empty or "RRName" not in pdns:
        return []
    rows = pdns[(pdns["Field"].astype(str).str.upper() == "NS")
                & (pdns["RRName"].map(_clean) == pdns["Domain"].map(_clean))]
    return [(domain, _clean(line.split()[-1])) for domain, value in zip(rows["Domain"], rows["Value"].astype(str))
            for line in value.split("\n") if line.split()]


def glance_stats(ds, alerts):
    """The run in numbers: {label: value} plus the time span the data covers."""
    profiles = _profiles(ds)
    ips = _ip_values(ds.pdns_utc) | {entry["ip"] for p in profiles.values() for entry in p["ips"]}
    asns = {entry["asn"] for p in profiles.values() for entry in p["ips"] if entry["asn"]}
    name_servers = {ns for _, ns in _ns_rows(ds.pdns_utc)} | {ns for p in profiles.values() for ns in p["name_servers"]}
    ssl = ds.ssl_utc if ds.ssl_utc is not None else pd.DataFrame()
    certificates = ssl["Hash"].astype(str).str.lower().replace("", pd.NA).dropna().nunique() if "Hash" in ssl else 0
    hostnames = ds.pdns_utc["RRName"].map(_clean).nunique() if ds.pdns_utc is not None and "RRName" in ds.pdns_utc else 0
    dates = pd.to_datetime(ds.events_utc["Date"], errors="coerce").dropna() \
        if ds.events_utc is not None and "Date" in ds.events_utc else pd.Series(dtype="datetime64[ns]")
    severities = alerts["Severity"].value_counts().to_dict() if alerts is not None and not alerts.empty else {}
    return {
        "Domains": len(ds.selected_domains),
        "Alerts": {s: int(severities.get(s, 0)) for s in SEVERITY_ORDER},
        "IPs": len(ips),
        "ASNs": len(asns),
        "Name servers": len(name_servers),
        "Certificates": int(certificates),
        "Self-signed": len(self_signed_certificates(ssl, ds.selected_domains)),
        "Passive DNS records": 0 if ds.pdns_utc is None else len(ds.pdns_utc),
        "Hostnames": int(hostnames),
        "First event": dates.min() if not dates.empty else None,
        "Last event": dates.max() if not dates.empty else None,
    }


def alerts_by_category(alerts):
    """Alert count per (Category, Severity), categories with the most alerts first."""
    if alerts is None or alerts.empty:
        return pd.DataFrame(columns=["Category", "Severity", "Alerts"])
    counts = alerts.groupby(["Category", "Severity"]).size().reset_index(name="Alerts")
    order = counts.groupby("Category")["Alerts"].sum().sort_values(ascending=False).index
    counts["Category"] = pd.Categorical(counts["Category"], categories=list(order), ordered=True)
    counts["Severity"] = pd.Categorical(counts["Severity"], categories=SEVERITY_ORDER, ordered=True)
    return counts.sort_values(["Category", "Severity"]).reset_index(drop=True)


def shared_infrastructure(ds, top=SHARED_TOP):
    """
    Top hosting networks, registrars, name servers and certificate issuers of the run, with how many of its domains
    use each. A value two or more domains share is a lead to one operator (unless it is a big provider).
    """
    found = []   # (type, value, domain)
    for domain, profile in _profiles(ds).items():
        for entry in profile["ips"]:
            network = f"AS{entry['asn']} {entry['isp']}".strip() if entry["asn"] else entry["isp"]
            if network:
                found.append(("Hosting network", network, domain))
        if profile["registrar"]:
            found.append(("Registrar", profile["registrar"], domain))
        found += [("Name server", ns, domain) for ns in profile["name_servers"]]
    found += [("Name server", ns, domain) for domain, ns in _ns_rows(ds.pdns_utc)]
    ssl = ds.ssl_utc if ds.ssl_utc is not None else pd.DataFrame()
    if not ssl.empty:
        issuer = ssl["Issuer Org"] if "Issuer Org" in ssl else pd.Series("", index=ssl.index)
        issuer = issuer.fillna("").astype(str).where(issuer.fillna("").astype(str).str.strip() != "",
                                                     ssl.get("Issuer", pd.Series("", index=ssl.index)).fillna("").astype(str))
        found += [("Certificate issuer", value.strip(), domain) for value, domain in zip(issuer, ssl["Domain"])
                  if value.strip()]
    columns = ["Type", "Value", "Domains", "Shared", "Domain List"]
    if not found:
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame(found, columns=["Type", "Value", "Domain"]).drop_duplicates()
    grouped = frame.groupby(["Type", "Value"])["Domain"].apply(lambda x: sorted(set(x))).reset_index()
    grouped["Domains"] = grouped["Domain"].map(len)
    grouped["Shared"] = grouped["Domains"] > 1
    grouped["Domain List"] = grouped["Domain"].map(", ".join)
    grouped = grouped.sort_values(["Type", "Domains", "Value"], ascending=[True, False, True])
    return grouped.groupby("Type", sort=False).head(top)[columns].reset_index(drop=True)


def _weekly(dates, kind):
    dates = pd.to_datetime(pd.Series(list(dates)), errors="coerce", utc=True).dropna().dt.tz_localize(None)
    return pd.DataFrame({"Date": dates, "Activity": kind})


def weekly_activity(ds, weeks=ACTIVITY_WEEKS):
    """Events per week and kind (ACTIVITY_KINDS) over the last `weeks` weeks of the data, all domains together."""
    frames = [_weekly([p["create_date"] for p in _profiles(ds).values()], "Registration")]
    dh = ds.dh_utc if ds.dh_utc is not None else pd.DataFrame()
    if not dh.empty:
        fields = dh["Field"].astype(str).str.upper()
        frames.append(_weekly(dh.loc[fields == "NAME_SERVER", "Date"], "Name server change"))
        frames.append(_weekly(dh.loc[fields == "IP", "Date"], "IP change"))
    pdns = ds.pdns_utc if ds.pdns_utc is not None else pd.DataFrame()
    if not pdns.empty and "First Seen" in pdns:
        fields = pdns["Field"].astype(str).str.upper()
        frames.append(_weekly(pdns.loc[fields == "NS", "First Seen"], "Name server change"))
        frames.append(_weekly(pdns.loc[fields.isin(IP_FIELDS), "First Seen"], "IP change"))
        if "RRName" in pdns:
            frames.append(_weekly(pdns.assign(_n=pdns["RRName"].map(_clean)).groupby("_n")["First Seen"].min(),
                                  "New hostname"))
    ssl = ds.ssl_utc if ds.ssl_utc is not None else pd.DataFrame()
    if not ssl.empty and "Not Before Date" in ssl:
        frames.append(_weekly(ssl.drop_duplicates(subset=["Hash"] if "Hash" in ssl else None)["Not Before Date"],
                              "New certificate"))
    events = pd.concat(frames, ignore_index=True)
    columns = ["Week", "Activity", "Events"]
    if events.empty:
        return pd.DataFrame(columns=columns)
    start = events["Date"].max() - pd.Timedelta(weeks=weeks)
    if ds.window is not None and ds.window.start is not None:   # registrations before the window stay out too
        start = max(start, ds.window.start)
    events = events[events["Date"] >= start]
    events["Week"] = events["Date"].dt.to_period("W-SUN").dt.start_time
    counts = events.groupby(["Week", "Activity"]).size().unstack(fill_value=0)
    weeks = pd.date_range(counts.index.min(), counts.index.max(), freq="W-MON")   # quiet weeks count 0
    counts = counts.reindex(weeks, fill_value=0).rename_axis("Week").reset_index()
    counts = counts.melt(id_vars="Week", var_name="Activity", value_name="Events")
    return counts.sort_values(["Week", "Activity"]).reset_index(drop=True)[columns]


def lifecycle_stats(ds, now=None, days=RECENT_DAYS):
    """Newest domain, domains registered or expiring within `days`, and valid certificates expiring within `days`."""
    now = _now(now)
    soon = now + pd.Timedelta(days=days)
    rows = [(domain, p["create_date"], p["expiration_date"]) for domain, p in _profiles(ds).items()]
    created = [(d, c) for d, c, _ in rows if c is not None and pd.notna(c)]
    newest = max(created, key=lambda item: item[1]) if created else None
    ssl = ds.ssl_utc if ds.ssl_utc is not None else pd.DataFrame()
    certs = []
    if not ssl.empty and "Not After Date" in ssl:
        not_after = pd.to_datetime(ssl["Not After Date"], errors="coerce")
        expiring = ssl[(not_after >= now) & (not_after <= soon)]
        expiring = expiring.drop_duplicates(subset=["Hash"] if "Hash" in expiring else None)
        names = expiring.assign(_day=pd.to_datetime(expiring["Not After Date"]).dt.normalize()) \
            .groupby(["Common Name", "_day"]).size().reset_index(name="n")   # renewals of one name: listed once
        certs = sorted(((f"{cn} ×{n}" if n > 1 else str(cn), day) for cn, day, n in names.itertuples(index=False)),
                       key=lambda item: item[1])
    return {
        "Newest domain": newest,
        "Registered recently": sorted(((d, c) for d, c in created if c >= now - pd.Timedelta(days=days)),
                                      key=lambda item: item[1], reverse=True),
        "Domains expiring": sorted(((d, e) for d, _, e in rows if e is not None and pd.notna(e) and now <= e <= soon),
                                   key=lambda item: item[1]),
        "Certificates expiring": certs,
        "Days": days,
    }


def data_health(statuses, progress_rows=None, now=None):
    """How the run's lookups went: {Lookups, OK, Partial, No data, Failed, Cached, Oldest cached (epoch or None)}."""
    frame = pd.DataFrame(statuses or [], columns=["Status", "Detail"])
    detail = frame["Detail"].astype(str)
    cached_at = [at for row in progress_rows or [] for _, at in getattr(row, "cache_hits", [])]
    return {
        "Lookups": len(frame),
        "OK": int((frame["Status"] == "OK").sum()),
        "Partial": int((frame["Status"] == "Partial").sum()),
        "No data": int((frame["Status"] == "No data").sum()),
        "Failed": int((frame["Status"] == "Error").sum()),
        "Cached": int(detail.str.contains("From cache").sum()),
        "Oldest cached": min(cached_at) if cached_at else None,
    }


def cluster_callouts(correlation, limit=3, values=2):
    """One sentence per cluster of linked domains: which domains share what (strong clusters first)."""
    clusters = sorted(getattr(correlation, "clusters", None) or [],
                      key=lambda c: (c["Strength"] != "Strong", -c["Size"]))
    lines = []
    for cluster in clusters[:limit]:
        shared = "; ".join(f"{kind} {', '.join(items[:values])}" + (f" (+{len(items) - values})" if len(items) > values else "")
                           for kind, items in cluster["Shared Artifacts"].items())
        domains = cluster["Domains"]
        names = ", ".join(domains[:4]) + (f" and {len(domains) - 4} more" if len(domains) > 4 else "")
        lines.append({"Cluster": cluster["Cluster"], "Strength": cluster["Strength"], "Size": cluster["Size"],
                      "Text": f"{names} share {shared}"})
    return lines

"""
API usage of a run: which service and DomainTools product each lookup counts against, the queries a run made (status
rows' "Queries": 0 for results from the lookup cache), what each product has left, and the per-source, per-target
and overall statistics of the Data sources page. Pure functions.
"""
import pandas as pd

DOMAINTOOLS, DNSDB, VPNDB, IRIS_WEB = "DomainTools API", "DNSDB", "VPNDB", "Iris pDNS (web session)"
IRIS_PRODUCTS = ("iris-investigate", "iris-investigate-(api-only)")
# status row Source prefix -> (service, DomainTools product ID or None); the first matching prefix wins
SOURCE_PRODUCTS = (
    ("Iris pDNS", IRIS_WEB, None),
    ("Iris Investigate", DOMAINTOOLS, "iris-investigate"),
    ("IrisQL", DOMAINTOOLS, "iris-investigate"),
    ("Domain History", DOMAINTOOLS, "domain-history"),
    ("Certificate Search", DOMAINTOOLS, "certificate-search"),
    ("CertsQL", DOMAINTOOLS, "certificate-search"),
    ("Cert Events", DOMAINTOOLS, "certificate-events"),
    ("CT Log", DOMAINTOOLS, "certificate-events"),
    ("Account Information", DOMAINTOOLS, "account-information"),
    ("DNSDB", DNSDB, None),
    ("VPNDB", VPNDB, None),
)
# status row Source prefix -> lookup cache group (config.CACHE_GROUPS)
CACHE_GROUP_PREFIXES = (("Iris pDNS", "pdns"), ("DNSDB", "pdns"), ("Iris Investigate", "iris"), ("IrisQL", "iris"),
                        ("Domain History", "history"), ("Certificate Search", "certs"), ("CertsQL", "certs"),
                        ("Cert Events", "certs"), ("CT Log", "certs"), ("VPNDB", "vpndb"))
USAGE_COLUMNS = ["Service", "Product", "Lookups", "From cache", "Queries"]


def source_product(source):
    """(service, DomainTools product ID or None) a status row's Source counts against; (source, None) if unknown."""
    text = str(source or "")
    for prefix, service, product in SOURCE_PRODUCTS:
        if text.startswith(prefix):
            return service, product
    return text, None


def cache_group(source):
    """The lookup cache group (config.CACHE_GROUPS) of a status row's Source, or None."""
    text = str(source or "")
    return next((group for prefix, group in CACHE_GROUP_PREFIXES if text.startswith(prefix)), None)


def failed_lookups(statuses):
    """Lookups of a run that failed or stopped with an error: they were not cached, so a re-run queries them again."""
    return sum(1 for row in statuses or [] if row.get("Status") == "Error"
               or str(row.get("Detail", "")).startswith("Incomplete"))


def product_label(service, product):
    return product or service


def run_usage(statuses):
    """One row per service / product (USAGE_COLUMNS): the run's lookups, how many came from the cache, and the API
    queries made. Rows without a Queries value (older runs, notes) count as 0 queries."""
    rows = []
    for status in statuses or []:
        if "Queries" not in status:
            continue
        service, product = source_product(status.get("Source"))
        cached = pd.notna(status.get("Cached At", pd.NaT))
        rows.append({"Service": service, "Product": product_label(service, product), "Lookups": 1,
                     "From cache": int(bool(cached)), "Queries": int(status.get("Queries") or 0)})
    if not rows:
        return pd.DataFrame(columns=USAGE_COLUMNS)
    frame = pd.DataFrame(rows).groupby(["Service", "Product"], as_index=False, sort=False).sum()
    return frame[USAGE_COLUMNS].sort_values(["Service", "Queries"], ascending=[True, False], kind="stable") \
        .reset_index(drop=True)


def queries_by_product(statuses):
    """{product (or service): queries} of a run, for its Run History snapshot."""
    usage = run_usage(statuses)
    return {row["Product"]: int(row["Queries"]) for row in usage.to_dict("records") if row["Queries"]}


def total_queries(statuses):
    return int(run_usage(statuses)["Queries"].sum()) if statuses else 0


def remaining(products, product):
    """What the account has left of `product` this month (int), None when it has no monthly limit or is unknown.
    For Iris, whichever Iris product the account has."""
    ids = IRIS_PRODUCTS if product in IRIS_PRODUCTS else (product,)
    for item in products or []:
        if item.get("id") in ids:
            left = (item.get("rest") or {}).get("month")
            try:
                return int(str(left).strip())
            except (TypeError, ValueError):
                limit, used = item.get("per_month_limit"), (item.get("usage") or {}).get("month")
                try:
                    return int(limit) - int(used)
                except (TypeError, ValueError):
                    return None
    return None



def capped_history(statuses):
    """
    Domains whose Domain History stopped at the cap (or the no-cap safeguard), so more changes are available:
    {domain: changes fetched}, from the run's status rows.
    """
    capped = {}
    for row in statuses or []:
        detail = str(row.get("Detail") or "")
        if str(row.get("Source", "")).startswith("Domain History") and row.get("Status") == "Partial" \
                and ("more changes are available" in detail or detail.startswith("Stopped at")):   # older runs
            capped[row.get("Target")] = int(row.get("Records") or 0)
    return capped


STATUSES = ("OK", "Partial", "No data", "Error")
SOURCE_STAT_COLUMNS = ["Source", "Product", "Lookups", "Answered", "OK", "Partial", "No data", "Errors", "Records",
                       "Avg records", "Max records", "Queries", "From cache"]
TARGET_STAT_COLUMNS = ["Target", "Sources", "Lookups", "OK", "Partial", "No data", "Errors", "Records", "Queries",
                       "From cache", "Needs attention"]


def status_frame(statuses):
    """The run's status rows as a frame with numeric Records / Queries and a boolean "Cached" column."""
    frame = pd.DataFrame([row for row in statuses or [] if row.get("Source")],
                         columns=["Source", "Target", "Status", "Records", "Detail", "Cached At", "Queries"])
    frame["Records"] = pd.to_numeric(frame["Records"], errors="coerce").fillna(0).astype(int)
    frame["Queries"] = pd.to_numeric(frame["Queries"], errors="coerce").fillna(0).astype(int)
    frame["Cached"] = pd.to_datetime(frame["Cached At"], errors="coerce").notna() \
        | frame["Detail"].astype(str).str.contains("From cache", regex=False)
    frame["Target"] = frame["Target"].fillna("").astype(str)
    return frame


def _counts(frame):
    status = frame["Status"]
    return {"Lookups": len(frame), "OK": int((status == "OK").sum()), "Partial": int((status == "Partial").sum()),
            "No data": int((status == "No data").sum()), "Errors": int((status == "Error").sum()),
            "Records": int(frame["Records"].sum()), "Queries": int(frame["Queries"].sum()),
            "From cache": int(frame["Cached"].sum())}


def run_overview(statuses):
    """The run in numbers: lookups, targets and sources, outcome counts, records, API queries, cache hits, and the
    share of lookups that got an answer ("Answered": all but errors, 0-1)."""
    frame = status_frame(statuses)
    counts = _counts(frame)
    return {**counts, "Targets": int(frame["Target"].nunique()), "Sources": int(frame["Source"].nunique()),
            "Answered": (1 - counts["Errors"] / counts["Lookups"]) if counts["Lookups"] else 0.0}


def source_stats(statuses):
    """One row per source (SOURCE_STAT_COLUMNS): outcomes, records (total, average and largest per lookup), API
    queries and cache hits; "Answered" is the share of its lookups without an error (0-1)."""
    frame = status_frame(statuses)
    rows = []
    for source, group in frame.groupby("Source", sort=False):
        counts = _counts(group)
        rows.append({"Source": source, "Product": product_label(*source_product(source)), **counts,
                     "Answered": 1 - counts["Errors"] / counts["Lookups"],
                     "Avg records": round(group["Records"].mean(), 1), "Max records": int(group["Records"].max())})
    return pd.DataFrame(rows, columns=SOURCE_STAT_COLUMNS).sort_values(
        ["Errors", "Partial", "Records"], ascending=False, kind="stable").reset_index(drop=True)


def target_stats(statuses):
    """One row per target (TARGET_STAT_COLUMNS): how many sources looked it up, their outcomes, records, queries and
    cache hits, and "Needs attention": the sources that failed or stopped at a limit for it."""
    frame = status_frame(statuses)
    rows = []
    for target, group in frame.groupby("Target", sort=False):
        issues = group[group["Status"].isin(["Error", "Partial"])]
        rows.append({"Target": target, "Sources": int(group["Source"].nunique()), **_counts(group),
                     "Needs attention": ", ".join(f"{s} ({st.lower()})" for s, st in zip(issues["Source"],
                                                                                          issues["Status"]))})
    return pd.DataFrame(rows, columns=TARGET_STAT_COLUMNS).sort_values(
        ["Errors", "Partial", "Records"], ascending=False, kind="stable").reset_index(drop=True)


def attention_rows(statuses):
    """Lookups that failed or stopped at a limit, errors first, with what happened."""
    frame = status_frame(statuses)
    frame = frame[frame["Status"].isin(["Error", "Partial"])]
    return frame.sort_values(["Status", "Source", "Target"], kind="stable")[
        ["Status", "Source", "Target", "Records", "Detail"]].reset_index(drop=True)

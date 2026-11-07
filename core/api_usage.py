"""
API usage of a run: which service and DomainTools product each lookup counts against, the queries a run made (status
rows' "Queries": 0 for results from the lookup cache), and how a cost estimate compares with what the account has
left. Pure functions; the estimate itself is built in integrations.estimate.
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
ESTIMATE_COLUMNS = ["Service", "Product", "Lookups", "From cache", "Queries (min)", "Queries (max)", "Left",
                    "Status"]


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


def compare_estimate(estimate, products=None, quotas=None):
    """
    `estimate` rows ({"Service", "Product", "Lookups", "From cache", "Queries (min)", "Queries (max)"}) with "Left"
    (DomainTools products from the account's `products`; DNSDB and VPNDB from `quotas` {service: remaining}) and a
    "Status": "over" when even the fewest queries exceed what is left, "may exceed" when the most would, else "ok"
    ("unknown" when nothing is known about what is left).
    """
    rows = []
    for row in estimate:
        product = row["Product"]
        left = remaining(products, product) if row["Service"] == DOMAINTOOLS else (quotas or {}).get(row["Service"])
        if left is None:
            status = "unknown"
        elif row["Queries (min)"] > left:
            status = "over"
        elif row["Queries (max)"] > left:
            status = "may exceed"
        else:
            status = "ok"
        rows.append({**row, "Left": left, "Status": status})
    frame = pd.DataFrame(rows, columns=ESTIMATE_COLUMNS)
    frame["Left"] = pd.to_numeric(frame["Left"], errors="coerce").astype("Int64")
    return frame

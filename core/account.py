"""
DomainTools Account Information (/v1/account): the account and each product's limits, usage and expiry, as tables for
the Account page. The API returns numbers as strings and "" or null where a product has no such limit.
"""
import pandas as pd

from config import EXPIRY_WARN_DAYS, QUOTA_WARN_PERCENT

# Products this app's lookups count against (Iris Investigate may be billed to either Iris product)
APP_PRODUCTS = {
    "iris-investigate": "IrisQL searches, enrichment and risk scores of analyzed domains",
    "iris-investigate-(api-only)": "IrisQL searches, enrichment and risk scores of analyzed domains (API-only plan)",
    "domain-history": "Domain History of analyzed domains",
    "certificate-search": "CertsQL searches and certificate lookups by name",
    "certificate-events": "Certificate events of hostnames, IPs and SHA-256s",
    "account-information": "This page",
}
# What the app needs, each met by any one of its product IDs: (feature, what fails without it, product IDs)
APP_NEEDS = (
    ("Iris Investigate", "IrisQL searches, and the Iris enrichment and risk scores of analyzed domains",
     ("iris-investigate", "iris-investigate-(api-only)")),
    ("Domain History", "Domain History of analyzed domains", ("domain-history",)),
    ("Certificate search", "CertsQL searches and certificate lookups by name", ("certificate-search",)),
    ("Certificate events", "certificate events of hostnames, IPs and SHA-256s", ("certificate-events",)),
)
# What each collection stage needs from the account (product IDs; any one will do): stages are skipped without it
STAGE_PRODUCTS = {
    "iris": ("iris-investigate", "iris-investigate-(api-only)"),
    "history": ("domain-history",),
    "certs": ("certificate-search",),
    "events": ("certificate-events",),
}
STAGE_NAMES = {"iris": "Iris Investigate", "history": "Domain History", "certs": "Certificate Search",
               "events": "Certificate events"}
PRODUCT_COLUMNS = ["Product", "Used by this app", "Today", "This month", "Monthly limit", "Left this month",
                   "Used %", "Per hour", "Per minute", "Expires", "ID"]
_WORDS = {"api": "API", "s3": "S3", "ip": "IP", "rdap": "RDAP", "rpz": "RPZ", "mcp": "MCP", "whois": "Whois"}


def _number(value):
    """int of an API count ("82"), or None for null / "" / anything else."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def product_name(product_id):
    """"iris-investigate-(api-only)" -> "Iris investigate (API only)"."""
    main, _, extra = str(product_id or "").partition("-(")

    def words(text):
        return " ".join(_WORDS.get(word.lower(), word) for word in text.split("-") if word)

    name = words(main) + (f" ({words(extra.rstrip(')'))})" if extra else "")
    return name[:1].upper() + name[1:]


def account_parts(payload):
    """(account dict, products list) of an account_information() payload, with or without its "response" wrapper."""
    response = (payload or {}).get("response", payload or {}) or {}
    return response.get("account") or {}, list(response.get("products") or [])


def products_frame(products):
    """One row per product (PRODUCT_COLUMNS); the ones this app uses first, then by monthly use."""
    rows = []
    for product in products:
        pid = product.get("id", "")
        usage, rest = product.get("usage") or {}, product.get("rest") or {}
        limit, month = _number(product.get("per_month_limit")), _number(usage.get("month"))
        left = _number(rest.get("month"))
        if left is None and limit is not None and month is not None:
            left = limit - month
        rows.append({
            "Product": product_name(pid),
            "Used by this app": pid in APP_PRODUCTS,
            "Today": _number(usage.get("today")),
            "This month": month,
            "Monthly limit": limit,
            "Left this month": left,
            "Used %": round(100 * month / limit, 1) if limit and month is not None else None,
            "Per hour": _number(product.get("per_hour_limit")),
            "Per minute": _number(product.get("per_minute_limit")),
            "Expires": product.get("expiration_date") or None,
            "ID": pid,
        })
    frame = pd.DataFrame(rows, columns=PRODUCT_COLUMNS)
    counts = ["Today", "This month", "Monthly limit", "Left this month", "Per hour", "Per minute"]
    frame[counts] = frame[counts].astype("Int64")   # whole numbers, empty where the API gives none
    frame["Used %"] = frame["Used %"].astype("float64")
    if frame.empty:
        return frame
    frame = frame.sort_values(["Used by this app", "This month", "Product"], ascending=[False, False, True],
                              na_position="last", kind="stable")
    return frame.reset_index(drop=True)


def _expiry_text(value, today):
    """(level, text) for an expiration date: "error" once past, "warning" within EXPIRY_WARN_DAYS, else None."""
    day = pd.to_datetime(value, errors="coerce", utc=True)
    if pd.isna(day):
        return None, None
    days = (day.date() - today).days
    if days < 0:
        return "error", f"expired on {day:%Y-%m-%d}"
    if days <= EXPIRY_WARN_DAYS:
        return "warning", f"expires on {day:%Y-%m-%d} ({'today' if days == 0 else f'in {days} day' + ('s' if days != 1 else '')})"
    return None, None


def quota_level(used, limit):
    """"error" when `used` reaches `limit`, "warning" from QUOTA_WARN_PERCENT of it, else None (also when unknown)."""
    if not limit or used is None:
        return None
    if used >= limit:
        return "error"
    return "warning" if 100 * used / limit >= QUOTA_WARN_PERCENT else None


def account_alerts(products, today=None):
    """
    Banner lines for the products this app uses (APP_PRODUCTS): [{"level": "error" | "warning", "product", "text"}].
    Red when the monthly quota is used up or the product expired; yellow from QUOTA_WARN_PERCENT used or within
    EXPIRY_WARN_DAYS of expiring. Empty when the products are unknown (None).
    """
    today = today or pd.Timestamp.now(tz="UTC").date()
    alerts = []
    for product in products or []:
        pid = product.get("id", "")
        if pid not in APP_PRODUCTS:
            continue
        name = product_name(pid)
        limit, used = _number(product.get("per_month_limit")), _number((product.get("usage") or {}).get("month"))
        level = quota_level(used, limit)
        if level == "error":
            alerts.append({"level": "error", "product": name,
                           "text": f"{name}: this month's quota is used up ({used:,} of {limit:,}); its lookups fail "
                                   "until it resets next month"})
        elif level == "warning":
            alerts.append({"level": "warning", "product": name,
                           "text": f"{name}: {100 * used / limit:.0f}% of this month's quota used ({used:,} of "
                                   f"{limit:,}, {limit - used:,} left)"})
        level, text = _expiry_text(product.get("expiration_date"), today)
        if level:
            alerts.append({"level": level, "product": name, "text": f"{name} {text}"
                           + ("; its lookups fail" if level == "error" else "")})
    return alerts


def dnsdb_alerts(rate, now=None):
    """The same banner lines for a DNSDB key from its rate-limit check (`rate`: limit, remaining, expires)."""
    if not rate:
        return []
    alerts = []
    limit, left = _number(rate.get("limit")), _number(rate.get("remaining"))
    if limit and left is not None:
        level = quota_level(limit - left, limit)
        if level == "error":
            alerts.append({"level": "error", "product": "DNSDB", "text": f"DNSDB: the key's quota is used up (0 of "
                                                                         f"{limit:,} left); its lookups fail until it resets"})
        elif level == "warning":
            alerts.append({"level": "warning", "product": "DNSDB",
                           "text": f"DNSDB: {100 * (limit - left) / limit:.0f}% of the key's quota used ({left:,} of "
                                   f"{limit:,} left)"})
    expires = _number(rate.get("expires"))
    if expires:
        today = (now or pd.Timestamp.now(tz="UTC")).date()
        level, text = _expiry_text(pd.Timestamp(expires, unit="s", tz="UTC"), today)
        if level:
            alerts.append({"level": level, "product": "DNSDB", "text": f"DNSDB key {text}"})
    return alerts


def missing_app_products(products):
    """(feature, what fails without it) for each APP_NEEDS entry none of whose products the account has."""
    have = {p.get("id") for p in products}
    return [(feature, effect) for feature, effect, ids in APP_NEEDS if not have.intersection(ids)]


def unavailable_stages(products):
    """Collection stages (STAGE_PRODUCTS keys) none of whose products are in `products`; empty when unknown (None)."""
    if products is None:
        return set()
    have = {p.get("id") for p in products}
    return {stage for stage, ids in STAGE_PRODUCTS.items() if not have.intersection(ids)}


def nearest_expiry(products):
    """The earliest expiration_date of any product (ISO text), or None when none has one."""
    dates = sorted(p.get("expiration_date") for p in products if p.get("expiration_date"))
    return dates[0] if dates else None


def endpoints(products):
    """{product id: [endpoint, ...]} for products that list endpoints (e.g. download-files feeds)."""
    return {p.get("id", ""): list(p["endpoints"]) for p in products if p.get("endpoints")}

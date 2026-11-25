"""
Summary figures for the Breakdown tabs of the IrisQL and CertsQL pages, worked out from the result tables alone (no
request): tiles, risk bands, monthly counts, concentration on the top IPs / name servers, validity classes.
"""
import pandas as pd

from core.helpers import is_ip_address

RISK_BANDS = (("0–39", 0, 39), ("40–69", 40, 69), ("70–89", 70, 89), ("90–100", 90, 100))
VALIDITY_CLASSES = (("≤ 10 days", 0, 10), ("11–47 days", 11, 47), ("48–100 days", 48, 100),
                    ("101–200 days", 101, 200), ("201–398 days", 201, 398), ("> 398 days", 399, None))


def _dates(values):
    dates = pd.to_datetime(pd.Series(values, dtype="object"), errors="coerce", utc=True)
    return dates.dt.tz_localize(None)


def _split(values):
    """Comma-separated cells ("a, b") → one list per row, blanks dropped."""
    return [[part.strip() for part in str(cell or "").split(",") if part.strip()] for cell in values]


def _now(now):
    return pd.Timestamp(now) if now is not None else pd.Timestamp.now(tz="UTC").tz_localize(None)


def risk_band(score):
    if score is None or pd.isna(score):
        return None
    return next((name for name, low, high in RISK_BANDS if low <= score <= high), None)


def risk_bands(scores):
    """{band: domains} for every band in order (0 when none), unknown scores left out."""
    counts = pd.Series([risk_band(s) for s in scores], dtype="object").value_counts()
    return {name: int(counts.get(name, 0)) for name, _, _ in RISK_BANDS}


def iris_summary(domains, ips, high_risk=70, now=None, days=30):
    """The IrisQL Breakdown tiles: risk, recent registrations, upcoming expiries, activity and spread."""
    now = _now(now)
    risk = pd.to_numeric(domains["Risk Score"], errors="coerce")
    created, expires = _dates(domains["Create Date"]), _dates(domains["Expiration Date"])
    active = domains["Active"].map(lambda v: v if isinstance(v, bool) else None)
    return {
        "domains": len(domains),
        "median_risk": None if risk.dropna().empty else float(risk.median()),
        "high_risk": int((risk >= high_risk).sum()),
        "new": int(((now - created).dt.days.between(0, days)).sum()),
        "expiring": int(((expires - now).dt.days.between(0, days)).sum()),
        "active": int((active == True).sum()),   # noqa: E712 (None stays out of both counts)
        "inactive": int((active == False).sum()),   # noqa: E712
        "registrars": int(domains["Registrar"].replace("", None).dropna().nunique()),
        "asns": int(ips["ASN"].dropna().nunique()) if "ASN" in ips else 0,
        "countries": int(ips["Country"].replace("", None).dropna().nunique()) if "Country" in ips else 0,
    }


def monthly(dates, bands=None):
    """Rows (Month, Band, Count) per month of `dates` (YYYY-MM), split by `bands` (one label per row) when given."""
    frame = pd.DataFrame({"Month": _dates(dates).dt.strftime("%Y-%m"),
                          "Band": list(bands) if bands is not None else "All"}).dropna(subset=["Month"])
    if frame.empty:
        return pd.DataFrame(columns=["Month", "Band", "Count"])
    frame["Band"] = frame["Band"].fillna("Unknown")
    return frame.groupby(["Month", "Band"]).size().reset_index(name="Count").sort_values("Month", kind="stable")


def top_values(cells, limit=10):
    """Most common values of comma-separated cells (each value counted once per row)."""
    values = [value for row in _split(cells) for value in dict.fromkeys(row)]
    return pd.Series(values, dtype="object").value_counts().head(limit)


def concentration(cells, top=5):
    """(share of rows that use one of the `top` most common values, those values): e.g. domains on the top 5 IPs."""
    rows = _split(cells)
    used = [row for row in rows if row]
    if not used:
        return 0.0, []
    leaders = list(top_values(cells, top).index)
    hit = sum(1 for row in used if set(row) & set(leaders))
    return hit / len(rows), leaders


def validity_class(days):
    if days is None or pd.isna(days):
        return None
    return next((name for name, low, high in VALIDITY_CLASSES if days >= low and (high is None or days <= high)), None)


def cert_summary(certs, now=None, days=30):
    """The CertsQL Breakdown tiles, over the certificates ticked Use."""
    now = _now(now)
    used = certs[certs["Use"].astype(bool)]
    not_after = _dates(used["Not After"])
    validity = pd.to_numeric(used["Days"], errors="coerce")
    left = (not_after - now).dt.days
    levels = used["Validation"].replace("", None).dropna().value_counts()
    return {
        "used": len(used),
        "issuers": int(used["Issuer"].replace("", None).dropna().nunique()),
        "median_days": None if validity.dropna().empty else float(validity.median()),
        "validation": {str(k): int(v) for k, v in levels.items()},
        "self_signed": int(used["Self-signed"].astype(bool).sum()),
        "expired": int((left < 0).sum()),
        "expiring": int(left.between(0, days).sum()),
        "short_lived": int((validity <= 10).sum()),
    }


def validity_classes(days):
    """{class: certificates} for every validity class in order."""
    counts = pd.Series([validity_class(d) for d in days], dtype="object").value_counts()
    return {name: int(counts.get(name, 0)) for name, _, _ in VALIDITY_CLASSES}


def names_per_cert(sans):
    """(names per certificate as a Series, wildcard certificates): from the SANs column ("a, b, *.c")."""
    rows = _split(sans)
    return pd.Series([len(row) for row in rows], dtype="int64"), sum(1 for row in rows if any(n.startswith("*.")
                                                                                             for n in row))


def san_ips(sans, limit=10):
    """Most common IP addresses named in the SANs."""
    values = [name for row in _split(sans) for name in dict.fromkeys(row) if is_ip_address(name)]
    return pd.Series(values, dtype="object").value_counts().head(limit)

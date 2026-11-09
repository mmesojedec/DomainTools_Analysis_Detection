"""DomainTools Domain History (SDK) lookup, payload unwrapping, and snapshot lifespan calculation."""
import pandas as pd

from config import DOMAIN_HISTORY_MAX_CHANGES, DOMAIN_HISTORY_SAFETY_LIMIT
from core.helpers import refang_domain
from core.pdns_features import add_event_gaps, add_tempo_features
from integrations.cache import cached_fetch
from integrations.credentials import DTAPI_MISSING, get_dt_api
from integrations.http import FetchResult, describe_exception, sdk_call

SOURCE = "Domain History"
PAGE_SIZE = 100  # API maximum


def _older(change, since):
    """True when the change happened before `since` (ISO date); changes without a readable date are kept."""
    when = pd.to_datetime(change.get("timestamp"), errors="coerce", utc=True)
    return pd.notna(when) and when.strftime("%Y-%m-%d") < since


@cached_fetch(group="history")
def fetch_domain_history(domain, max_changes=DOMAIN_HISTORY_MAX_CHANGES, since=None):
    """
    Fetches change events via the DomainTools SDK with offset pagination. data = {"response": {"changes": [...]}}.
    The API returns the newest changes first, so with `since` (an ISO date) paging stops at the first change before
    it, and older changes are left out. `max_changes` limits the changes per domain (Max changes; 0: no limit, up to
    DOMAIN_HISTORY_SAFETY_LIMIT); a domain that reaches it is `truncated`: it has more changes.
    """
    limit = int(max_changes) if max_changes else DOMAIN_HISTORY_SAFETY_LIMIT
    clean_dom = refang_domain(domain)
    api = get_dt_api()
    if api is None:
        return FetchResult(SOURCE, clean_dom, data=None, error=DTAPI_MISSING)

    changes, reached = [], False
    try:
        while len(changes) < limit:
            page = sdk_call(lambda: api.domain_history(clean_dom, page_size=PAGE_SIZE, offset=len(changes)).data())
            page_changes = (page or {}).get("response", {}).get("changes", []) or []
            if since:
                kept = [change for change in page_changes if not _older(change, since)]
                reached = len(kept) < len(page_changes)
                page_changes = kept
            changes.extend(page_changes)
            if reached or len(page_changes) < PAGE_SIZE:
                break
    except Exception as exc:
        if getattr(exc, "code", None) == 404:
            return FetchResult(SOURCE, clean_dom, data={"response": {"changes": []}})
        return FetchResult(SOURCE, clean_dom, data={"response": {"changes": changes}}, error=describe_exception(exc),
                           record_count=len(changes))

    truncated = len(changes) >= limit
    note = None
    if truncated:
        note = (f"Stopped at Max changes ({limit:,}); more changes are available" if max_changes else
                f"Stopped at the safety limit of {limit:,} changes; more changes are available")
    if since:
        note = "; ".join(filter(None, [note, f"Changes since {since} (Domain History period)"]))
    return FetchResult(SOURCE, clean_dom, data={"response": {"changes": changes}}, truncated=truncated,
                       record_count=len(changes), note=note)


def clean_unwrap(val):
    """Recursively unwraps single-item {"value": ...} dicts and lists from DomainTools JSON."""
    if isinstance(val, dict):
        if len(val) == 1 and "value" in val:
            return clean_unwrap(val["value"])
        return {k: clean_unwrap(v) for k, v in val.items()}
    if isinstance(val, list):
        return [clean_unwrap(item) for item in val]
    return str(val) if val is not None else ""


def format_value(val):
    """Formats unwrapped dictionary and list structures into readable strings."""
    unwrapped = clean_unwrap(val)
    if isinstance(unwrapped, dict):
        return ", ".join(f"{k}: {format_value(v)}" for k, v in unwrapped.items())
    if isinstance(unwrapped, list):
        return "\n".join(format_value(item) for item in unwrapped)
    return str(unwrapped) if unwrapped != "" else "None"


def _changes(raw_json):
    return (raw_json or {}).get("response", {}).get("changes", []) or []


def parse_history_to_dataframe(raw_json, domain_name):
    """Parses raw Domain History change events into a normalized DataFrame."""
    records = []
    for item in _changes(raw_json):
        field = item.get("field", "Unknown")
        before_raw = item.get("before", {})
        after_raw = item.get("after", {})
        b_val = format_value(before_raw.get(field, before_raw) if isinstance(before_raw, dict) else before_raw)
        a_val = format_value(after_raw.get(field, after_raw) if isinstance(after_raw, dict) else after_raw)
        records.append({
            "Domain": domain_name,
            "Timestamp": item.get("timestamp", ""),
            "Field": field.upper(),
            "Before": b_val,
            "After": a_val,
            "Change Event": f"{field.upper()}: {b_val} ➔ {a_val}",
        })
    df = pd.DataFrame(records)
    if df.empty:
        return df
    df["Date"] = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True).dt.tz_localize(None)
    df = df.dropna(subset=["Date"])
    if df.empty:
        return df.reset_index(drop=True)
    df = add_tempo_features(df)
    df = add_event_gaps(df)
    return df.sort_values("Date", ascending=False).reset_index(drop=True)


def _unwrap(obj, key, default=""):
    value = obj.get(key, default) if isinstance(obj, dict) else default
    return value.get("value", default) if isinstance(value, dict) else value


def extract_ssl_data(raw_json, domain_name):
    """Parses nested SSL certificate snapshots from Domain History change events."""
    ssl_records = []
    for item in _changes(raw_json):
        if item.get("field") != "ssl_info":
            continue
        after_ssl = (item.get("after") or {}).get("ssl_info", [])
        if not isinstance(after_ssl, list):
            continue
        for cert in after_ssl:
            if not isinstance(cert, dict):
                continue
            cn = _unwrap(cert, "common_name")
            issuer = _unwrap(cert, "issuer_common_name")
            cn_clean, issuer_clean = str(cn).strip().lower(), str(issuer).strip().lower()
            ssl_records.append({
                "Domain": domain_name,
                "Timestamp": item.get("timestamp", ""),
                "Hash": _unwrap(cert, "hash"),
                "Common Name": cn,
                "Issuer": issuer,
                "Alt Names List": [a.get("value", "") for a in cert.get("alt_names", []) if isinstance(a, dict)],
                "Not Before": _unwrap(cert, "not_before"),
                "Not After": _unwrap(cert, "not_after"),
                "Duration": None,
                "Is Self Signed": bool(cn_clean) and cn_clean == issuer_clean,
                "Source": SOURCE,
            })

    df = pd.DataFrame(ssl_records)
    if not df.empty:
        df["Date"] = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True).dt.tz_localize(None)
        df["Not Before Date"] = pd.to_datetime(df["Not Before"], format="%Y%m%d", errors="coerce")
        df["Not After Date"] = pd.to_datetime(df["Not After"], format="%Y%m%d", errors="coerce")
    return df


def calculate_lifespans_for_dh(df_chronological):
    """Calculates forward-looking lifespans for Domain History snapshots (until the next change of that field)."""
    if df_chronological is None or df_chronological.empty:
        return pd.DataFrame()
    df = df_chronological.dropna(subset=["Date"]).sort_values("Date", kind="stable").copy()
    now = pd.Timestamp.now(tz="UTC").tz_localize(None)
    df["End"] = df.groupby(["Domain", "Field"])["Date"].shift(-1).fillna(now)
    lifespan = ((df["End"] - df["Date"]).dt.total_seconds() / 86400.0).round(1)
    values = df["After"].astype(str)
    return pd.DataFrame({
        "Domain": df["Domain"],
        "Field": df["Field"],
        "Domain_Field": df["Domain"].astype(str) + " | " + df["Field"].astype(str),
        "Value": values.where(values.str.len() <= 60, values.str[:60] + "..."),
        "Start": df["Date"],
        "End": df["End"],
        "Lifespan Days": lifespan.where(lifespan > 0, 0.1),
    }).reset_index(drop=True)

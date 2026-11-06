"""DomainTools Risk Evidence (SDK) lookup and risk component aggregation."""
import pandas as pd

from core.helpers import refang_domain
from integrations.cache import cached_fetch
from integrations.credentials import DTAPI_MISSING, get_dt_api
from integrations.http import FetchResult, describe_exception

SOURCE = "Risk Evidence"
RISK_COLUMNS = ["Domain", "Component", "Score", "Threats", "Evidence"]


@cached_fetch()
def fetch_risk_evidence(domain):
    """Fetches risk evidence via the DomainTools SDK. data = the API `response` object."""
    clean_dom = refang_domain(domain)
    api = get_dt_api()
    if api is None:
        return FetchResult(SOURCE, clean_dom, error=DTAPI_MISSING)
    try:
        payload = api.risk_evidence(clean_dom).data()
    except Exception as exc:
        if getattr(exc, "code", None) == 404:
            return FetchResult(SOURCE, clean_dom, data={}, note="No risk score available")
        return FetchResult(SOURCE, clean_dom, error=describe_exception(exc))
    response = (payload or {}).get("response", {}) or {}
    has_score = response.get("risk_score") is not None
    return FetchResult(SOURCE, clean_dom, data=response, record_count=1 if has_score else 0,
                       note=None if has_score else "No risk score available")


def risk_response_to_rows(domain, response):
    """Converts one risk evidence response into component rows. No rows when no score was returned."""
    if not response or response.get("risk_score") is None:
        return []
    rows = [{"Domain": domain, "Component": "Overall Risk", "Score": response.get("risk_score"), "Threats": "", "Evidence": ""}]
    for comp in response.get("components", []) or []:
        rows.append({
            "Domain": domain,
            "Component": str(comp.get("name", "Unknown")).replace("_", " ").title(),
            "Score": comp.get("risk_score", 0),
            "Threats": ", ".join(comp.get("threats", []) or []),
            "Evidence": ", ".join(comp.get("evidence", []) or []),
        })
    return rows


def risk_rows_to_dataframe(rows):
    df = pd.DataFrame(rows, columns=RISK_COLUMNS)
    if not df.empty:
        df["Score"] = pd.to_numeric(df["Score"], errors="coerce")
    return df

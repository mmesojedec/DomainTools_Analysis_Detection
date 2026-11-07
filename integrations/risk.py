"""
DomainTools risk scores of analyzed domains, read from the Iris Investigate records the run already fetched
(`domain_risk`: the overall score and its components with their threats and evidence), so they cost no extra query.
"""
import pandas as pd

RISK_COLUMNS = ["Domain", "Component", "Score", "Threats", "Evidence"]


def risk_from_iris(enrichment):
    """Risk component rows (RISK_COLUMNS) of every domain in `enrichment` ({domain: Iris record}) that has a score."""
    rows = []
    for domain, record in (enrichment or {}).items():
        rows.extend(risk_response_to_rows(domain, (record or {}).get("domain_risk")))
    return risk_rows_to_dataframe(rows)


def risk_response_to_rows(domain, response):
    """Converts one `domain_risk` object (Iris Investigate) into component rows. No rows when no score was returned."""
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

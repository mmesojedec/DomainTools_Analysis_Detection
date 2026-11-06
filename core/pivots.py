"""
Pivot ranking: every value in the run's Iris Investigate records that other domains can share (IPs, name servers,
emails, registrant details, certificates, trackers, ...), with Iris's count of domains that share it. A value shared by
a few hundred domains is a strong lead to the same operator; one shared by millions (a CDN IP, a large registrar's
name server) is noise. Values shared by several domains of the run rank first within each signal level.
"""
from urllib.parse import urlencode

import pandas as pd

from config import PIVOT_STRONG_MAX, PIVOT_USEFUL_MAX
from integrations.enrichment import TRACKER_FIELDS

PIVOT_COLUMNS = ["Signal", "Type", "Value", "Iris Domains", "Run Domains", "Shared With", "Iris Search", "Analyze As"]
SIGNALS = {
    "Strong": f"2 to {PIVOT_STRONG_MAX:,} domains share it: small enough to review every domain, often one operator",
    "Useful": f"{PIVOT_STRONG_MAX + 1:,} to {PIVOT_USEFUL_MAX:,} domains: combine with another pivot or filter "
              "(create date, TLD, risk) in Iris",
    "Weak": f"More than {PIVOT_USEFUL_MAX:,} domains: shared infrastructure (CDN, large host, registrar), rarely useful alone",
    "This domain only": "No other domain shares it in Iris",
    "Count unknown": "Iris returned the value without a count",
}
SIGNAL_ORDER = list(SIGNALS)
# Iris Investigate search parameter per tracker field (TRACKER_FIELDS gives the label)
TRACKER_PARAMS = {
    "ga4": "google_analytics_4", "gtm_codes": "google_tag_manager", "google_analytics": "google_analytics",
    "adsense": "adsense", "yandex_codes": "yandex_metrica", "baidu_codes": "baidu_analytics", "hotjar_codes": "hotjar",
    "matomo_codes": "matomo", "fb_codes": "facebook", "statcounter_project_codes": "statcounter_project",
    "statcounter_security_codes": "statcounter_security",
}
CONTACTS = ("registrant_contact", "admin_contact", "technical_contact", "billing_contact")
IRIS_API_URL = "https://api.domaintools.com/v1/iris-investigate/"


def signal_of(count):
    if count is None or pd.isna(count) or count <= 0:
        return "Count unknown"
    if count == 1:
        return "This domain only"
    if count <= PIVOT_STRONG_MAX:
        return "Strong"
    return "Useful" if count <= PIVOT_USEFUL_MAX else "Weak"


def _entries(value):
    """{"value", "count"} entries from an Iris field that is one entry or a list of them."""
    for entry in value if isinstance(value, list) else [value]:
        if isinstance(entry, dict) and str(entry.get("value", "")).strip():
            yield str(entry["value"]).strip(), entry.get("count")


def iter_pivots(record):
    """(type, Iris search parameter, value, count, target line or "") for every pivotable value of one Iris record."""
    record = record if isinstance(record, dict) else {}
    for ip in record.get("ip") or []:
        for value, count in _entries((ip or {}).get("address")):
            yield "IP address", "ip", value, count, value
    for kind, field_name, param in (("Name server", "name_server", "nameserver"), ("Mail server", "mx", "mailserver")):
        for server in record.get(field_name) or []:
            for value, count in _entries((server or {}).get("host")):
                yield kind, f"{param}_host", value.lower().rstrip("."), count, ""
            for value, count in _entries((server or {}).get("ip")):
                yield f"{kind} IP", f"{param}_ip", value, count, value
    for kind, field_name, param in (("Registrant", "registrant_name", "registrant"),
                                    ("Registrant org", "registrant_org", "registrant_org")):
        for value, count in _entries(record.get(field_name)):
            yield kind, param, value, count, ""
    for contact in CONTACTS:
        details = record.get(contact) or {}
        for value, count in _entries(details.get("email")):
            yield "Contact email", "email", value.lower(), count, ""
        for value, count in _entries(details.get("phone")):
            yield "Contact phone", "contact_phone", value, count, ""
        for value, count in _entries(details.get("street")):
            yield "Contact street", "contact_street", value, count, ""
    for kind, field_name in (("WHOIS email", "additional_whois_email"), ("SOA email", "soa_email")):
        for value, count in _entries(record.get(field_name)):
            yield kind, "email", value.lower(), count, ""
    for value, count in _entries(record.get("email_domain")):
        yield "Email domain", "email_domain", value.lower(), count, ""
    for cert in record.get("ssl_info") or []:
        cert = cert or {}
        for value, count in _entries(cert.get("hash")):
            yield "SSL certificate (SHA-1)", "ssl_hash", value.lower(), count, f"sha1:{value.lower()}"
        common_name = next((v for v, _ in _entries(cert.get("common_name"))), "")
        for value, count in _entries(cert.get("subject")):
            yield "SSL subject", "ssl_subject", value, count, f"cn:{common_name}" if common_name else ""
        for value, count in _entries(cert.get("organization")):
            yield "SSL organization", "ssl_org", value, count, f"org:{value}"
        for value, count in _entries(cert.get("email")):
            yield "SSL email", "ssl_email", value.lower(), count, ""
    for field_name, label in TRACKER_FIELDS:
        for value, count in _entries(record.get(field_name)):
            yield label, TRACKER_PARAMS[field_name], value, count, ""
    for value, count in _entries(record.get("redirect_domain")):
        yield "Redirect domain", "redirect_domain", value.lower(), count, value.lower()


def build_pivot_ranking(enrichment):
    """
    One row (PIVOT_COLUMNS) per distinct (type, value) across the run's Iris records, ranked by signal level, then by
    how many of the run's domains share it, then by the Iris count (smaller first).
    """
    found = {}
    for domain, record in (enrichment or {}).items():
        for kind, param, value, count, target in iter_pivots(record):
            row = found.setdefault((kind, value), {"Type": kind, "Value": value, "Iris Domains": None, "Domains": set(),
                                                   "Iris Search": f"{param}={value}", "Analyze As": target})
            if isinstance(count, (int, float)) and count > 0:
                row["Iris Domains"] = max(row["Iris Domains"] or 0, int(count))
            row["Domains"].add(domain)
    rows = []
    for row in found.values():
        domains = sorted(row.pop("Domains"))
        rows.append({**row, "Signal": signal_of(row["Iris Domains"]), "Run Domains": len(domains),
                     "Shared With": ", ".join(domains)})
    if not rows:
        return pd.DataFrame(columns=PIVOT_COLUMNS)
    frame = pd.DataFrame(rows)
    frame["Iris Domains"] = frame["Iris Domains"].astype("Int64")
    frame = frame.assign(_signal=frame["Signal"].map(SIGNAL_ORDER.index))
    frame = frame.sort_values(["_signal", "Run Domains", "Iris Domains", "Type", "Value"],
                              ascending=[True, False, True, True, True], na_position="last", kind="stable")
    return frame[PIVOT_COLUMNS].reset_index(drop=True)


def iris_search_params(search):
    """{"param": "value"} from an Iris Search cell (`param=value`)."""
    param, _, value = str(search).partition("=")
    return {param: value}


def iris_curl(search):
    """The Iris Investigate search as a curl command (credentials from $DT_API_USERNAME / $DT_API_KEY)."""
    query = urlencode(iris_search_params(search))
    return (f'curl -s "{IRIS_API_URL}?{query}&api_username=$DT_API_USERNAME&api_key=$DT_API_KEY"')


def pivot_domains_frame(results):
    """Domains returned by an Iris Investigate pivot search, one row each with the fields that help triage them."""
    rows = []
    for item in results or []:
        if not isinstance(item, dict):
            continue
        risk = (item.get("domain_risk") or {}).get("risk_score")
        ips = [v for ip in item.get("ip") or [] for v, _ in _entries((ip or {}).get("address"))]
        rows.append({
            "Domain": str(item.get("domain", "")).lower(),
            "Risk Score": risk,
            "Created": next((v for v, _ in _entries(item.get("create_date"))), ""),
            "First Seen": next((v for v, _ in _entries(item.get("first_seen"))), ""),
            "Registrar": next((v for v, _ in _entries(item.get("registrar"))), ""),
            "IPs": ", ".join(ips),
            "Active": item.get("active"),
        })
    frame = pd.DataFrame(rows, columns=["Domain", "Risk Score", "Created", "First Seen", "Registrar", "IPs", "Active"])
    return frame.sort_values(["Risk Score", "Created"], ascending=[False, False], na_position="last").reset_index(drop=True)


def top_leads(ranking, limit=5):
    """The strongest pivots to follow next: strong ones (useful ones when there are none), shared in the run first."""
    if ranking is None or ranking.empty:
        return ranking if ranking is not None else pd.DataFrame(columns=PIVOT_COLUMNS)
    for signal in ("Strong", "Useful"):
        leads = ranking[ranking["Signal"] == signal]
        if not leads.empty:
            return leads.head(limit).reset_index(drop=True)
    return ranking.iloc[0:0]


def iris_queries(ranking, domains):
    """Iris searches (`param=value`) of the strong and useful pivots that `domains` have."""
    if ranking is None or ranking.empty or not domains:
        return []
    domains = set(domains)
    rows = ranking[ranking["Signal"].isin(["Strong", "Useful"])
                   & ranking["Shared With"].map(lambda s: bool(domains & {d.strip() for d in str(s).split(",")}))]
    return list(dict.fromkeys(rows["Iris Search"]))

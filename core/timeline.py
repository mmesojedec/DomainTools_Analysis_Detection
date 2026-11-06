"""Per-domain story timeline: registration, DNS changes, certificates, and Domain History on one swimlane chart."""
import pandas as pd

from core.helpers import extract_ip_addresses
from core.network_intel import record_types
from integrations.enrichment import extract_iris_profile

TIMELINE_COLUMNS = ["Lane", "Time", "Event", "Detail"]
LANE_ORDER = ["Registration", "First Seen (Iris)", "DNS: A/AAAA", "DNS: NS", "DNS: MX/TXT", "DNS: Other",
              "Domain History", "Certificate Issued", "Certificate Expiry"]


def _shift(value, timezone):
    parsed = pd.to_datetime(value, errors="coerce", utc=True)
    return parsed.tz_convert(timezone).tz_localize(None) if pd.notna(parsed) else pd.NaT


def _dns_lane(rtype):
    if rtype in ("A", "AAAA", "IP", "A RECORD"):
        return "DNS: A/AAAA"
    if rtype in ("NS", "NAME_SERVER"):
        return "DNS: NS"
    if rtype in ("MX", "TXT", "SPF"):
        return "DNS: MX/TXT"
    return "DNS: Other"


def build_domain_timeline(ds, domain):
    """Events for one domain from the timezone-shifted dataset frames (first observation of each value)."""
    rows = []
    profile = extract_iris_profile(ds.enrichment.get(domain))
    if pd.notna(profile["create_date"]):
        rows.append(("Registration", _shift(profile["create_date"], ds.timezone), "Registered",
                     f"Registrar: {profile['registrar'] or 'N/A'}"))
    if pd.notna(profile["expiration_date"]):
        rows.append(("Registration", _shift(profile["expiration_date"], ds.timezone), "Expires", ""))
    if pd.notna(profile["first_seen"]):
        rows.append(("First Seen (Iris)", _shift(profile["first_seen"], ds.timezone), "First seen by DomainTools", ""))

    pdns = ds.pdns[ds.pdns["Domain"] == domain] if not ds.pdns.empty else pd.DataFrame()
    if not pdns.empty:
        types = record_types(pdns)
        seen = set()
        for rtype, date, value, rrname in sorted(zip(types, pdns["Date"], pdns["Value"].astype(str),
                                                     pdns.get("RRName", pd.Series("", index=pdns.index)).astype(str)),
                                                 key=lambda r: r[1]):
            values = extract_ip_addresses(value) if _dns_lane(rtype) == "DNS: A/AAAA" else [v.strip() for v in value.split("\n") if v.strip()]
            for v in values or [value]:
                key = (rtype, v)
                if key in seen:
                    continue
                seen.add(key)
                rows.append((_dns_lane(rtype), date, f"{rtype} ➔ {v[:60]}", f"RRName: {rrname}"))

    dh = ds.dh[ds.dh["Domain"] == domain] if not ds.dh.empty else pd.DataFrame()
    for _, row in dh.iterrows():
        rows.append(("Domain History", row["Date"], f"{row['Field']} changed", str(row.get("After", ""))[:120]))

    ssl = ds.ssl[ds.ssl["Domain"] == domain] if not ds.ssl.empty else pd.DataFrame()
    if not ssl.empty and "Hash" in ssl.columns:
        for _, cert in ssl.drop_duplicates("Hash").iterrows():
            label = f"{cert.get('Issuer') or 'Unknown CA'} | {str(cert.get('Hash'))[:12]}"
            if pd.notna(cert.get("Not Before Date")):
                rows.append(("Certificate Issued", cert["Not Before Date"], label, f"CN: {cert.get('Common Name', '')}"))
            if pd.notna(cert.get("Not After Date")):
                rows.append(("Certificate Expiry", cert["Not After Date"], label, ""))

    timeline = pd.DataFrame(rows, columns=TIMELINE_COLUMNS)
    timeline["Time"] = pd.to_datetime(timeline["Time"], errors="coerce")
    return timeline.dropna(subset=["Time"]).sort_values("Time").reset_index(drop=True)

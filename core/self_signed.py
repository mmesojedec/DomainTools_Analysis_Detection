"""
Self-signed certificates of a run, one row per certificate, rated by how much they matter: a self-signed
certificate on the live site is a different finding from an expired one on a lab hostname, or from the default
certificate of a C2 framework.
"""
import pandas as pd

from core.cert_utils import (
    PUBLIC_CA_MARKERS,
    cert_alt_names,
    cert_duration_days,
    cert_ip_names,
    cert_is_self_signed,
    is_weak_public_key,
)
from core.helpers import is_ip_address

SEVERITIES = ["Critical", "High", "Medium", "Low"]
LIVE_SOURCE = "Iris Investigate API"   # certificates Iris sees served right now
LONG_VALIDITY_DAYS = 825               # longest lifetime public CAs were ever allowed; hand-made certs often run 10 years

# (marker in the subject / issuer text, severity, what it means)
KNOWN_DEFAULTS = [
    ("cobalt strike", "Critical", "Cobalt Strike's default team server certificate (C2 framework)"),
    ("cobaltstrike", "Critical", "Cobalt Strike's default team server certificate (C2 framework)"),
    ("sliver", "Critical", "Name used by the Sliver C2 framework's generated certificates"),
    ("metasploit", "Critical", "Metasploit's generated certificate (exploitation framework)"),
    ("mythic", "High", "Name used by the Mythic C2 framework"),
    ("internet widgits pty ltd", "High", "OpenSSL's default organization: made by hand in seconds, nothing filled in"),
    ("kubernetes ingress controller fake certificate", "Medium",
     "Default certificate of the Kubernetes NGINX ingress: a host or path with no certificate configured"),
    ("traefik default cert", "Medium", "Traefik's default certificate: a route with no certificate configured"),
    ("plesk", "Medium", "Plesk hosting panel's default certificate"),
    ("cpanel", "Medium", "cPanel hosting panel's default certificate"),
    ("localhost", "Medium", "Issued to localhost: a development or default certificate exposed to the internet"),
    ("fortinet", "Medium", "Fortinet appliance's factory certificate (VPN / firewall management)"),
    ("fortigate", "Medium", "Fortinet appliance's factory certificate (VPN / firewall management)"),
    ("synology", "Medium", "Synology NAS default certificate"),
]


def _text(cert, *keys):
    return " ".join(str(cert.get(key) or "") for key in keys).lower()


def _date(cert, parsed, raw):
    value = cert.get(parsed)
    value = pd.to_datetime(value if pd.notna(value) else cert.get(raw), errors="coerce", utc=True)
    return value.tz_localize(None) if pd.notna(value) else pd.NaT


def _lifetime(cert):
    """Validity in days, also from the raw Not Before / Not After strings when no parsed dates are present."""
    days = cert_duration_days(cert)
    if days is None:
        start, end = _date(cert, "Not Before Date", "Not Before"), _date(cert, "Not After Date", "Not After")
        days = float((end - start).days) if pd.notna(start) and pd.notna(end) else None
    return days


def _names_target(names, domain):
    domain = str(domain).lower().rstrip(".")
    return any(name.lower().rstrip(".") in (domain, f"www.{domain}", f"*.{domain}") for name in names)


def _under(names, domain):
    domain = str(domain).lower().rstrip(".")
    return any(name.lower().rstrip(".").lstrip("*.") == domain or name.lower().rstrip(".").endswith("." + domain)
               for name in names)


def _sha1(group):
    """The certificate's SHA-1 (what Iris Investigate searches by): the SHA1 column, or a 40-character Hash."""
    for column in ("SHA1", "Hash"):
        if column in group.columns:
            values = [str(v).strip().lower() for v in group[column] if len(str(v).strip()) == 40]
            if values:
                return values[0]
    return ""


def assess(cert, domains, sources, now):
    """(severity, reasons, action) for one self-signed certificate."""
    names = [str(cert.get("Common Name") or "").strip()] + cert_alt_names(cert)
    names = [name for name in names if name]
    not_after = _date(cert, "Not After Date", "Not After")
    expired = pd.notna(not_after) and not_after < now
    live = LIVE_SOURCE in sources and not expired
    ip_names = cert_ip_names(cert)
    duration = _lifetime(cert)
    constraints = cert.get("Basic Constraints")
    is_ca = isinstance(constraints, dict) and constraints.get("is_ca") is True
    text = _text(cert, "Common Name", "Subject DN", "Subject Org", "Issuer", "Issuer DN", "Issuer Org")

    found = []   # (severity, reason)
    for marker, severity, meaning in KNOWN_DEFAULTS:
        if marker in text and not any(meaning == reason for _, reason in found):
            found.append((severity, meaning))
    issuer_text = _text(cert, "Issuer", "Issuer Org", "Issuer DN")
    claimed = next((marker for marker in PUBLIC_CA_MARKERS if marker in issuer_text and marker != "cpanel"), None)
    if claimed and any(_under(names, domain) for domain in domains):
        found.append(("High", f"Self-signed, yet its issuer claims to be a public CA ('{claimed}') while naming the "
                              "analyzed domain: real CAs never self-sign a site certificate, so this imitates one "
                              "(interception proxy, phishing kit or test certificate)"))
    if live and any(_names_target(names, domain) for domain in domains):
        found.append(("Critical", "Served on the analyzed domain right now (Iris Investigate): visitors get a browser "
                                  "warning, or the site is not what it claims to be"))
    elif live:
        found.append(("High", "Served right now (Iris Investigate) on a name other than the analyzed domain"))
    if ip_names and not all(is_ip_address(domain) for domain in domains):
        found.append(("High", f"Names a bare IP address ({', '.join(ip_names[:3])}): typical of C2 servers that agents "
                              "reach without DNS"))
    if is_weak_public_key(cert.get("Public Key Bits"), cert.get("Public Key Algo")):
        found.append(("High", f"Weak key: {cert.get('Public Key Algo') or ''} {cert.get('Public Key Bits')} bits"))
    if is_ca:
        found.append(("Medium", "Marked as a CA (basic constraints): a private root that can sign other certificates; "
                                "only trusted where someone installed it"))
    if duration is not None and duration > LONG_VALIDITY_DAYS:
        found.append(("Medium", f"Valid for {duration / 365:.0f} year(s) ({duration:,.0f} days): far beyond what any "
                                "public CA issues, typical of a certificate made by hand"))
    if not found:
        found.append(("Medium", "Self-signed: no public CA vouches for it, so browsers do not trust it"))
    severity = min((severity for severity, _ in found), key=SEVERITIES.index)
    if expired:
        found.append(("Low", f"Expired on {not_after:%Y-%m-%d}: historical, unless it is still served"))
        if severity != "Critical":   # an expired certificate matters one step less; a C2 default stays Critical
            severity = SEVERITIES[SEVERITIES.index(severity) + 1]

    action = {
        "Critical": "Investigate now: check what the host serves, and treat it as possible C2 or impersonation until "
                    "explained.",
        "High": "Check the host and who runs it; pivot on the certificate hash and public key to find related servers.",
        "Medium": "Usually a misconfiguration or an internal service exposed to the internet; confirm it is expected.",
        "Low": "Historical: keep for context and pivots.",
    }[severity]
    return severity, [reason for _, reason in found], action


def self_signed_certificates(ssl, domains, now=None):
    """One row per self-signed certificate (by hash) of `ssl`, most severe first."""
    columns = ["Severity", "Common Name", "Domains", "Status", "Not Before", "Not After", "Validity (days)", "Key",
               "Signature", "Subject", "Issuer", "Names", "Sources", "Last Seen", "Hash", "SHA-1", "Reasons", "Action"]
    if ssl is None or ssl.empty:
        return pd.DataFrame(columns=columns)
    now = pd.Timestamp.now(tz="UTC").tz_localize(None) if now is None else now
    certs = ssl[[cert_is_self_signed(cert) for _, cert in ssl.iterrows()]]
    if certs.empty:
        return pd.DataFrame(columns=columns)
    key = certs["Hash"].astype(str).where(certs["Hash"].astype(str).str.strip() != "", certs["Common Name"].astype(str)) \
        if "Hash" in certs.columns else certs["Common Name"].astype(str)
    rows = []
    for _, group in certs.groupby(key, sort=False):
        # the richest row (Cert API has keys and DNs) describes the certificate; every row adds its domain and source
        cert = group.loc[group.notna().sum(axis=1).idxmax()]
        seen_in = sorted(set(group["Domain"].astype(str)))
        sources = sorted(set(group["Source"].astype(str))) if "Source" in group.columns else []
        last_seen = pd.to_datetime(group["Date"], errors="coerce").max() if "Date" in group.columns else pd.NaT
        severity, reasons, action = assess(cert, seen_in, sources, now)
        not_before, not_after = _date(cert, "Not Before Date", "Not Before"), _date(cert, "Not After Date", "Not After")
        bits = pd.to_numeric(cert.get("Public Key Bits"), errors="coerce")
        rows.append({
            "Severity": severity,
            "Common Name": str(cert.get("Common Name") or "") or "(none)",
            "Domains": ", ".join(seen_in),
            "Status": "Expired" if pd.notna(not_after) and not_after < now else
                      ("Not yet valid" if pd.notna(not_before) and not_before > now else "Valid"),
            "Not Before": not_before,
            "Not After": not_after,
            "Validity (days)": _lifetime(cert),
            "Key": f"{cert.get('Public Key Algo') or ''} {int(bits)} bits".strip() if pd.notna(bits) else "",
            "Signature": str(cert.get("Signature Algo") or ""),
            "Subject": str(cert.get("Subject DN") or cert.get("Common Name") or ""),
            "Issuer": str(cert.get("Issuer DN") or cert.get("Issuer") or ""),
            "Names": ", ".join(cert_alt_names(cert)),
            "Sources": ", ".join(sources),
            "Last Seen": last_seen,
            "Hash": str(cert.get("Hash") or ""),
            "SHA-1": _sha1(group),
            "Reasons": reasons,
            "Action": action,
        })
    table = pd.DataFrame(rows, columns=columns)
    order = table["Severity"].map(SEVERITIES.index)
    return table.assign(_order=order).sort_values(["_order", "Last Seen"], ascending=[True, False]) \
        .drop(columns="_order").reset_index(drop=True)

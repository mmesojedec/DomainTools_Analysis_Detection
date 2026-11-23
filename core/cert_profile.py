"""
Certificate profile: one certificate of the run, field by field. The X.509 fields the Certificate API returns are
grouped as in the certificate itself (subject, issuer, validity, public key, extensions, subject alternative names,
signature and fingerprints), checked for what stands out (flags), drawn by core.cert_anatomy, and set next to the run's other
certificates (related certificates, where it was seen, the alerts citing it). The field breakdown does the same across
every certificate: per field how often it is filled, its common values and its rare ones.

Pure: no API call, no Streamlit.
"""
import re
from datetime import datetime

import pandas as pd

from core import ja4x
from core.cert_utils import is_weak_public_key, publicly_trusted
from core.intel_data import SEVERITY_RANK

# (section, [(label, column)]) in the order of the certificate's own structure
FIELD_GROUPS = [
    ("Subject", [("Common name", "Common Name"), ("Organization", "Subject Org"), ("Country", "Subject Country"),
                 ("State / province", "Subject State/Province"), ("Distinguished name", "Subject DN")]),
    ("Issuer", [("Common name", "Issuer"), ("Organization", "Issuer Org"), ("Unit", "Issuer OU"),
                ("Country", "Issuer Country"), ("Distinguished name", "Issuer DN")]),
    ("Validity", [("Not before", "Not Before"), ("Not after", "Not After"), ("Days", "Duration"),
                  ("Validation level", "Validation Level")]),
    ("Public key", [("Algorithm", "Public Key Algo"), ("Bits", "Public Key Bits"), ("SPKI SHA-256", "Public Key SHA256")]),
    ("Extensions", [("Key usage", "Key Usage"), ("Extended key usage", "Extended Key Usage"),
                    ("EKU OIDs", "Extended Key Usage OIDs"), ("Basic constraints", "Basic Constraints"),
                    ("Certificate policy", "Certificate Policy"), ("Authority key ID", "Authority Key ID"),
                    ("Subject key ID", "Subject Key ID"), ("Extension OIDs", "Extension OIDs"),
                    ("Embedded SCTs", "Has Embedded SCTs"), ("SCT logs", "Signed Certificate Timestamps"),
                    ("Precertificate", "Is Precertificate")]),
    ("Subject alternative names", [("DNS names", "SAN DNS"), ("IPv4", "SAN IPv4"), ("IPv6", "SAN IPv6"),
                                   ("Count", "SAN Count"), ("Wildcard", "Has Wildcard SAN")]),
    ("Signature and fingerprints", [("Signature algorithm", "Signature Algo"), ("Serial number", "Serial Number"),
                                    ("SHA-256", "Hash"), ("SHA-1", "SHA1"), ("MD5", "MD5"), ("JA4X", "JA4X"),
                                    ("Self-signed", "Is Self Signed")]),
]
FIELDS = [(section, label, column) for section, fields in FIELD_GROUPS for label, column in fields]
CA_BROWSER_MAX_DAYS = 398       # CA/Browser Forum limit for publicly trusted TLS certificates
SHORT_DAYS = 7                  # shorter: a throwaway or automation-made certificate
SAN_SPRAWL = 50                 # more SANs: a shared (CDN / hosting) or bulk certificate
EXPIRY_DAYS = 14
DATETIME_TEXT = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}")
RARE_JA4X = 5                  # a JA4X shared by at most this many other certificates relates them
FLAG_COLUMNS = ["Severity", "Field", "Finding"]
RELATED_COLUMNS = ["Relation", "Common Name", "Issuer", "Not Before", "Not After", "Domains", "Hash"]
SOURCE_PRIORITY = {"DomainTools Cert API": 1, "CertsQL search": 1, "Iris Investigate API": 2, "Domain History": 3}
SERVED_SOURCE = "Iris Investigate API"     # Iris lists the certificates the domain's website serves now
ORDERS = ["Most relevant", "Newest issued", "Expiring soonest", "Most severe flag"]
ROLES = ["Apex", "Wildcard", "Subdomain", "Other"]           # how a certificate covers the analyzed domain
STATUSES = ["Valid", "Not valid yet", "Expired", "Unknown"]
BREAKDOWN_COLUMNS = ["Section", "Field", "Filled", "Filled %", "Distinct", "Most common", "Rare values"]


def _empty(value):
    if value is None:
        return True
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) == 0
    try:
        if pd.isna(value):
            return True
    except (TypeError, ValueError):
        pass
    return str(value).strip().lower() in ("", "nan", "nat", "none", "[]")


def _values(value):
    """The field's values as strings (a list stays a list, one value becomes one)."""
    if _empty(value):
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if not _empty(v)]
    if isinstance(value, (pd.Timestamp, datetime)) or hasattr(value, "dtype") and "datetime" in str(value.dtype):
        return [when(value).strftime("%Y-%m-%d %H:%M")]
    if isinstance(value, str) and DATETIME_TEXT.match(value.strip()):
        return [value.strip()[:16].replace("T", " ")]
    if isinstance(value, float) and value.is_integer():
        return [str(int(value))]
    return [str(value).strip()]


def text(value, limit=None):
    """A field as display text (lists joined)."""
    joined = ", ".join(_values(value))
    return joined if not limit or len(joined) <= limit else joined[:limit - 1] + "…"


def when(value):
    """
    A certificate date as a naive UTC timestamp, NaT when missing. The sources disagree: the Certificate API gives ISO
    text, Iris Investigate and Domain History give YYYYMMDD (as text or a number), and the run's dates may be
    timezone-aware; a bare number is never read as nanoseconds since 1970.
    """
    if _empty(value):
        return pd.NaT
    if isinstance(value, (int, float)) and not isinstance(value, bool) or isinstance(value, str) and value.strip().isdigit():
        digits = str(int(float(value))) if not isinstance(value, str) else value.strip()
        if len(digits) == 8:
            stamp = pd.to_datetime(digits, format="%Y%m%d", errors="coerce", utc=True)
        elif len(digits) in (10, 13):                                       # epoch seconds / milliseconds
            stamp = pd.to_datetime(int(digits), unit="s" if len(digits) == 10 else "ms", errors="coerce", utc=True)
        else:
            return pd.NaT
    else:
        stamp = pd.to_datetime(value, errors="coerce", utc=True)
    return stamp.tz_convert(None) if pd.notna(stamp) else pd.NaT


def _bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def certificates(ssl):
    """
    One row per certificate (by Hash) of the run's certificate rows, newest first: the richest source's row (Certificate
    API, then Iris Investigate, then Domain History), the analyzed Domains and the Sources that list it. Not Before and
    Not After become timestamps, whatever form the source gave them in.
    """
    if ssl is None or ssl.empty or "Hash" not in ssl:
        return pd.DataFrame()
    frame = ssl[ssl["Hash"].astype(str).str.strip() != ""]
    if "Source" in frame:
        frame = frame.assign(_s=frame["Source"].map(SOURCE_PRIORITY).fillna(9)).sort_values("_s", kind="stable") \
            .drop(columns="_s")
    domains = frame.groupby("Hash")["Domain"].agg(lambda s: sorted(set(map(str, s)))) if "Domain" in frame else None
    sources = frame.groupby("Hash")["Source"].agg(lambda s: sorted(set(map(str, s)))) if "Source" in frame else None
    unique = frame.drop_duplicates("Hash").set_index("Hash", drop=False)
    if domains is not None:
        unique["Domains"] = domains
    if sources is not None:
        unique["Sources"] = sources
    for column in ("Not Before", "Not After"):
        if column in unique:
            parsed = unique[column].map(when)
            fallback = f"{column} Date"
            if fallback in unique:
                parsed = parsed.fillna(unique[fallback].map(when))
            unique[column] = pd.to_datetime(parsed)
    if "Not Before" in unique:
        unique = unique.sort_values("Not Before", ascending=False, na_position="last", kind="stable")
    return unique.reset_index(drop=True)


def label(cert):
    """A short name for a certificate in pickers: [role · status · served now ·] CN · issuer · valid from · hash."""
    start = when(cert.get("Not Before"))
    tags = [cert.get("Role") if cert.get("Role") not in (None, "", "Other") else "",
            cert.get("Status") if cert.get("Status") not in (None, "", "Unknown") else "",
            "served now" if _bool(cert.get("Served")) else ""]
    tags = [t for t in tags if t]
    name = " · ".join(part for part in (text(cert.get("Common Name")) or "(no CN)", text(cert.get("Issuer")),
                                        f"{start:%Y-%m-%d}" if pd.notna(start) else "", str(cert.get("Hash"))[:12]) if part)
    return f"[{' · '.join(tags)}] {name}" if tags else name


def names(cert):
    """The names the certificate is for: its common name and DNS SANs, lower case."""
    found = [text(cert.get("Common Name"))] + (_values(cert.get("SAN DNS")) or _values(cert.get("Alt Names List")))
    return {n.strip().lower().rstrip(".") for n in found if n and n.strip()}


def role(cert, domains):
    """How the certificate covers the analyzed domain(s): Apex (names the domain itself), Wildcard (*.domain only),
    Subdomain (only names under it) or Other."""
    covered = names(cert)
    best = len(ROLES) - 1
    for domain in (d.lower().rstrip(".") for d in domains if d):
        if domain in covered:
            return ROLES[0]
        if f"*.{domain}" in covered:
            best = min(best, 1)
        elif any(n.endswith("." + domain) for n in covered):
            best = min(best, 2)
    return ROLES[best]


def status(cert, now=None):
    """Valid, Not valid yet, Expired or Unknown (no dates), at `now`."""
    now = now or pd.Timestamp.now(tz="UTC").tz_localize(None)
    start, end = when(cert.get("Not Before")), when(cert.get("Not After"))
    if pd.isna(start) and pd.isna(end):
        return STATUSES[3]
    if pd.notna(end) and end < now:
        return STATUSES[2]
    if pd.notna(start) and start > now:
        return STATUSES[1]
    return STATUSES[0]


def ranked(certs, domain=None, order=ORDERS[0], now=None):
    """
    The certificates with Role, Status, Served (on the domain's website now, per Iris Investigate) and Worst (most
    severe flag), in `order`:
    - Most relevant: valid before not-yet-valid before expired; then the certificate for the domain itself (Apex), a
      wildcard over it, one for its subdomains, any other; then served now; then the newest issued. The first is the
      domain's certificate to look at first.
    - Newest issued, Expiring soonest (still valid first, then expired most recently), Most severe flag (then newest).
    `domain`: the analyzed domain the roles are relative to; None: each certificate's own Domains.
    """
    if certs is None or certs.empty:
        return certs
    now = now or pd.Timestamp.now(tz="UTC").tz_localize(None)
    rows = certs.to_dict("records")
    frame = certs.assign(
        Role=[role(r, [domain] if domain else _values(r.get("Domains"))) for r in rows],
        Status=[status(r, now) for r in rows],
        Served=[SERVED_SOURCE in _values(r.get("Sources")) or text(r.get("Source")) == SERVED_SOURCE for r in rows],
        Worst=[next(iter(flags(r, now)["Severity"]), "None") for r in rows])
    start = frame["Not Before"].map(when) if "Not Before" in frame else pd.Series(pd.NaT, index=frame.index)
    end = frame["Not After"].map(when) if "Not After" in frame else pd.Series(pd.NaT, index=frame.index)
    newest = -start.map(lambda t: t.value if pd.notna(t) else -2 ** 62)
    if order == ORDERS[1]:
        keys = [newest]
    elif order == ORDERS[2]:
        left = (end - now).map(lambda d: d.total_seconds() if pd.notna(d) else float("inf"))
        keys = [left.map(lambda v: v < 0), left.map(abs), newest]       # valid soonest-ending, then expired latest
    elif order == ORDERS[3]:
        keys = [frame["Worst"].map(SEVERITY_RANK).fillna(9), newest]
    else:
        keys = [frame["Status"].map(STATUSES.index), frame["Role"].map(ROLES.index), ~frame["Served"], newest]
    columns = [f"_k{i}" for i in range(len(keys))]
    return frame.assign(**dict(zip(columns, keys))).sort_values(columns, kind="stable").drop(columns=columns) \
        .reset_index(drop=True)


def most_relevant(certs, domain=None, now=None):
    """The Hash of the domain's most relevant certificate (ranked's first), None when there is none."""
    frame = ranked(certs, domain, now=now)
    return None if frame is None or frame.empty else str(frame["Hash"].iloc[0])


def flags(cert, now=None, related=None):
    """
    FLAG_COLUMNS: what stands out in the certificate, most severe first. Field is the column it concerns (the anatomy
    shows the flag under it). `related`: related_certificates, for a key reused by other certificates.
    """
    now = now or pd.Timestamp.now(tz="UTC").tz_localize(None)
    found = []

    def add(severity, column, finding):
        found.append({"Severity": severity, "Field": column, "Finding": finding})
    value = ja4x.normalize(cert.get("JA4X"))
    known = ja4x.known_ja4x(value) if value else None
    if known:
        add("Critical" if known[1] == "c2" else "Medium", "JA4X",
            f"JA4X matches {known[0]} ({ja4x.KIND_LABELS.get(known[1], known[1])})")
    elif value and ja4x.generated_layout(value):
        add("High", "JA4X", "JA4X shows a code-generated layout (empty issuer): no certificate authority issues this")
    if _bool(cert.get("Is Self Signed")):
        add("High", "Is Self Signed", "Self-signed: no certificate authority vouches for it")
    algo = text(cert.get("Public Key Algo"))
    if is_weak_public_key(cert.get("Public Key Bits"), algo):
        add("High", "Public Key Bits", f"Weak key: {algo} {text(cert.get('Public Key Bits'))} bits")
    signature = text(cert.get("Signature Algo")).lower()
    if re.search(r"md5|sha1(?!\d)", signature):
        add("High", "Signature Algo", f"Deprecated signature algorithm {text(cert.get('Signature Algo'))}")
    constraints = text(cert.get("Basic Constraints")).lower()
    raw = cert.get("Basic Constraints")
    is_ca = raw.get("is_ca") if isinstance(raw, dict) else None          # the Certificate API: {'is_ca': ...}
    if is_ca is True or "ca:true" in constraints.replace(" ", "") or "'is_ca': true" in constraints \
            or constraints in ("true", "ca"):
        add("High", "Basic Constraints", "Marked as a CA certificate (basic constraints CA:TRUE) while naming hosts")
    start, end = when(cert.get("Not Before")), when(cert.get("Not After"))
    if pd.notna(end) and end < now:
        add("Medium", "Not After", f"Expired on {end:%Y-%m-%d}")
    elif pd.notna(end) and end < now + pd.Timedelta(days=EXPIRY_DAYS):
        add("Low", "Not After", f"Expires on {end:%Y-%m-%d}, within {EXPIRY_DAYS} days")
    if pd.notna(start) and start > now:
        add("Medium", "Not Before", f"Not valid yet: starts on {start:%Y-%m-%d}")
    days = (end - start).days if pd.notna(start) and pd.notna(end) else pd.to_numeric(cert.get("Duration"),
                                                                                       errors="coerce")
    trusted = publicly_trusted(cert)
    if pd.notna(days) and days > CA_BROWSER_MAX_DAYS and trusted:
        add("Medium", "Duration", f"Valid {int(days)} days, longer than the {CA_BROWSER_MAX_DAYS}-day limit for "
                                  "publicly trusted certificates")
    elif pd.notna(days) and days > CA_BROWSER_MAX_DAYS * 2 and not trusted:
        add("Low", "Duration", f"Valid {int(days)} days (private or self-made certificates often run for years)")
    elif pd.notna(days) and 0 <= days < SHORT_DAYS:
        add("Low", "Duration", f"Valid only {int(days)} day(s): throwaway or automation-made")
    if trusted and "Has Embedded SCTs" in cert and not _empty(cert.get("Has Embedded SCTs")) \
            and not _bool(cert.get("Has Embedded SCTs")) and not _bool(cert.get("Is Precertificate")):
        add("Medium", "Has Embedded SCTs", "Publicly trusted but without embedded SCTs (not logged in CT before issuance)")
    eku = text(cert.get("Extended Key Usage")).lower()
    if "code signing" in eku or "codesigning" in eku or "any extended key usage" in eku:
        add("Medium", "Extended Key Usage", f"Unusual extended key usage for a web certificate: {text(cert.get('Extended Key Usage'))}")
    sans = _values(cert.get("SAN DNS")) or _values(cert.get("Alt Names List"))
    if any(s.startswith("*.") for s in sans) or _bool(cert.get("Has Wildcard SAN")):
        add("Low", "SAN DNS", "Wildcard SAN: covers every name at that level")
    count = pd.to_numeric(cert.get("SAN Count"), errors="coerce")
    count = count if pd.notna(count) else len(sans)
    if count > SAN_SPRAWL:
        add("Low", "SAN Count", f"{int(count)} SANs: a shared (CDN / hosting) or bulk certificate")
    if _values(cert.get("SAN IPv4")) or _values(cert.get("SAN IPv6")):
        add("Low", "SAN IPv4", "Names IP addresses in its SANs")
    if related is not None and not related.empty:
        reused = related[related["Relation"] == "Same public key"]
        if len(reused):
            add("Medium" if reused["Issuer"].nunique() > 1 or len(reused) > 3 else "Low", "Public Key SHA256",
                f"Public key reused by {len(reused)} other certificate(s)")
    frame = pd.DataFrame(found, columns=FLAG_COLUMNS)
    if frame.empty:
        return frame
    return frame.assign(_r=frame["Severity"].map(SEVERITY_RANK).fillna(9)).sort_values("_r", kind="stable") \
        .drop(columns="_r").reset_index(drop=True)


def related_certificates(cert, certs):
    """RELATED_COLUMNS: the run's other certificates with the same public key, JA4X, SAN set or common name."""
    if certs is None or certs.empty:
        return pd.DataFrame(columns=RELATED_COLUMNS)
    others = certs[certs["Hash"] != cert.get("Hash")]
    rows = []

    def add(relation, mask):
        for row in others[mask].to_dict("records"):
            rows.append({"Relation": relation, "Hash": row["Hash"], "Common Name": text(row.get("Common Name")),
                         "Issuer": text(row.get("Issuer")), "Not Before": when(row.get("Not Before")),
                         "Not After": when(row.get("Not After")), "Domains": text(row.get("Domains"))})
    key = text(cert.get("Public Key SHA256"))
    if key and "Public Key SHA256" in others:
        add("Same public key", others["Public Key SHA256"].map(text) == key)
    value = ja4x.normalize(cert.get("JA4X"))
    if value and "JA4X" in others:
        same = others["JA4X"].map(ja4x.normalize) == value
        # a CA's usual layout is shared by all its certificates: only a notable or rare JA4X relates them
        rare = 0 < same.sum() <= RARE_JA4X and same.sum() < len(certs) / 2
        if ja4x.known_ja4x(value) or ja4x.generated_layout(value) or rare:
            add("Same JA4X", same)
    sans = frozenset(_values(cert.get("SAN DNS")) or _values(cert.get("Alt Names List")))
    column = "SAN DNS" if "SAN DNS" in others else "Alt Names List" if "Alt Names List" in others else None
    if sans and column:
        add("Same SAN set", others[column].map(lambda v: frozenset(_values(v)) == sans))
    cn = text(cert.get("Common Name"))
    if cn and "Common Name" in others:
        add("Same common name", others["Common Name"].map(text) == cn)
    frame = pd.DataFrame(rows, columns=RELATED_COLUMNS)
    for column in ("Not Before", "Not After"):
        frame[column] = pd.to_datetime(frame[column])
    return frame.drop_duplicates(["Relation", "Hash"]).reset_index(drop=True)


def where_seen(digest, ctl=None, observations=None, hostnames=None):
    """{"CT logs", "Observations", "Hostnames"}: the run's certificate event rows of this certificate."""
    found = {}
    for name, frame in (("CT logs", ctl), ("Observations", observations), ("Hostnames", hostnames)):
        if frame is None or frame.empty:
            continue
        column = next((c for c in ("Hash", "SHA256", "Sha256", "Certificate") if c in frame.columns), None)
        if column:
            rows = frame[frame[column].astype(str).str.lower() == str(digest).lower()]
            if not rows.empty:
                found[name] = rows.reset_index(drop=True)
    return found


def citing_alerts(digest, alerts):
    """The alerts whose triggering IOCs, threat logic or evidence name the certificate (full or 16-character hash)."""
    if alerts is None or alerts.empty or not digest:
        return pd.DataFrame()
    needles = {str(digest).lower(), str(digest).lower()[:16]}

    def cites(row):
        blob = " ".join(str(row.get(c) or "") for c in ("Triggering IOCs", "Threat Logic", "Evidence")).lower()
        return any(n in blob for n in needles)
    return alerts[[cites(row) for row in alerts.to_dict("records")]].reset_index(drop=True)


def field_rows(cert):
    """Section, Field, Value (text) for every field, empty ones included."""
    return pd.DataFrame([{"Section": section, "Field": label_, "Column": column, "Value": text(cert.get(column))}
                         for section, label_, column in FIELDS])


def field_breakdown(certs, rare_limit=5):
    """BREAKDOWN_COLUMNS: per field across the certificates, how often it is filled, its distinct values, the most
    common one and values seen on a single certificate (the outliers worth a look)."""
    if certs is None or certs.empty:
        return pd.DataFrame(columns=BREAKDOWN_COLUMNS)
    total = len(certs)
    rows = []
    for section, label_, column in FIELDS:
        if column not in certs or column in ("Hash", "SHA1", "MD5", "Serial Number"):
            continue          # unique per certificate by design: nothing to compare
        cells = certs[column].map(_values)
        filled = int(cells.map(bool).sum())
        counts = pd.Series([v for values in cells for v in dict.fromkeys(values)], dtype=object).value_counts()
        rare = list(counts[counts == 1].index[:rare_limit]) if total > 2 and len(counts) > 1 else []
        rows.append({"Section": section, "Field": label_, "Filled": filled,
                     "Filled %": round(100 * filled / total) if total else 0, "Distinct": int(len(counts)),
                     "Most common": f"{counts.index[0]} ({counts.iloc[0]})" if len(counts) else "",
                     "Rare values": ", ".join(map(str, rare))})
    return pd.DataFrame(rows, columns=BREAKDOWN_COLUMNS)


def riskiest(certs, now=None, limit=None):
    """The certificates ordered by their most severe flag (then newest), for the report."""
    if certs is None or certs.empty:
        return certs
    ranks = [min((SEVERITY_RANK.get(s, 9) for s in flags(row, now)["Severity"]), default=9)
             for row in certs.to_dict("records")]
    ordered = certs.assign(_r=ranks).sort_values("_r", kind="stable").drop(columns="_r")
    return ordered.head(limit) if limit else ordered

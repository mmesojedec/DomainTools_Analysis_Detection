"""
Certificate profile: one certificate of the run, field by field. The X.509 fields the Certificate API returns are
grouped as in the certificate itself (subject, issuer, validity, public key, extensions, subject alternative names,
signature and fingerprints), checked for what stands out (flags), drawn as a field map, and set next to the run's other
certificates (related certificates, where it was seen, the alerts citing it). The field breakdown does the same across
every certificate: per field how often it is filled, its common values and its rare ones.

Pure: no API call, no Streamlit.
"""
import re
from datetime import datetime

import pandas as pd

from core import ja4x
from core.cert_utils import is_weak_public_key, publicly_trusted
from core.intel_data import SEVERITY_COLORS, SEVERITY_RANK

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
    """A certificate date as a naive UTC timestamp (the run's dates may be timezone-aware), NaT when missing."""
    stamp = pd.to_datetime(value, errors="coerce", utc=True)
    return stamp.tz_convert(None) if pd.notna(stamp) else pd.NaT


def _bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def certificates(ssl):
    """One row per certificate (by Hash) of the run's certificate rows, with the analyzed Domains and Sources that list
    it; newest first."""
    if ssl is None or ssl.empty or "Hash" not in ssl:
        return pd.DataFrame()
    frame = ssl[ssl["Hash"].astype(str).str.strip() != ""]
    domains = frame.groupby("Hash")["Domain"].agg(lambda s: sorted(set(map(str, s)))) if "Domain" in frame else None
    sources = frame.groupby("Hash")["Source"].agg(lambda s: sorted(set(map(str, s)))) if "Source" in frame else None
    unique = frame.drop_duplicates("Hash").set_index("Hash", drop=False)
    if domains is not None:
        unique["Domains"] = domains
    if sources is not None:
        unique["Sources"] = sources
    order = unique["Not Before"].map(when) if "Not Before" in unique else None
    if order is not None:
        unique = unique.assign(_o=order).sort_values("_o", ascending=False, na_position="last").drop(columns="_o")
    return unique.reset_index(drop=True)


def label(cert):
    """A short name for a certificate in pickers: CN · issuer · valid from · hash."""
    start = when(cert.get("Not Before"))
    return " · ".join(part for part in (text(cert.get("Common Name")) or "(no CN)", text(cert.get("Issuer")),
                                        f"{start:%Y-%m-%d}" if pd.notna(start) else "", str(cert.get("Hash"))[:12]) if part)


def flags(cert, now=None, related=None):
    """
    FLAG_COLUMNS: what stands out in the certificate, most severe first. Field is the column it concerns (the field map
    colours it). `related`: related_certificates, for a key reused by other certificates.
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
    if "ca:true" in constraints.replace(" ", "") or constraints in ("true", "ca"):
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
                         "Issuer": text(row.get("Issuer")), "Not Before": row.get("Not Before"),
                         "Not After": row.get("Not After"), "Domains": text(row.get("Domains"))})
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


def _html(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            .replace("]", "&#93;").replace("[", "&#91;"))


def _worst_of(severities):
    ranked = [s for s in severities if s]
    return min(ranked, key=lambda s: SEVERITY_RANK.get(s, 9)) if ranked else None


SECTION_COLOUR, FIELD_COLOUR, EMPTY_COLOUR = "#0f766e", "#475569", "#cbd5e1"


def field_map(cert, found=None, width=44):
    """
    Graphviz DOT of the certificate's structure: the certificate → one table per section (subject, issuer, validity,
    key, extensions, SANs, signature) with a row per field and its value. A field a flag concerns takes the flag's
    colour (so does its section's title); an empty field is grey ("—"), so missing fields show too.
    """
    by_column = {}
    if found is not None and not found.empty:
        for row in found.to_dict("records"):
            by_column.setdefault(row["Field"], row["Severity"])
    by_column.setdefault("Duration", by_column.get("Not After"))
    title = text(cert.get("Common Name")) or str(cert.get("Hash"))[:16]
    lines = ['digraph { rankdir=LR; bgcolor="transparent"; nodesep=0.15; ranksep=0.6;',
             'node [shape=plaintext, fontname="Helvetica", fontsize=10]; edge [color="#94a3b8", arrowsize=0.5];',
             f'"root" [shape=box, style="rounded,filled", fillcolor="#4f46e5", fontcolor="white", fontsize=12, '
             f'color="#4f46e5", label="{_html(title)}\\ncertificate"];']
    for number, (section, fields) in enumerate(FIELD_GROUPS):
        worst = _worst_of(by_column.get(c) for _, c in fields)
        head = SEVERITY_COLORS.get(worst, SECTION_COLOUR) if worst else SECTION_COLOUR
        rows = [f'<TR><TD COLSPAN="2" BGCOLOR="{head}" ALIGN="LEFT"><FONT COLOR="white"><B>{_html(section)}</B>'
                "</FONT></TD></TR>"]
        for label_, column in fields:
            value = text(cert.get(column), width)
            severity = by_column.get(column)
            fill = SEVERITY_COLORS.get(severity, "#ef4444") if severity else FIELD_COLOUR if value else EMPTY_COLOUR
            font = "white" if value or severity else "#475569"
            rows.append(f'<TR><TD BGCOLOR="{fill}" ALIGN="LEFT"><FONT COLOR="{font}">{_html(label_)}</FONT></TD>'
                        f'<TD BGCOLOR="{fill}" ALIGN="LEFT"><FONT COLOR="{font}">{_html(value or "—")}</FONT></TD>'
                        "</TR>")
        table = ('<TABLE BORDER="0" CELLBORDER="1" CELLSPACING="0" CELLPADDING="4" COLOR="#334155">'
                 + "".join(rows) + "</TABLE>")
        lines.append(f'"s{number}" [label=<{table}>]; "root" -> "s{number}";')
    lines.append("}")
    return "\n".join(lines)


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

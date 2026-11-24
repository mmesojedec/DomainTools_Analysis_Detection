"""
Certificate shape: how a certificate was made, leaving out who it is for. Eleven traits (issuer, key, validity band,
extension layout, extended key usage, policy, serial length, SAN profile, self-signed, signature algorithm, subject
layout), each normalised so routine noise does not split certificates that belong together:
- the CT parts of the extension list (the precertificate's poison, the final certificate's SCT list) count as one CT
  token, so a precertificate and its final certificate get the same shape;
- the serial number counts in bytes once the leading zeros are gone (DER adds a 00 byte to a serial whose high bit is
  set: ZeroSSL's 32 and 34 hex characters are both 16 bytes);
- validity counts in bands (Let's Encrypt's 89 and 90 days land together, its 6-day certificates do not).

Certificates with every shared trait equal are one family (the same issuing pipeline, or the same tooling across
domains); near shapes score 0-100 by weighted trait agreement and name the traits that differ. Only traits both
certificates have are compared, and at least MIN_TRAITS of them, so sparse Domain History rows don't all "match".

Pure: no API call, no Streamlit.
"""
import ast
import hashlib
import re

import pandas as pd

from core.cert_profile import _bool, _empty, _values, text, when
from core.certsql import HEADER

CT_OIDS = {"1.3.6.1.4.1.11129.2.4.2", "1.3.6.1.4.1.11129.2.4.3"}       # SCT list, CT poison
CT_TOKEN = "CT"
API_SOURCES = {"DomainTools Cert API", "CertsQL search"}                # full records, dates to the second
VALIDITY_BANDS = ((7, "≤7 d"), (47, "8–47 d"), (100, "48–100 d"), (200, "101–200 d"), (398, "201–398 d"))
VALIDITY_RANGES = {"≤7 d": (0, 7), "8–47 d": (8, 47), "48–100 d": (48, 100), "101–200 d": (101, 200),
                   "201–398 d": (201, 398), ">398 d": (399, 100000)}
SAN_BANDS = ((1, "1 name"), (2, "2 names"), (10, "3–10 names"), (50, "11–50 names"))
SAN_RANGES = {"1 name": (1, 1), "2 names": (2, 2), "3–10 names": (3, 10), "11–50 names": (11, 50),
              ">50 names": (51, 100000)}
# (key, label, weight in the near-shape score, part of the family key). The subject layout is left out of the family
# key: the Certificate API leaves the subject of some certificates empty, which would split one pipeline in two.
TRAITS = (("issuer", "Issuer", 3, True), ("key", "Key", 2, True), ("validity", "Validity", 2, True),
          ("extensions", "Extension layout", 3, True), ("eku", "Extended key usage", 1, True),
          ("policy", "Policy", 1, True), ("serial", "Serial length", 1, True), ("sans", "SAN profile", 1, True),
          ("self_signed", "Self-signed", 1, True), ("signature", "Signature", 1, True),
          ("subject", "Subject layout", 1, False))
TRAIT_LABELS = {key: label for key, label, _, _ in TRAITS}
FAMILY_TRAITS = [key for key, _, _, family in TRAITS if family]
MIN_TRAITS = 5                 # fewer known traits: too little data to give a shape or compare
NEAR = 85                      # near-shape score from which two certificates count as near
FAMILY_COLUMNS = ["Family", "Shape", "Certificates", "Domains", "Domain count", "Issuer", "First issued",
                  "Last issued", "Anomalies", "Hashes"]
SHAPE_RELATIONS = ("Same shape", "Near shape")
OID_SHORT = {"2.23.140.1.2.1": "DV", "2.23.140.1.2.2": "OV", "2.23.140.1.2.3": "IV", "2.23.140.1.1": "EV",
             "1.3.6.1.5.5.7.3.1": "server auth", "1.3.6.1.5.5.7.3.2": "client auth", "1.3.6.1.5.5.7.3.3": "code signing",
             "1.3.6.1.5.5.7.3.4": "email", "1.3.6.1.5.5.7.3.8": "time stamping", "2.5.29.37.0": "any"}


def _parsed(value):
    if isinstance(value, str) and value.strip()[:1] in "{[":
        try:
            return ast.literal_eval(value.strip())
        except (ValueError, SyntaxError):
            return value
    return value


def _list(value):
    """A list field (also when it came back as its Python text) as a list of strings."""
    value = _parsed(value)
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if not _empty(v)]
    return [v.strip() for v in str(value).split(",") if v.strip()] if not _empty(value) else []


def policies(cert):
    """The certificate's policy OIDs."""
    value = _parsed(cert.get("Certificate Policy"))
    items = value if isinstance(value, (list, tuple)) else [value] if not _empty(value) else []
    found = []
    for item in items:
        item = _parsed(item)
        oid = item.get("policy_oid") if isinstance(item, dict) else item
        if not _empty(oid):
            found.append(str(oid).strip())
    return found


def scts(cert):
    """The embedded SCTs as [{"log_id", "timestamp"}] (timestamp a naive UTC Timestamp), [] when none or unknown."""
    value = _parsed(cert.get("Signed Certificate Timestamps"))
    found = []
    for item in value if isinstance(value, (list, tuple)) else []:
        item = _parsed(item)
        if isinstance(item, dict):
            found.append({"log_id": str(item.get("log_id") or ""), "timestamp": when(item.get("timestamp"))})
    return found


def serial_bytes(value):
    """The serial number's length in bytes, leading zeros (and DER's sign byte) left out; None when missing."""
    serial = re.sub(r"[^0-9a-f]", "", str(value or "").lower().removeprefix("0x")) if not _empty(value) else ""
    serial = serial.lstrip("0")
    return (len(serial) + 1) // 2 if serial else None


def days(cert):
    """The validity in whole days, None when unknown."""
    start, end = when(cert.get("Not Before")), when(cert.get("Not After"))
    if pd.notna(start) and pd.notna(end):
        return (end - start).days
    value = pd.to_numeric(cert.get("Duration"), errors="coerce")
    return int(value) if pd.notna(value) else None


def _band(value, bands, last):
    return next((name for limit, name in bands if value <= limit), last)


def precise(cert):
    """Whether the certificate's dates are to the second (a Certificate API record), not a day."""
    sources = set(_values(cert.get("Sources"))) | {text(cert.get("Source"))}
    return bool(sources & API_SOURCES)


def traits(cert):
    """{trait key: normalised value or None (unknown)} plus "days" (exact validity) for display."""
    issuer, org = text(cert.get("Issuer")), text(cert.get("Issuer Org"))
    algo = text(cert.get("Public Key Algo")).lower()
    bits = pd.to_numeric(cert.get("Public Key Bits"), errors="coerce")
    valid_for = days(cert)
    oids = _list(cert.get("Extension OIDs"))
    layout = tuple(o for o in oids if o not in CT_OIDS) + ((CT_TOKEN,) if any(o in CT_OIDS for o in oids) else ())
    eku = _list(cert.get("Extended Key Usage OIDs")) or _list(cert.get("Extended Key Usage"))
    policy = policies(cert)
    names = _values(cert.get("SAN DNS")) or _values(cert.get("Alt Names List"))
    count = pd.to_numeric(cert.get("SAN Count"), errors="coerce")
    count = int(count) if pd.notna(count) and count > 0 else len(names)
    wildcard = _bool(cert.get("Has Wildcard SAN")) or any(n.startswith("*.") for n in names)
    subject = text(cert.get("Subject DN"))
    layout_subject = tuple(sorted({part.split("=", 1)[0].strip().lower() for part in re.split(r",(?=\s*\w+=)", subject)
                                   if "=" in part})) if subject else None
    signature = text(cert.get("Signature Algo")).lower()
    return {
        "issuer": (issuer, org) if issuer or org else None,
        "key": (algo, int(bits) if pd.notna(bits) else None) if algo else None,
        "validity": _band(valid_for, VALIDITY_BANDS, ">398 d") if valid_for is not None and valid_for >= 0 else None,
        "extensions": layout or None,
        "eku": frozenset(eku) or None,
        "policy": frozenset(policy) or None,
        "serial": serial_bytes(cert.get("Serial Number")),
        "sans": (_band(count, SAN_BANDS, ">50 names"), wildcard) if count else None,
        "self_signed": _bool(cert.get("Is Self Signed")) if not _empty(cert.get("Is Self Signed")) else None,
        "signature": signature or None,
        "subject": layout_subject or None,
        "days": valid_for,
    }


def trait_text(key, value, exact_days=None):
    """A trait value as text."""
    if value is None:
        return "–"
    if key == "issuer":
        return " · ".join(dict.fromkeys(v for v in value if v))
    if key == "key":
        return f"{value[0]} {value[1]}" if value[1] else value[0]
    if key == "validity":
        return f"{exact_days} d ({value})" if exact_days is not None else value
    if key == "extensions":
        return f"{len(value) - (CT_TOKEN in value)} extension(s)" + (" + CT" if CT_TOKEN in value else "")
    if key in ("eku", "policy"):
        return ", ".join(OID_SHORT.get(v, v) for v in sorted(value))
    if key == "serial":
        return f"{value} bytes"
    if key == "sans":
        return value[0] + (", wildcard" if value[1] else "")
    if key == "self_signed":
        return "yes" if value else "no"
    if key == "subject":
        return "+".join(value).upper()
    return str(value)


def known(found, keys=None):
    return [k for k in (keys or [t[0] for t in TRAITS]) if found.get(k) is not None]


def shape_id(found):
    """A short ID of the family traits ("S-3f9a1c"), None when fewer than MIN_TRAITS are known."""
    if len(known(found, FAMILY_TRAITS)) < MIN_TRAITS:
        return None
    key = repr([(k, sorted(found[k]) if isinstance(found[k], frozenset) else found[k]) for k in FAMILY_TRAITS])
    return "S-" + hashlib.sha1(key.encode()).hexdigest()[:6]


def shape_label(found):
    """A human name of the shape: "YE2 · ecdsa 256 · 48–100 d · 9 ext + CT · 2 names"."""
    parts = []
    if found.get("issuer"):
        parts.append(found["issuer"][0] or found["issuer"][1])
    if found.get("key"):
        parts.append(trait_text("key", found["key"]))
    if found.get("validity"):
        parts.append(found["validity"])
    if found.get("extensions"):
        ext = found["extensions"]
        parts.append(f"{len(ext) - (CT_TOKEN in ext)} ext" + (" + CT" if CT_TOKEN in ext else ""))
    if found.get("sans"):
        parts.append(trait_text("sans", found["sans"]))
    if found.get("self_signed"):
        parts.append("self-signed")
    return " · ".join(parts) or "unknown"


def similarity(a, b):
    """(score 0-100, [(trait label, a text, b text)] of the traits that differ), or (None, []) when fewer than
    MIN_TRAITS traits are known on both."""
    shared = [(key, label, weight) for key, label, weight, _ in TRAITS if a.get(key) is not None and b.get(key) is not None]
    if len(shared) < MIN_TRAITS:
        return None, []
    total = sum(weight for _, _, weight in shared)
    same = sum(weight for key, _, weight in shared if a[key] == b[key])
    differs = [(label, trait_text(key, a[key], a.get("days") if key == "validity" else None),
                trait_text(key, b[key], b.get("days") if key == "validity" else None))
               for key, label, _ in shared if a[key] != b[key]]
    return round(100 * same / total), differs


def distinct(certs):
    """
    The certificates once each: Domain History lists a certificate by its SHA-1, the Certificate API by its SHA-256,
    so a Domain History row whose hash is another row's SHA1 is the same certificate (its domains join that row).
    """
    if certs is None or certs.empty or "SHA1" not in certs:
        return certs
    alias = {str(s).lower(): h for s, h in zip(certs["SHA1"], certs["Hash"]) if not _empty(s)}
    dup = certs["Hash"].astype(str).str.lower().isin(alias)
    if not dup.any():
        return certs
    kept = certs[~dup].copy()
    if "Domains" in kept:
        extra = {}
        for row in certs[dup].to_dict("records"):
            extra.setdefault(alias[str(row["Hash"]).lower()], set()).update(_values(row.get("Domains")))
        kept["Domains"] = [sorted(set(_values(d)) | extra.get(h, set())) for h, d in zip(kept["Hash"], kept["Domains"])]
    return kept.reset_index(drop=True)


def shapes(certs):
    """One row per distinct certificate: Hash, Shape (ID or None), Shape label, Known (trait count) and Traits."""
    certs = distinct(certs)
    if certs is None or certs.empty:
        return pd.DataFrame(columns=["Hash", "Shape", "Shape label", "Known", "Traits"])
    rows = []
    for cert in certs.to_dict("records"):
        found = traits(cert)
        rows.append({"Hash": cert["Hash"], "Shape": shape_id(found), "Shape label": shape_label(found),
                     "Known": len(known(found)), "Traits": found})
    return pd.DataFrame(rows)


def families(certs, anomalies=None, table=None):
    """
    FAMILY_COLUMNS, largest first: the certificates sharing one shape, with the analyzed domains they cover, first
    and last issue time and how many anomalies (core.cert_anomalies) their certificates have. A family across several
    analyzed domains points to shared infrastructure or tooling; a family of one or two next to large ones is an
    outlier worth a look.
    """
    certs = distinct(certs)
    table = shapes(certs) if table is None else table
    if table.empty or table["Shape"].isna().all():
        return pd.DataFrame(columns=FAMILY_COLUMNS)
    rows_by_hash = {row["Hash"]: row for row in certs.to_dict("records")}
    per_hash = anomalies["Hash"].value_counts().to_dict() if anomalies is not None and not anomalies.empty else {}
    rows = []
    for shape, group in table.dropna(subset=["Shape"]).groupby("Shape", sort=False):
        members = [rows_by_hash[h] for h in group["Hash"]]
        domains = sorted({d for m in members for d in _values(m.get("Domains"))})
        issued = [when(m.get("Not Before")) for m in members]
        issued = [t for t in issued if pd.notna(t)]
        found = group["Traits"].iloc[0]
        rows.append({"Family": shape, "Shape": group["Shape label"].iloc[0], "Certificates": len(members),
                     "Domains": ", ".join(domains), "Domain count": len(domains),
                     "Issuer": trait_text("issuer", found.get("issuer")),
                     "First issued": min(issued) if issued else pd.NaT, "Last issued": max(issued) if issued else pd.NaT,
                     "Anomalies": sum(per_hash.get(h, 0) for h in group["Hash"]), "Hashes": list(group["Hash"])})
    frame = pd.DataFrame(rows, columns=FAMILY_COLUMNS)
    for column in ("First issued", "Last issued"):
        frame[column] = pd.to_datetime(frame[column])
    return frame.sort_values(["Certificates", "Domain count"], ascending=False, kind="stable").reset_index(drop=True)


def family_of(digest, certs, table=None):
    """(shape ID, label, members' hashes) of the certificate's family; (None, label, []) when it has no shape.
    `table`: shapes(certs) when already worked out."""
    table = shapes(certs) if table is None else table
    row = table[table["Hash"] == digest]
    if row.empty:
        return None, "", []
    shape = row["Shape"].iloc[0]
    members = list(table.loc[table["Shape"] == shape, "Hash"]) if shape else []
    return shape, row["Shape label"].iloc[0], members


def shape_relations(cert, certs, limit=None, table=None):
    """The run's other certificates of the same shape ("Same shape") or a near one ("Near shape (92%: validity 6 d vs
    89 d)"), as cert_profile.RELATED_COLUMNS rows with a "Score" column, best first. `table`: shapes(certs) when
    already worked out (its Traits and Shape are reused)."""
    from core.cert_profile import RELATED_COLUMNS
    columns = [*RELATED_COLUMNS, "Score"]
    certs = distinct(certs)
    if certs is None or certs.empty:
        return pd.DataFrame(columns=columns)
    known_shapes = {} if table is None or table.empty else \
        {h: (s, t) for h, s, t in zip(table["Hash"], table["Shape"], table["Traits"])}
    mine = traits(cert)
    own = shape_id(mine)
    sha1 = text(cert.get("SHA1")).lower()
    rows = []
    for other in certs.to_dict("records"):
        if other["Hash"] == cert.get("Hash") or str(other["Hash"]).lower() == sha1:
            continue
        theirs, found = known_shapes.get(other["Hash"], (None, None))
        if found is None:
            found = traits(other)
            theirs = shape_id(found)
        if own and theirs == own:
            relation, score = "Same shape", 100
        else:
            score, differs = similarity(mine, found)
            if score is None or score < NEAR:
                continue
            relation = f"Near shape ({score}%: " + "; ".join(f"{label.lower()} {a} vs {b}" for label, a, b in differs[:2]) + ")"
        rows.append({"Relation": relation, "Hash": other["Hash"], "Common Name": text(other.get("Common Name")),
                     "Issuer": text(other.get("Issuer")), "Not Before": when(other.get("Not Before")),
                     "Not After": when(other.get("Not After")), "Domains": text(other.get("Domains")), "Score": score})
    frame = pd.DataFrame(rows, columns=columns)
    for column in ("Not Before", "Not After"):
        frame[column] = pd.to_datetime(frame[column])
    frame = frame.sort_values("Score", ascending=False, kind="stable").reset_index(drop=True)
    return frame.head(limit) if limit else frame


def shape_query(cert, since_days=90, today=None):
    """
    A CertsQL query for certificates of the same shape (issuer, key, validity band, SAN count band, the extension
    OIDs that are not CT's, policy), issued in the last `since_days` days. The page runs it only on Search.
    """
    found = traits(cert)
    clauses = []
    if found["issuer"]:
        cn, org = found["issuer"]
        if cn:
            clauses.append(f'issuer_common_name equals "{cn}"')
        elif org:
            clauses.append(f'issuer_organization equals "{org}"')
    if found["key"]:
        clauses.append(f'public_key_algorithm equals "{found["key"][0]}"')
        if found["key"][1]:
            clauses.append(f"public_key_bits equals {found['key'][1]}")
    if found["validity"]:
        low, high = VALIDITY_RANGES[found["validity"]]
        clauses.append(f"validity_duration_days between [{low}, {high}]")
    if found["sans"]:
        low, high = SAN_RANGES[found["sans"][0]]
        clauses.append(f"san_count equals {low}" if low == high else f"san_count between [{low}, {high}]")
    for oid in sorted(found["policy"] or ()):
        clauses.append(f'certificate_policy.policy_oid equals "{oid}"')
    if found["self_signed"] is not None:
        clauses.append(f"is_self_signed equals {'true' if found['self_signed'] else 'false'}")
    today = pd.Timestamp(today) if today is not None else pd.Timestamp.now(tz="UTC").tz_localize(None)
    clauses.append(f'validity_not_before greater_than "{(today - pd.Timedelta(days=since_days)):%Y-%m-%d}"')
    return HEADER + "\n" + "\nAND\n".join(clauses)

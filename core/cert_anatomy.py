"""
Certificate anatomy: one certificate drawn as a single HTML view, replacing the separate field map and field table.
- A header: the trust flow (issuer → certificate → names), the role / status / served tags and the verdict.
- A field fingerprint: one cell per X.509 field, filled, empty or flagged, so a certificate's completeness and its
  problems read at a glance (and two certificates compare by eye).
- A validity timeline (issued → now → expiry, with the 398-day limit when it runs longer) and a key strength meter.
- One card per section in the certificate's own order, with how many of its fields are filled, every field with a
  value drawn for its kind (DN parts, SAN chips with the analyzed domains highlighted, JA4X in its three parts,
  fingerprints in groups of four, yes / no pills, dates with how long ago) and the flags right under the field.

Pure: returns HTML built from escaped values only (Streamlit's st.html and the analysis report both show it).
"""
import html
import re

import pandas as pd

from core import ja4x
from core.cert_profile import CA_BROWSER_MAX_DAYS, FIELD_GROUPS, _empty, _values, publicly_trusted, text, when
from core.intel_data import SEVERITY_COLORS, SEVERITY_RANK

FIELD_HELP = {
    "Common Name": "The main name the certificate is for. Browsers ignore it in favour of the SANs.",
    "Subject Org": "The organization the CA verified (OV / EV only). Empty on DV certificates.",
    "Subject Country": "The subject's country, verified on OV / EV certificates.",
    "Subject State/Province": "The subject's state or province, verified on OV / EV certificates.",
    "Subject DN": "The full subject distinguished name: every attribute of who the certificate is for.",
    "Issuer": "The issuing CA certificate's common name (often an intermediate, such as R11 or E6).",
    "Issuer Org": "The organization that runs the issuing CA.",
    "Issuer OU": "The issuing CA's organizational unit.",
    "Issuer Country": "The issuing CA's country.",
    "Issuer DN": "The issuer's full distinguished name. It equals the subject's on a self-signed certificate.",
    "Not Before": "When the certificate starts being valid: close to when it was issued.",
    "Not After": "When the certificate stops being valid.",
    "Duration": f"Days between Not Before and Not After. Publicly trusted TLS certificates may run up to "
                f"{CA_BROWSER_MAX_DAYS} days.",
    "Validation Level": "DV: domain control only. OV: organization checked. EV: extended checks.",
    "Public Key Algo": "The key type: RSA, or an elliptic curve (EC / ECDSA, Ed25519).",
    "Public Key Bits": "Key size. RSA below 2048 bits is weak; EC 256 bits is about as strong as RSA 3072.",
    "Public Key SHA256": "Fingerprint of the public key (SPKI). The same key on several certificates links them.",
    "Key Usage": "What the key may do (sign, encrypt, agree keys).",
    "Extended Key Usage": "What the certificate is for. A web server certificate says Server Authentication.",
    "Extended Key Usage OIDs": "The extended key usages as object identifiers.",
    "Basic Constraints": "CA:TRUE marks a certificate that may issue others; a site's certificate has CA:FALSE.",
    "Certificate Policy": "The CA's policy OIDs: the CA/B Forum DV / OV / EV policy shows how it was validated.",
    "Authority Key ID": "Identifies the issuer's key: links the certificate to the CA certificate that signed it.",
    "Subject Key ID": "Identifies this certificate's own key.",
    "Extension OIDs": "Every extension the certificate carries, as object identifiers. Their set and order make "
                      "the JA4X extension part.",
    "Has Embedded SCTs": "Signed certificate timestamps: proof it was logged in Certificate Transparency before "
                         "issuance. Publicly trusted certificates carry them.",
    "Signed Certificate Timestamps": "The CT logs that signed a timestamp for it.",
    "Is Precertificate": "A precertificate is the copy logged in CT before the real certificate is issued.",
    "SAN DNS": "Subject alternative names: every hostname the certificate is valid for.",
    "SAN IPv4": "IPv4 addresses the certificate is valid for: rare on public web certificates.",
    "SAN IPv6": "IPv6 addresses the certificate is valid for.",
    "SAN Count": "How many names the certificate covers. Many names: a shared (CDN / hosting) or bulk certificate.",
    "Has Wildcard SAN": "A *.domain name covers every hostname at that level.",
    "Signature Algo": "How the CA signed it. SHA-1 and MD5 are broken.",
    "Serial Number": "The CA's unique number for the certificate.",
    "Hash": "SHA-256 of the whole certificate: its identity across CT logs and scans.",
    "SHA1": "SHA-1 of the whole certificate (older tools key on it).",
    "MD5": "MD5 of the whole certificate (older tools key on it).",
    "JA4X": "How the certificate was generated: hashes of the issuer's and the subject's attribute order and the "
            "extension order. The same tool makes the same JA4X.",
    "Is Self Signed": "Signed by its own key: no certificate authority vouches for it.",
}
BOOLEAN_FIELDS = {"Is Self Signed", "Has Embedded SCTs", "Is Precertificate", "Has Wildcard SAN"}
BAD_WHEN_TRUE = {"Is Self Signed"}
GOOD_WHEN_TRUE = {"Has Embedded SCTs"}
HEX_FIELDS = {"Hash", "SHA1", "MD5", "Public Key SHA256", "Serial Number", "Subject Key ID", "Authority Key ID"}
LIST_FIELDS = {"Key Usage", "Extended Key Usage", "Extended Key Usage OIDs", "Extension OIDs", "Certificate Policy",
               "Signed Certificate Timestamps", "SAN IPv4", "SAN IPv6"}
DN_FIELDS = {"Subject DN", "Issuer DN"}
OID_NAMES = {
    "2.5.29.14": "Subject key ID", "2.5.29.15": "Key usage", "2.5.29.17": "Subject alt names",
    "2.5.29.18": "Issuer alt names", "2.5.29.19": "Basic constraints", "2.5.29.30": "Name constraints",
    "2.5.29.31": "CRL distribution", "2.5.29.32": "Certificate policies", "2.5.29.35": "Authority key ID",
    "2.5.29.37": "Extended key usage", "1.3.6.1.5.5.7.1.1": "Authority info access (OCSP, CA issuers)",
    "1.3.6.1.5.5.7.1.24": "TLS feature (OCSP must-staple)", "1.3.6.1.4.1.11129.2.4.2": "Embedded SCT list",
    "1.3.6.1.4.1.11129.2.4.3": "CT poison (precertificate)", "2.16.840.1.113730.1.1": "Netscape cert type",
    "2.16.840.1.113730.1.13": "Netscape comment",
    "1.3.6.1.5.5.7.3.1": "Server authentication", "1.3.6.1.5.5.7.3.2": "Client authentication",
    "1.3.6.1.5.5.7.3.3": "Code signing", "1.3.6.1.5.5.7.3.4": "Email protection", "1.3.6.1.5.5.7.3.8": "Time stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP signing", "2.5.29.37.0": "Any extended key usage",
    "2.23.140.1.2.1": "Domain validated (CA/B Forum)", "2.23.140.1.2.2": "Organization validated (CA/B Forum)",
    "2.23.140.1.2.3": "Individual validated (CA/B Forum)", "2.23.140.1.1": "Extended validation (CA/B Forum)",
    "1.3.6.1.4.1.44947.1.1.1": "ISRG domain validated (Let's Encrypt)", "2.5.29.32.0": "Any policy",
}
UNUSUAL_OIDS = {"1.3.6.1.5.5.7.3.3", "2.5.29.37.0", "2.16.840.1.113730.1.1", "2.16.840.1.113730.1.13"}
SAN_SHOWN = 60                 # SAN chips shown before the rest fold away

CSS = """
<style>
.ca{--ca-line:rgba(127,127,127,.28);--ca-soft:rgba(127,127,127,.08);--ca-mute:rgba(127,127,127,.95);
 --ca-accent:#6366f1;font-size:14px;line-height:1.45;color:inherit}
.ca *{box-sizing:border-box}
.ca .hero{display:flex;flex-wrap:wrap;gap:16px;align-items:stretch;justify-content:space-between;padding:16px 18px;
 border:1px solid var(--ca-line);border-radius:14px;margin-bottom:12px;
 background:linear-gradient(135deg,rgba(99,102,241,.14),rgba(20,184,166,.08) 60%,transparent)}
.ca .flow{display:flex;flex-wrap:wrap;align-items:center;gap:8px;min-width:0;flex:1 1 440px}
.ca .node{padding:8px 12px;border-radius:10px;border:1px solid var(--ca-line);background:var(--ca-soft);min-width:0}
.ca .node.main{border-color:var(--ca-accent);box-shadow:0 0 0 3px rgba(99,102,241,.18)}
.ca .node small{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--ca-mute)}
.ca .node b{display:block;font-size:15px;overflow-wrap:anywhere}
.ca .arrow{font-size:11px;color:var(--ca-mute);text-align:center;white-space:nowrap}
.ca .arrow:after{content:"";display:block;height:2px;margin-top:2px;
 background:linear-gradient(90deg,transparent,var(--ca-accent))}
.ca .verdict{margin-left:auto;display:flex;flex-direction:column;align-items:flex-end;justify-content:center;gap:6px}
.ca .badge{display:inline-block;padding:5px 12px;border-radius:999px;color:#fff;font-weight:700;font-size:13px}
.ca .tags{display:flex;flex-wrap:wrap;gap:6px;justify-content:flex-end}
.ca .tag{font-size:12px;padding:2px 9px;border-radius:999px;border:1px solid var(--ca-line);background:var(--ca-soft)}
.ca .tag.good{border-color:#16a34a;color:#16a34a}.ca .tag.bad{border-color:#dc2626;color:#dc2626}
.ca .tag.live{border-color:#16a34a;background:rgba(22,163,74,.12);color:#16a34a}
.ca .strip{border:1px solid var(--ca-line);border-radius:12px;padding:10px 14px;margin-bottom:12px}
.ca .strip h5{margin:0 0 6px;font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--ca-mute)}
.ca .dna{display:flex;gap:3px;flex-wrap:wrap}
.ca .dna span{width:14px;height:22px;border-radius:3px;background:var(--ca-accent);opacity:.85}
.ca .dna span.empty{background:var(--ca-line);opacity:.6}
.ca .dna span.gap{width:8px;background:transparent}
.ca .legend{display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--ca-mute);margin-top:6px}
.ca .legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
.ca .twin{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin-bottom:12px}
.ca .twin .strip{margin:0}
.ca .bar{position:relative;height:14px;border-radius:7px;background:var(--ca-soft);margin:22px 0 22px}
.ca .bar .span{position:absolute;top:0;bottom:0;border-radius:7px}
.ca .bar .mark{position:absolute;top:-6px;bottom:-6px;width:2px;background:currentColor}
.ca .bar .mark em{position:absolute;top:-18px;left:50%;transform:translateX(-50%);font-size:11px;font-style:normal;
 white-space:nowrap;font-weight:700}
.ca .bar .limit{position:absolute;top:-3px;bottom:-3px;border-left:2px dashed #dc2626}
.ca .bar .limit em{position:absolute;bottom:-18px;left:4px;font-size:11px;font-style:normal;color:#dc2626;
 white-space:nowrap}
.ca .ends{display:flex;justify-content:space-between;font-size:12px;color:var(--ca-mute)}
.ca .meter{height:14px;border-radius:7px;background:var(--ca-soft);overflow:hidden;margin:10px 0 6px}
.ca .meter div{height:100%;border-radius:7px}
.ca .big{font-size:20px;font-weight:700}
.ca .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:12px}
.ca .card{border:1px solid var(--ca-line);border-left:5px solid var(--ca-sev,var(--ca-line));border-radius:12px;
 overflow:hidden}
.ca .card header{display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--ca-soft)}
.ca .card header .t{flex:1;font-weight:700}
.ca .card header .t small{display:block;font-weight:400;font-size:12px;color:var(--ca-mute)}
.ca .ring{position:relative;width:40px;height:40px;flex:none;display:grid;place-items:center}
.ca .ring i{position:absolute;inset:0;border-radius:50%;
 -webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 5px),#000 calc(100% - 4px));
 mask:radial-gradient(farthest-side,transparent calc(100% - 5px),#000 calc(100% - 4px))}
.ca .ring span{position:relative;font-size:10px;font-weight:700}
.ca .row{display:grid;grid-template-columns:150px 1fr;gap:10px;padding:7px 12px;border-top:1px solid var(--ca-line)}
.ca .row.empty{opacity:.5}
.ca .row.hit{background:rgba(250,204,21,.14)}
.ca .row.flagged{background:color-mix(in srgb,var(--ca-sev) 10%,transparent)}
.ca .k{font-size:12.5px;color:var(--ca-mute);cursor:help}
.ca .k abbr{text-decoration:none;border-bottom:1px dotted var(--ca-line)}
.ca .v{min-width:0;overflow-wrap:anywhere}
.ca .help{grid-column:1/-1;font-size:12px;color:var(--ca-mute);margin-top:-2px}
.ca .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.ca .hex span{margin-right:5px}
.ca .chips{display:flex;flex-wrap:wrap;gap:4px}
.ca .chip{padding:1px 8px;border-radius:6px;border:1px solid var(--ca-line);background:var(--ca-soft);font-size:12.5px}
.ca .chip.own{border-color:var(--ca-accent);background:rgba(99,102,241,.16);font-weight:600}
.ca .chip.wild{border-style:dashed}
.ca .chip b{color:var(--ca-mute);font-weight:600;margin-right:2px}
.ca .pill{padding:1px 9px;border-radius:999px;font-size:12px;font-weight:700;color:#fff}
.ca .hex i{font-style:normal;color:var(--ca-mute);margin-right:5px}
.ca .flag{display:flex;gap:6px;align-items:baseline;margin-top:5px;font-size:12.5px}
.ca .flag b{color:#fff;font-size:11px;padding:0 7px;border-radius:999px;flex:none}
.ca .rel{color:var(--ca-mute);font-size:12px;margin-left:6px}
.ca details summary{cursor:pointer;color:var(--ca-accent);font-size:12.5px;margin-top:4px}
.ca .none{padding:14px;color:var(--ca-mute)}
.ca .shape{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline;margin-bottom:10px}
.ca .shape b.mono{font-size:13px;padding:1px 8px;border-radius:6px;background:rgba(99,102,241,.16)}
.ca .vs{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:6px}
.ca .vs div{border:1px solid var(--ca-line);border-left:4px solid var(--ca-vs);border-radius:8px;padding:5px 9px;
 font-size:12.5px;min-width:0;overflow-wrap:anywhere}
.ca .vs small{display:block;color:var(--ca-mute);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
.ca .vs em{display:block;font-style:normal;color:var(--ca-mute);font-size:12px}
</style>
"""


def _e(value):
    return html.escape(str(value), quote=True)


def _severity_colour(severity):
    return SEVERITY_COLORS.get(severity, "#64748b")


def _worst(severities):
    ranked = [s for s in severities if s]
    return min(ranked, key=lambda s: SEVERITY_RANK.get(s, 9)) if ranked else None


def _is_true(value):
    return isinstance(value, bool) and value or str(value).strip().lower() in ("true", "1", "yes")


def field_value(cert, column):
    """The field's raw value; the SANs fall back to Alt Names List (Iris and Domain History rows)."""
    value = cert.get(column)
    if column == "SAN DNS" and _empty(value):
        value = cert.get("Alt Names List")
    return value


def _ago(stamp, now):
    days = (stamp - now).days
    if days == 0:
        return "today"
    return f"in {days:,} d" if days > 0 else f"{-days:,} d ago"


def _chips(items, classes=None):
    classes = classes or {}
    return '<div class="chips">' + "".join(f'<span class="{" ".join(["chip", classes.get(i, "")]).strip()}">'
                                           f"{_e(i)}</span>" for i in items) + "</div>"


def _split(value):
    items = _values(value)
    if len(items) == 1 and ", " in items[0]:
        items = [p.strip() for p in items[0].split(", ") if p.strip()]
    return items


def _dn(value):
    parts = [p.strip() for p in re.split(r",(?=\s*[A-Za-z][\w.]*\s*=)", text(value)) if p.strip()]
    if len(parts) < 2 and "=" not in text(value):
        return _e(text(value))
    chips = []
    for part in parts:
        key, _, rest = part.partition("=")
        chips.append(f'<span class="chip"><b>{_e(key.strip())}=</b>{_e(rest.strip())}</span>')
    return '<div class="chips">' + "".join(chips) + "</div>"


def _hex(value):
    raw = text(value)
    plain = raw.replace(":", "").replace(" ", "")
    if not re.fullmatch(r"[0-9A-Fa-f]+", plain or "-"):
        return f'<span class="mono">{_e(raw)}</span>'
    return '<span class="mono hex">' + "".join(f"<span>{_e(plain[i:i + 4])}</span>"
                                               for i in range(0, len(plain), 4)) + "</span>"


def _ja4x(value):
    """JA4X like the other fingerprints: monospace, in groups of four, its three parts apart (the JA4X card below the
    view explains them; a known or code-generated JA4X is a flag, shown under the field)."""
    normalized = ja4x.normalize(value) or text(value)
    parts = normalized.split("_")
    if len(parts) != 3 or not all(re.fullmatch(r"[0-9A-Fa-f]+", p) for p in parts):
        return f'<span class="mono">{_e(text(value))}</span>'
    return '<span class="mono hex">' + "<i>_</i>".join(
        "".join(f"<span>{_e(p[i:i + 4])}</span>" for i in range(0, len(p), 4)) for p in parts) + "</span>"


def _sans(value, domains):
    names = _values(value)
    domains = [d.lower() for d in domains]

    def own(name):
        bare = name.lower().lstrip("*.")
        return any(bare == d or bare.endswith("." + d) for d in domains)
    ordered = sorted(names, key=lambda n: (not own(n), n.startswith("*."), n))
    classes = {n: " ".join(c for c in ("own" if own(n) else "", "wild" if n.startswith("*.") else "") if c)
               for n in ordered}
    mine = sum(own(n) for n in names)
    head = (f'<div class="rel" style="margin:0 0 4px">{mine} of the analyzed domain(s) · {len(names) - mine} other'
            "</div>") if domains else ""
    shown, rest = ordered[:SAN_SHOWN], ordered[SAN_SHOWN:]
    more = (f"<details><summary>{len(rest):,} more name(s)</summary>{_chips(rest, classes)}</details>"
            if rest else "")
    return head + _chips(shown, classes) + more


def _parsed(value):
    """A structured value (dict / list of dicts), also when it came back as its Python text."""
    if isinstance(value, str) and value.strip()[:1] in "{[":
        import ast
        try:
            return ast.literal_eval(value.strip())
        except (ValueError, SyntaxError):
            return value
    return value


def _oids(value, numbered=False):
    """OIDs as chips with their names; `numbered` keeps their order visible (the extension order is part of JA4X)."""
    items = _split(value)
    chips = []
    for number, oid in enumerate(items, 1):
        name = OID_NAMES.get(oid)
        unusual = ' style="border-color:#d97706"' if oid in UNUSUAL_OIDS else ""
        prefix = f"<b>{number}</b>" if numbered else ""
        body = f"{_e(name)} <small class=\"mono rel\" style=\"margin:0\">{_e(oid)}</small>" if name else \
            f'<span class="mono">{_e(oid)}</span> <small class="rel" style="margin:0">unknown</small>'
        chips.append(f'<span class="chip"{unusual}>{prefix}{body}</span>')
    return '<div class="chips">' + "".join(chips) + "</div>"


def _constraints(value):
    value = _parsed(value)
    if not isinstance(value, dict):
        return _e(text(value))
    is_ca = value.get("is_ca")
    pills = [f'<span class="pill" style="background:{"#dc2626" if is_ca else "#16a34a"}">'
             f'{"CA: yes, may issue certificates" if is_ca else "CA: no (end-entity)"}</span>']
    if value.get("critical"):
        pills.append('<span class="chip">critical</span>')
    for key in ("max_path_len", "path_len", "pathlen"):
        if value.get(key) is not None:
            pills.append(f'<span class="chip"><b>path length</b> {_e(value[key])}</span>')
    return '<div class="chips">' + "".join(pills) + "</div>"


def _policies(value):
    value = _parsed(value)
    items = value if isinstance(value, list) else [value]
    oids = [i.get("policy_oid") if isinstance(i, dict) else str(i) for i in items if i]
    return _oids([o for o in oids if o])


def _scts(value, cert):
    value = _parsed(value)
    if not isinstance(value, list) or not all(isinstance(i, dict) for i in value):
        return _e(text(value))
    start = when(cert.get("Not Before"))
    rows = []
    for item in sorted(value, key=lambda i: str(i.get("timestamp"))):
        stamp = when(item.get("timestamp"))
        delta = ""
        if pd.notna(stamp) and pd.notna(start):
            minutes = (stamp - start).total_seconds() / 60
            delta = f"{minutes:+.0f} min vs Not Before" if abs(minutes) < 2880 else f"{minutes / 1440:+.0f} d vs Not Before"
        rows.append(f'<div><span class="mono">{_e(str(item.get("log_id", ""))[:16])}…</span>'
                    f'<span class="rel">{f"{stamp:%Y-%m-%d %H:%M}" if pd.notna(stamp) else ""} {_e(delta)}</span></div>')
    return f'<div class="rel" style="margin:0 0 3px">{len(value)} CT log(s) signed it</div>' + "".join(rows)


def _boolean(column, value):
    yes = _is_true(value)
    if column in BAD_WHEN_TRUE:
        colour = "#dc2626" if yes else "#16a34a"
    elif column in GOOD_WHEN_TRUE:
        colour = "#16a34a" if yes else "#d97706"
    else:
        colour = "#64748b"
    return f'<span class="pill" style="background:{colour}">{"Yes" if yes else "No"}</span>'


def render_value(column, cert, domains=(), now=None):
    """One field's value as HTML for its kind."""
    value = field_value(cert, column)
    if column == "Has Embedded SCTs" and _is_true(cert.get("Is Precertificate")) and not _is_true(value):
        return _boolean("", value) + '<span class="rel">a precertificate carries none: expected</span>'
    if column in BOOLEAN_FIELDS:
        return _boolean(column, value)
    if column in ("Not Before", "Not After"):
        stamp = when(value)
        if pd.isna(stamp):
            return _e(text(value))
        return f'{stamp:%Y-%m-%d %H:%M} UTC<span class="rel">{_ago(stamp, now)}</span>'
    if column == "SAN DNS":
        return _sans(value, domains)
    if column == "JA4X":
        return _ja4x(value)
    if column in DN_FIELDS:
        return _dn(value)
    if column == "Basic Constraints":
        return _constraints(value)
    if column == "Certificate Policy":
        return _policies(value)
    if column == "Signed Certificate Timestamps":
        return _scts(value, cert)
    if column == "Extension OIDs":
        return _oids(value, numbered=True)
    if column == "Extended Key Usage OIDs":
        return _oids(value)
    if column in ("Key Usage", "Extended Key Usage"):
        return _chips([v.replace("_", " ") for v in _split(value)])
    if column in HEX_FIELDS:
        return _hex(value)
    if column in LIST_FIELDS:
        return _chips(_split(value))
    if column == "Validation Level":
        return f'<span class="chip">{_e(text(value).upper())}</span>'
    return _e(text(value))


def _security_bits(algo, bits):
    """Rough symmetric-equivalent strength (NIST SP 800-57) of a public key."""
    bits = pd.to_numeric(bits, errors="coerce")
    if pd.isna(bits) or bits <= 0:
        return None
    algo = str(algo).lower()
    if any(k in algo for k in ("ec", "ed25519", "ed448")):
        return int(bits // 2)
    for limit, strength in ((1024, 80), (2048, 112), (3072, 128), (7680, 192), (15360, 256)):
        if bits <= limit:
            return strength if bits == limit else max(strength - 32, 40)
    return 256


def _key_meter(cert):
    algo, bits = text(cert.get("Public Key Algo")), text(cert.get("Public Key Bits"))
    strength = _security_bits(algo, bits)
    if strength is None:
        return '<div class="strip"><h5>Key strength</h5><div class="rel">No key size in the source.</div></div>'
    colour = "#dc2626" if strength < 112 else "#d97706" if strength < 128 else "#16a34a"
    verdict = "weak" if strength < 112 else "acceptable" if strength < 128 else "strong"
    return (f'<div class="strip"><h5>Key strength</h5><div class="big">{_e(algo)} {_e(bits)} '
            f'<span class="rel">≈ {strength}-bit security · {verdict}</span></div>'
            f'<div class="meter"><div style="width:{min(100, strength / 256 * 100):.0f}%;background:{colour}">'
            "</div></div><div class=\"ends\"><span>80 broken</span><span>112 minimum</span><span>128</span>"
            "<span>256</span></div></div>")


def _timeline(cert, now):
    start, end = when(cert.get("Not Before")), when(cert.get("Not After"))
    if pd.isna(start) or pd.isna(end) or end <= start:
        return '<div class="strip"><h5>Validity</h5><div class="rel">No validity dates in the source.</div></div>'
    days = (end - start).days
    limit = start + pd.Timedelta(days=CA_BROWSER_MAX_DAYS)
    show_limit = days > CA_BROWSER_MAX_DAYS and publicly_trusted(cert) is not False
    lo, hi = min(start, now), max(end, now, limit if show_limit else end)
    span = (hi - lo).total_seconds() or 1

    def pos(t):
        return (t - lo).total_seconds() / span * 100
    expired, early = now > end, now < start
    colour = "#dc2626" if expired else "#d97706" if early or (end - now).days < 14 else "#16a34a"
    used = min(100, max(0, (now - start).total_seconds() / ((end - start).total_seconds()) * 100))
    state = ("expired " + _ago(end, now) if expired else "not valid yet: starts " + _ago(start, now) if early
             else f"{(end - now).days:,} d left · {used:.0f}% of its life used")
    limit_html = (f'<div class="limit" style="left:{pos(limit):.1f}%"><em>{CA_BROWSER_MAX_DAYS}-day limit</em></div>'
                  if show_limit else "")
    return (f'<div class="strip"><h5>Validity</h5><div class="big">{days:,} days '
            f'<span class="rel">{_e(state)}</span></div>'
            f'<div class="bar"><div class="span" style="left:{pos(start):.1f}%;width:{pos(end) - pos(start):.1f}%;'
            f'background:{colour};opacity:.75"></div>{limit_html}'
            f'<div class="mark" style="left:{pos(now):.1f}%"><em>now</em></div></div>'
            f'<div class="ends"><span>issued {start:%Y-%m-%d}</span><span>expires {end:%Y-%m-%d}</span></div></div>')


def _hero(cert, worst, flag_count, sections_filled):
    issuer = text(cert.get("Issuer Org")) or text(cert.get("Issuer")) or "unknown issuer"
    ca = text(cert.get("Issuer"))
    cn = text(cert.get("Common Name")) or "(no common name)"
    names = len(_values(field_value(cert, "SAN DNS")))
    self_signed = _is_true(cert.get("Is Self Signed"))
    badge = (f'<span class="badge" style="background:{_severity_colour(worst)}">{_e(worst)} · {flag_count} flag(s)'
             "</span>" if worst else '<span class="badge" style="background:#16a34a">Nothing stands out</span>')
    tags = []
    if cert.get("Role"):
        tags.append(f'<span class="tag">{_e(cert["Role"])}</span>')
    status = cert.get("Status")
    if status:
        tags.append(f'<span class="tag {"good" if status == "Valid" else "bad"}">{_e(status)}</span>')
    if _is_true(cert.get("Served")):
        tags.append('<span class="tag live">● served on the website now</span>')
    filled, total = sections_filled
    tags.append(f'<span class="tag">{filled} of {total} fields filled</span>')
    issuer_node = (f'<div class="node"><small>{"self-signed" if self_signed else "issued by"}</small><b>{_e(issuer)}</b>'
                   + (f'<span class="rel" style="margin:0">{_e(ca)}</span>' if ca and ca != issuer else "") + "</div>")
    return ('<div class="hero"><div class="flow">' + issuer_node
            + '<div class="arrow">signs</div>'
            + f'<div class="node main"><small>certificate</small><b>{_e(cn)}</b></div>'
            + '<div class="arrow">covers</div>'
            + f'<div class="node"><small>names</small><b>{names:,}</b></div></div>'
            + f'<div class="verdict">{badge}<div class="tags">{"".join(tags)}</div></div></div>')


def _ring(pct, colour):
    """A completeness ring: a conic gradient with its middle masked out (plain CSS: Streamlit's st.html drops SVG,
    and no background colour is assumed, so it reads on light and dark themes)."""
    return (f'<div class="ring"><i style="background:conic-gradient({colour} {pct:.0f}%,rgba(127,127,127,.25) 0)">'
            f"</i><span>{pct:.0f}%</span></div>")


def _fingerprint(cert, by_column):
    cells = []
    for number, (section, fields) in enumerate(FIELD_GROUPS):
        if number:
            cells.append('<span class="gap"></span>')
        for label, column in fields:
            value = text(field_value(cert, column), 60)
            severity = _worst(s for s, _ in by_column.get(column, []))
            tip = f"{section} · {label}: {value or 'empty'}"
            if severity:
                cells.append(f'<span title="{_e(tip)}" style="background:{_severity_colour(severity)};opacity:1">'
                             "</span>")
            else:
                cells.append(f'<span class="{"" if value else "empty"}" title="{_e(tip)}"></span>')
    legend = ('<div class="legend"><span><i style="background:#6366f1"></i>filled</span>'
              '<span><i style="background:rgba(127,127,127,.4)"></i>empty</span>'
              + "".join(f'<span><i style="background:{_severity_colour(s)}"></i>{s}</span>'
                        for s in ("Critical", "High", "Medium", "Low"))
              + "<span>one cell per field, sections apart: hover a cell</span></div>")
    return f'<div class="strip"><h5>Field fingerprint</h5><div class="dna">{"".join(cells)}</div>{legend}</div>'


USUAL = "Issuer's usual"
VERDICT_COLOURS = {"usual": "#16a34a", "differs": "#d97706", "rare": "#dc2626", "too few": "rgba(127,127,127,.45)"}


def _shape_strip(family, against):
    """The certificate's shape (family ID, label, size) and its traits against its issuer's usual ones."""
    if not family and (against is None or against.empty):
        return ""
    parts = ['<div class="strip"><h5>Shape and issuer baseline</h5>']
    if family and family.get("id"):
        size, spread = len(family.get("members") or []), len(family.get("domains") or [])
        parts.append(f'<div class="shape"><b class="mono">{_e(family["id"])}</b><span>{_e(family.get("label"))}</span>'
                     f'<span class="tag">{size} certificate(s) of this shape · {spread} analyzed domain(s)</span></div>')
    elif family:
        parts.append('<div class="shape"><span class="rel" style="margin:0">Too few known fields to give this '
                     "certificate a shape (Domain History and Iris Investigate list only a few).</span></div>")
    if against is not None and not against.empty:
        def note(row):
            share = re.search(r"\((\d+ of \d+)\)$", row[USUAL])
            if row["Verdict"] == "usual":
                return f"usual ({share.group(1)})" if share else "usual"
            return f"{row['Verdict']} · usual: {row[USUAL]}"
        cells = "".join(
            f'<div style="--ca-vs:{VERDICT_COLOURS.get(r["Verdict"], "#6366f1")}"><small>{_e(r["Trait"])}</small>'
            f'{_e(r["This certificate"])}<em>{_e(note(r))}</em></div>' for r in against.to_dict("records"))
        parts.append(f'<div class="vs">{cells}</div><div class="legend">'
                     + "".join(f'<span><i style="background:{c}"></i>{v}</span>' for v, c in VERDICT_COLOURS.items())
                     + "<span>against the run's certificates of the same issuer (usual: the most common value, "
                       "n of N issuances)</span></div>")
    return "".join(parts) + "</div>"


def anatomy_html(cert, found=None, only_filled=True, query="", explain=False, domains=None, now=None, css=True,
                 family=None, against=None):
    """
    The certificate's anatomy as one HTML block (see the module docstring). `found`: cert_profile.flags.
    `only_filled`: leave out empty fields. `query`: keep only fields whose name or value contains it (highlighted).
    `explain`: a line under each field saying what it is. `domains`: the analyzed domains (highlighted SANs).
    `css`: include the stylesheet (a page showing several anatomies needs it once). `family` and `against`
    (core.cert_anomalies.profile): the certificate's shape and its traits against its issuer's usual ones.
    """
    now = now or pd.Timestamp.now(tz="UTC").tz_localize(None)
    domains = list(domains if domains is not None else _values(cert.get("Domains")))
    by_column = {}
    if found is not None and not found.empty:
        for row in found.to_dict("records"):
            by_column.setdefault(row["Field"], []).append((row["Severity"], row["Finding"]))
    every = [(s, label, c) for s, fields in FIELD_GROUPS for label, c in fields]
    filled = sum(bool(text(field_value(cert, c))) for _, _, c in every)
    worst = _worst(s for findings in by_column.values() for s, _ in findings)
    flag_count = sum(len(v) for v in by_column.values())
    needle = (query or "").strip().lower()
    cards = []
    for section, fields in FIELD_GROUPS:
        rows = []
        section_filled = sum(bool(text(field_value(cert, c))) for _, c in fields)
        section_worst = _worst(s for _, c in fields for s, _ in by_column.get(c, []))
        for label, column in fields:
            value_text = text(field_value(cert, column))
            findings = by_column.get(column, [])
            if only_filled and not value_text and not findings:
                continue
            value_html = render_value(column, cert, domains, now) if value_text else "—"
            shown = html.unescape(re.sub(r"<[^>]+>", " ", value_html))       # what the analyst sees: OID names too
            hit = bool(needle) and any(needle in part.lower() for part in (
                label, column, value_text, shown, FIELD_HELP.get(column, ""), *(f for _, f in findings)))
            if needle and not hit:
                continue
            severity = _worst(s for s, _ in findings)
            classes = " ".join(c for c in ("empty" if not value_text else "", "hit" if hit else "",
                                           "flagged" if severity else "") if c)
            style = f' style="--ca-sev:{_severity_colour(severity)}"' if severity else ""
            flags_html = "".join(f'<div class="flag"><b style="background:{_severity_colour(s)}">{_e(s)}</b>'
                                 f"<span>{_e(f)}</span></div>" for s, f in findings)
            help_text = FIELD_HELP.get(column, "")
            help_html = f'<div class="help">{_e(help_text)}</div>' if explain and help_text else ""
            rows.append(f'<div class="row {classes}"{style}><div class="k"><abbr title="{_e(help_text)}">'
                        f"{_e(label)}</abbr></div><div class=\"v\">{value_html}{flags_html}</div>{help_html}</div>")
        if not rows:
            continue
        pct = section_filled / len(fields) * 100
        ring_colour = _severity_colour(section_worst) if section_worst else "#6366f1"
        sev_style = f' style="--ca-sev:{_severity_colour(section_worst)}"' if section_worst else ""
        flag_note = (f" · {sum(len(by_column.get(c, [])) for _, c in fields)} flag(s)" if section_worst else "")
        cards.append(f'<section class="card"{sev_style}><header><div class="t">{_e(section)}<small>{section_filled} of '
                     f"{len(fields)} fields filled{flag_note}</small></div>"
                     f"{_ring(pct, ring_colour)}</header>" + "".join(rows) + "</section>")
    body = "".join(cards) or (f'<div class="none">No field, value or explanation matches “{_e(query.strip())}”'
                              + (" (empty fields are hidden: switch off “Only filled fields” to search them too)"
                                 if only_filled else "") + ".</div>")
    return ((CSS if css else "") + '<div class="ca">' + _hero(cert, worst, flag_count, (filled, len(every)))
            + _fingerprint(cert, by_column) + _shape_strip(family, against)
            + f'<div class="twin">{_timeline(cert, now)}{_key_meter(cert)}</div>'
            + f'<div class="grid">{body}</div></div>')

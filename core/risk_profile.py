"""Unified Digital Risk Profile and Domain Infrastructure Fingerprint (DIF) generator."""
import hashlib
import re

import pandas as pd

from config import SEVERITY_WEIGHTS
from core.cert_utils import cert_alt_names, cert_is_self_signed, weak_key_mask
from core.helpers import safe_bool
from core.intel_data import INFORMATIONAL_RULES
from integrations.enrichment import unwrap_value

VECTOR_COLUMNS = ["Domain Risk Score", "DNS Volatility", "Certificate Trust", "Email/Phish Posture", "App & C2 Footprint", "Infra Sprawl"]

# --- DIF codes (segment 1 hosting, 2 TLS, 3 identity & apps, 4 configuration hash) ---
FLUX_CODES = {"P": "Parked / no resolved IPs", "S": "Static host (1-2 IPs)", "F": "Dynamic / fast-flux (3+ IPs)"}
SERVER_CODES = {"CF": "Cloudflare", "AW": "Amazon", "NX": "Nginx", "UN": "Unidentified server / VPS"}
VALIDATION_CODES = {"DV": "Domain Validated", "OV": "Organization Validated", "EV": "Extended Validation",
                    "NA": "Validation not reported", "UN": "Unknown validation"}
ISSUER_CODES = {"LE": "Let's Encrypt", "ZS": "ZeroSSL", "SS": "Self-signed", "UN": "Other / unknown CA"}
KEY_CODES = {"R": "RSA", "E": "EC"}
APPS_CODES = {
    "EM": "SPF email routing (checked first)",
    "GW": "Google Workspace (Google verification, no SPF)",
    "MS": "Microsoft 365 (MS= verification, no SPF or Google)",
    "NO": "No enterprise services (disposable / staging indicator)",
}
DIF_SEGMENTS = [
    # (segment, format, code, meaning, derived from)
    *[("1 Hosting", "<flux>-<server>", f"{code}-..", meaning, "Distinct A/AAAA IPs in passive DNS")
      for code, meaning in FLUX_CODES.items()],
    *[("1 Hosting", "<flux>-<server>", f"..-{code}", meaning, "Iris web server type") for code, meaning in SERVER_CODES.items()],
    *[("2 TLS", "<validation><issuer>-<key>", f"{code}....", meaning, "Validation level of the primary certificate")
      for code, meaning in VALIDATION_CODES.items()],
    *[("2 TLS", "<validation><issuer>-<key>", f"..{code}..", meaning, "Issuer of the primary certificate")
      for code, meaning in ISSUER_CODES.items()],
    ("2 TLS", "<validation><issuer>-<key>", "..-R2048", "Key type (R = RSA, E = EC) and size (U = unknown)",
     "Certificate public key"),
    ("2 TLS", "NOCERT", "NOCERT", "No certificate observed", "Certificate sources"),
    *[("3 Identity & Apps", "<code>", code, meaning, "TXT records in passive DNS") for code, meaning in APPS_CODES.items()],
    ("4 Config Hash", "<6 hex>", "e.g. 3fa91c", "Same hash on different domains = identical backend setup",
     "IP count, server type, primary certificate issuer, validation, key and names, TXT records"),
]
# Validity days are no longer part of the TLS block (renewals and lifetime changes would change the DIF);
# the optional <days> group still decodes fingerprints saved by earlier versions.
_TLS_BLOCK_RE = re.compile(r"^(?P<val>[^-]{1,2}?)(?P<iss>LE|ZS|SS|UN)(?P<dur>\d+|U)?-(?P<key>[RE]\d+|U)$")

# Risk vector -> (alert pattern on ATT&CK id / threat type, what else raises it)
VECTOR_RULES = {
    "DNS Volatility": ("T1568|Flux|Rotation|Parked|Sinkhole", "many IPs in passive DNS"),
    "Certificate Trust": ("T1588.004|T1573|Certificate|Weak", "self-signed or weak-key certificates"),
    "Email/Phish Posture": ("T1583.002|T1585.002|Phish|SPF|Mail", "many mail and TXT records"),
    "App & C2 Footprint": ("T1071|T1008|T1048|T1090.003|T1572|Proxy Exit|Anonymizer Exit|Bare-IP|Payload|JA4X", "C2-style findings, VPN / proxy / Tor hosting"),
    "Infra Sprawl": ("T1584.001|Sprawl|Nested|Wildcard", "certificates with many names"),
}
BASE_WEIGHT, VECTOR_WEIGHT = 0.4, 1.5 / len(VECTOR_RULES)   # Unified Risk = 0.4 x base + 1.5 x the vectors' mean

_IP_FIELDS = ["A", "IP", "A RECORD", "AAAA"]
_MAIL_FIELDS = ["TXT", "SPF", "MX"]


def _matching_alerts(dom_alerts, pattern):
    if dom_alerts.empty:
        return dom_alerts
    dom_alerts = dom_alerts[~dom_alerts["Threat Type"].isin(INFORMATIONAL_RULES)]
    return dom_alerts[
        dom_alerts["MITRE ATT&CK"].astype(str).str.contains(pattern, case=False, na=False)
        | dom_alerts["Threat Type"].astype(str).str.contains(pattern, case=False, na=False)
    ]


def _max_severity(dom_alerts, pattern):
    matches = _matching_alerts(dom_alerts, pattern)
    return max((SEVERITY_WEIGHTS.get(s, 0) for s in matches["Severity"]), default=0) if not matches.empty else 0


def _base_score(r_df, dom):
    if r_df.empty:
        return 0.0
    dom_risk = r_df[(r_df["Domain"] == dom) & (r_df["Component"] == "Overall Risk")]
    if dom_risk.empty:
        return 0.0
    score = pd.to_numeric(dom_risk["Score"].iloc[0], errors="coerce")
    return 0.0 if pd.isna(score) else float(score)


def _hosting_description(ip_count, srv):
    if ip_count == 0:
        flux_desc = "Parked / Zero Resolved IPs"
    elif ip_count <= 2:
        flux_desc = f"Static Single/Dual Host ({ip_count} IP{'s' if ip_count != 1 else ''})"
    else:
        flux_desc = f"Dynamic / Multi-IP Fast-Flux ({ip_count} distinct IPs)"

    srv_upper = srv.upper()
    if "CLOUDFLARE" in srv_upper:
        host_desc = "Cloudflare CDN / Proxy"
    elif "AMAZON" in srv_upper or "AWS" in srv_upper:
        host_desc = "Amazon Web Services (AWS Cloud)"
    elif "NGINX" in srv_upper:
        host_desc = "Nginx Web Server"
    elif "APACHE" in srv_upper:
        host_desc = "Apache HTTP Server"
    elif srv:
        host_desc = f"{srv.title()} Host"
    else:
        host_desc = "Custom / Unidentified VPS"
    return f"Hosting: {flux_desc} on {host_desc}"


def _issuer_description(issuer_raw, is_ss):
    issuer_lower = issuer_raw.lower()
    if is_ss:
        return "Self-Signed"
    if any(x in issuer_lower for x in ["let's encrypt", "letsencrypt"]):
        return "Let's Encrypt (Automated ACME)"
    if "zerossl" in issuer_lower:
        return "ZeroSSL (Automated ACME)"
    if any(x in issuer_lower for x in ["pki.goog", "google"]):
        return "Google Trust Services"
    if any(x in issuer_lower for x in ["digicert", "thawte", "geotrust"]):
        return "DigiCert Inc"
    if any(x in issuer_lower for x in ["sectigo", "comodo"]):
        return "Sectigo / Comodo"
    if any(x in issuer_lower for x in ["amazon", "awstrust"]):
        return "Amazon Trust Services"
    return issuer_raw[:28] if issuer_raw else "Third-Party Public CA"


def _crypto_block_and_description(cert):
    """
    Returns (DIF TLS block, human description, certificate profile) for the primary certificate. The block and the
    profile (fed into the configuration hash) leave out validity and the certificate hash, so renewals and shorter
    lifetimes do not change the DIF; the description still shows the validity.
    """
    is_ss = cert_is_self_signed(cert)
    val_raw = str(cert.get("Validation Level") or "unknown").lower()
    issuer_raw = str(cert.get("Issuer") or "").strip()
    issuer_upper = issuer_raw.upper()
    iss_tag = "LE" if "LET'S ENCRYPT" in issuer_upper else ("ZS" if "ZEROSSL" in issuer_upper else ("SS" if is_ss else "UN"))
    dur_num = pd.to_numeric(cert.get("Duration"), errors="coerce")
    bits_num = pd.to_numeric(cert.get("Public Key Bits"), errors="coerce")
    algo_val = str(cert.get("Public Key Algo") or "RSA").upper()
    algo_tag = "E" if "EC" in algo_val else "R"
    key_tag = f"{algo_tag}{int(bits_num)}" if pd.notna(bits_num) else "U"
    block = f"{val_raw.upper()[:2]}{iss_tag}-{key_tag}"
    profile = "|".join([issuer_raw.lower(), val_raw, key_tag, ",".join(sorted(n.lower() for n in cert_alt_names(cert)))])

    val_labels = {"dv": "Domain Validated (DV)", "ov": "Organization Validated (OV)", "ev": "Extended Validation (EV)"}
    val_desc = "Self-Signed (Untrusted / Private)" if is_ss else val_labels.get(val_raw, "Standard Validation")
    dur_desc = f"{int(dur_num)}-day validity" if pd.notna(dur_num) else "Unknown validity"
    key_desc = f"{int(bits_num)}-bit {algo_val}" if pd.notna(bits_num) else f"{algo_val} Key"
    desc = f"TLS: {val_desc} issued by {_issuer_description(issuer_raw, is_ss)} ({dur_desc}, {key_desc})"
    return block, desc, profile


def _apps_block_and_description(txt_joined):
    block = "EM" if "SPF1" in txt_joined else ("GW" if "GOOGLE" in txt_joined else ("MS" if "MS=MS" in txt_joined else "NO"))
    if "MS=MS" in txt_joined or "PROTECTION.OUTLOOK.COM" in txt_joined:
        desc = "Identity & Apps: Microsoft 365 & Azure AD Configured"
    elif "GOOGLE-SITE-VERIFICATION" in txt_joined or "GOOGLE" in txt_joined:
        desc = "Identity & Apps: Google Workspace Cloud Suite Integrated"
    elif "V=SPF1" in txt_joined:
        desc = "Identity & Apps: Active SPF Email Routing Only"
    else:
        desc = "Identity & Apps: Zero Enterprise Services (Disposable / Staging Indicator)"
    return block, desc


def generate_digital_risk_profile(domains, t_df, r_df, s_df, p_df, enr_map):
    """Calculates unified risk vectors and generates 4-block DIF fingerprints per domain."""
    t_df = t_df if t_df is not None else pd.DataFrame()
    r_df = r_df if r_df is not None else pd.DataFrame()
    s_df = s_df if s_df is not None else pd.DataFrame()
    p_df = p_df if p_df is not None else pd.DataFrame()
    enr_map = enr_map or {}
    profiles = []

    for dom in domains:
        base_score = _base_score(r_df, dom)
        dom_alerts = t_df[t_df["Domain"] == dom] if not t_df.empty else pd.DataFrame()
        dom_pdns = p_df[p_df["Domain"] == dom] if not p_df.empty else pd.DataFrame()
        dom_ssl = s_df[s_df["Domain"] == dom] if not s_df.empty else pd.DataFrame()
        pdns_fields = dom_pdns["Field"].astype(str).str.upper() if not dom_pdns.empty else pd.Series(dtype=str)

        ip_count = dom_pdns.loc[pdns_fields.isin(_IP_FIELDS), "Value"].nunique() if not dom_pdns.empty else 0
        vec_dns = min(100, _max_severity(dom_alerts, VECTOR_RULES["DNS Volatility"][0]) + min(40, ip_count * 2))

        raw_crypto_penalty = 0
        if not dom_ssl.empty:
            if "Is Self Signed" in dom_ssl.columns and dom_ssl["Is Self Signed"].map(safe_bool).any():
                raw_crypto_penalty += 40
            if weak_key_mask(dom_ssl).any():
                raw_crypto_penalty += 40
        vec_certificate = min(100, _max_severity(dom_alerts, VECTOR_RULES["Certificate Trust"][0]) + raw_crypto_penalty)

        txt_count = dom_pdns.loc[pdns_fields.isin(_MAIL_FIELDS), "Value"].nunique() if not dom_pdns.empty else 0
        vec_email = min(100, _max_severity(dom_alerts, VECTOR_RULES["Email/Phish Posture"][0]) + min(30, txt_count * 5))

        vec_c2 = min(100, _max_severity(dom_alerts, VECTOR_RULES["App & C2 Footprint"][0]))

        max_sans = 0
        if not dom_ssl.empty and "SAN Count" in dom_ssl.columns:
            max_sans = pd.to_numeric(dom_ssl["SAN Count"], errors="coerce").max()
            max_sans = 0 if pd.isna(max_sans) else max_sans
        vec_sprawl = min(100, _max_severity(dom_alerts, VECTOR_RULES["Infra Sprawl"][0]) + min(50, max_sans * 2))

        active_avg = (vec_dns + vec_certificate + vec_email + vec_c2 + vec_sprawl) / 5
        unified_score = min(100, max(base_score, int((base_score * BASE_WEIGHT) + (active_avg * 1.5))))

        # --- DIF block 1: hosting ---
        srv = str(unwrap_value(enr_map.get(dom, {}).get("server_type")) or "").strip()
        flux_tag = "P" if ip_count == 0 else ("S" if ip_count <= 2 else "F")
        srv_upper = srv.upper()
        ns_tag = "CF" if "CLOUDFLARE" in srv_upper else ("AW" if "AMAZON" in srv_upper else ("NX" if "NGINX" in srv_upper else "UN"))
        block1 = f"{flux_tag}-{ns_tag}"

        # --- DIF block 2: TLS ---
        if dom_ssl.empty:
            block2, desc_crypto, cert_profile = "NOCERT", "TLS: No Certificate (Unencrypted Cleartext / Insecure)", ""
        else:
            block2, desc_crypto, cert_profile = _crypto_block_and_description(dom_ssl.iloc[0])

        # --- DIF block 3: identity & apps ---
        txt_values = dom_pdns.loc[pdns_fields.str.contains("TXT", na=False), "Value"] if not dom_pdns.empty else []
        txt_joined = " ".join(str(v) for v in txt_values).upper()
        block3, desc_app = _apps_block_and_description(txt_joined)

        fingerprint_hash = hashlib.sha256(f"{ip_count}-{srv_upper}-{cert_profile}-{txt_joined}".encode("utf-8")).hexdigest()[:6]

        profiles.append({
            "Domain": dom,
            "Unified Risk": unified_score,
            "Base Domain Risk Score": round(base_score),
            "DIF Fingerprint": f"{block1}_{block2}_{block3}_{fingerprint_hash}",
            "DIF Breakdown": f"{_hosting_description(ip_count, srv)} | {desc_crypto} | {desc_app}",
            "Domain Risk Score": base_score,
            "DNS Volatility": vec_dns,
            "Certificate Trust": vec_certificate,
            "Email/Phish Posture": vec_email,
            "App & C2 Footprint": vec_c2,
            "Infra Sprawl": vec_sprawl,
        })
    return pd.DataFrame(profiles)


def _decode_tls(block):
    if block == "NOCERT":
        return "No certificate"
    match = _TLS_BLOCK_RE.match(block)
    if not match:
        return block
    key = match["key"]
    key_text = "unknown key" if key == "U" else f"{KEY_CODES.get(key[0], key[0])} {key[1:]}-bit"
    validation = VALIDATION_CODES.get(match["val"], match["val"])
    parts = [validation, ISSUER_CODES.get(match["iss"], match["iss"])]
    if match["dur"] is not None:   # fingerprints saved by earlier versions carried the validity
        parts.append("unknown validity" if match["dur"] == "U" else f"{match['dur']}-day validity")
    return ", ".join(parts + [key_text])


def decode_dif(fingerprint):
    """Plain-language meaning of each DIF segment (hosting, TLS, identity & apps, configuration hash)."""
    parts = str(fingerprint or "").split("_")
    if len(parts) != 4:
        return {"Hosting": "", "TLS": "", "Identity & Apps": "", "Config Hash": str(fingerprint or "")}
    hosting, tls, apps, config_hash = parts
    flux, _, server = hosting.partition("-")
    return {
        "Hosting": f"{FLUX_CODES.get(flux, flux)} on {SERVER_CODES.get(server, server)}",
        "TLS": _decode_tls(tls),
        "Identity & Apps": APPS_CODES.get(apps, apps),
        "Config Hash": config_hash,
    }


def decode_profiles(profiles):
    """One row per domain: its DIF decoded, plus other domains sharing the same DIF or configuration hash."""
    if profiles is None or profiles.empty:
        return pd.DataFrame(columns=["Domain", "DIF Fingerprint", "Hosting", "TLS", "Identity & Apps", "Config Hash", "Same DIF As"])
    rows = []
    for _, row in profiles.iterrows():
        fingerprint = row["DIF Fingerprint"]
        same = profiles.loc[(profiles["DIF Fingerprint"] == fingerprint) & (profiles["Domain"] != row["Domain"]), "Domain"]
        rows.append({"Domain": row["Domain"], "DIF Fingerprint": fingerprint, **decode_dif(fingerprint),
                     "Same DIF As": ", ".join(sorted(same))})
    return pd.DataFrame(rows)


def score_drivers(profile, alerts, limit=3):
    """
    What drove one domain's Unified Risk: [(points, text)], largest first. Points are each part's share of the score
    (0.4 x the DomainTools risk score, 0.3 x each risk vector); a vector names its most severe matching alert.
    When the DomainTools score alone is higher than the computed score, it sets the score and is the only driver.
    """
    base = float(profile.get("Domain Risk Score") or 0)
    dom_alerts = alerts[alerts["Domain"] == profile["Domain"]] if alerts is not None and not alerts.empty else pd.DataFrame()
    parts = [(base * BASE_WEIGHT, f"DomainTools risk score {base:.0f}")] if base else []
    for vector, (pattern, otherwise) in VECTOR_RULES.items():
        value = float(profile.get(vector) or 0)
        if not value:
            continue
        matches = _matching_alerts(dom_alerts, pattern)
        if not matches.empty:
            top = matches.assign(_w=matches["Severity"].map(SEVERITY_WEIGHTS).fillna(0)).sort_values("_w").iloc[-1]
            why = f"{top['Threat Type']} ({top['Severity']})"
        else:
            why = otherwise
        parts.append((value * VECTOR_WEIGHT, f"{vector}: {why}"))
    computed = sum(points for points, _ in parts)
    if base and base >= computed:
        return [(round(base), f"DomainTools risk score {base:.0f} (higher than the telemetry score, so it sets the score)")]
    return sorted(((round(points), text) for points, text in parts if round(points) > 0), reverse=True)[:limit]


def drivers_text(drivers):
    return " · ".join(f"+{points} {text}" for points, text in drivers)

"""Certificate attribute helpers shared by the threat engine, risk profile, and SSL views."""
import re

import pandas as pd

from core.helpers import is_ip_address, optional_bool, safe_bool

AUTOMATED_CA_MARKERS = ("let's encrypt", "letsencrypt", "zerossl", "we1", "cpanel", "cloudflare", "google trust services")
# Issuer name fragments (CN / O / DN, lowercase) of publicly trusted CAs and their intermediates
PUBLIC_CA_MARKERS = (
    "let's encrypt", "letsencrypt", "isrg", "digicert", "geotrust", "thawte", "rapidssl", "sectigo", "comodo", "usertrust",
    "globalsign", "godaddy", "go daddy", "starfield", "entrust", "amazon", "google trust services", "gts ca", "zerossl",
    "buypass", "certum", "identrust", "ssl.com", "actalis", "harica", "quovadis", "swisssign", "telia", "trustasia",
    "certainly", "microsoft azure", "microsoft rsa tls", "apple public", "network solutions", "cloudflare inc ecc ca",
    "trustwave", "secom", "gandi", "cpanel", "encryption everywhere",
)
# Bare intermediate common names used without an organization in some sources (Let's Encrypt, Google Trust Services)
PUBLIC_CA_CN_PATTERN = re.compile(r"^(?:r\d{1,2}|e\d{1,2}|w[er]\d|wr\d|we\d|gts ca \w+)$")
CABF_POLICY_PREFIX = "2.23.140.1."

MIN_RSA_BITS = 2048
MIN_EC_BITS = 224


def is_weak_public_key(bits, algorithm=""):
    """RSA/DSA keys < 2048 bits or EC keys < 224 bits are weak. Unknown sizes are not flagged."""
    bits_num = pd.to_numeric(bits, errors="coerce")
    if pd.isna(bits_num) or bits_num <= 0:
        return False
    algo = str(algorithm or "").upper()
    if "EC" in algo or "ED25519" in algo or "ED448" in algo:
        return bits_num < MIN_EC_BITS
    return bits_num < MIN_RSA_BITS


def weak_key_mask(df):
    """Vectorized weak-key mask for a certificate DataFrame."""
    if df.empty or "Public Key Bits" not in df.columns:
        return pd.Series(False, index=df.index)
    algos = df["Public Key Algo"] if "Public Key Algo" in df.columns else pd.Series("", index=df.index)
    return pd.Series([is_weak_public_key(b, a) for b, a in zip(df["Public Key Bits"], algos)], index=df.index)


def cert_duration_days(cert):
    """Validity in days from the API's duration field, falling back to Not After - Not Before."""
    duration = pd.to_numeric(cert.get("Duration"), errors="coerce")
    if pd.notna(duration):
        return float(duration)
    not_before = pd.to_datetime(cert.get("Not Before Date"), errors="coerce")
    not_after = pd.to_datetime(cert.get("Not After Date"), errors="coerce")
    if pd.notna(not_before) and pd.notna(not_after):
        return float((not_after - not_before).days)
    return None


def cert_is_self_signed(cert):
    """Explicit self-signed flag, falling back to Subject CN == Issuer CN."""
    if safe_bool(cert.get("Is Self Signed")):
        return True
    cn = str(cert.get("Common Name") or "").strip().lower()
    issuer = str(cert.get("Issuer") or "").strip().lower()
    return bool(cn) and cn == issuer


def cert_flag(cert, key):
    """Tri-state flag lookup (True/False/None when the source does not provide the field)."""
    return optional_bool(cert.get(key))


def cert_alt_names(cert):
    sans = cert.get("Alt Names List")
    return [str(s).strip() for s in sans if str(s).strip()] if isinstance(sans, list) else []


def cert_ip_names(cert):
    """IP addresses present in a certificate CN or SANs."""
    names = [str(cert.get("Common Name") or "").strip()] + cert_alt_names(cert)
    found = []
    for name in names:
        if is_ip_address(name) and name not in found:
            found.append(name)
    return found


def publicly_trusted(cert):
    """
    Whether a certificate looks publicly trusted (CAA only binds public CAs):
    True  - embedded SCTs, a CA/B Forum policy OID, a DV/OV/EV validation level, or a recognized public CA issuer;
    False - self-signed, or the source explicitly reports no embedded SCTs and nothing indicates a public CA;
    None  - not enough information (e.g. Domain History / Iris snapshots with an unrecognized issuer).
    """
    if cert_is_self_signed(cert):
        return False
    if cert_flag(cert, "Has Embedded SCTs") is True:
        return True
    policies = cert.get("Certificate Policy")
    if isinstance(policies, list) and any(
        str((p.get("policy_oid") if isinstance(p, dict) else p) or "").startswith(CABF_POLICY_PREFIX) for p in policies
    ):
        return True
    if str(cert.get("Validation Level") or "").strip().lower() in ("dv", "ov", "ev"):
        return True
    issuer_cn = str(cert.get("Issuer") or "").strip().lower()
    issuer_text = " ".join(str(cert.get(k) or "").lower() for k in ("Issuer", "Issuer Org", "Issuer DN"))
    if any(marker in issuer_text for marker in PUBLIC_CA_MARKERS) or PUBLIC_CA_CN_PATTERN.match(issuer_cn):
        return True
    if cert_flag(cert, "Has Embedded SCTs") is False:
        return False
    return None


def is_automated_ca(issuer):
    issuer_lower = str(issuer or "").lower()
    return any(marker in issuer_lower for marker in AUTOMATED_CA_MARKERS)

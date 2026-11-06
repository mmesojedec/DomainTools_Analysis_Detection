"""CAA (RFC 8659) record parsing and certificate issuer authorization checks."""
import re
from dataclasses import dataclass, field

import pandas as pd

from core.helpers import safe_bool

KNOWN_CA_ALIASES = {
    "digicert.com": ["digicert", "thawte", "geotrust", "rapidssl"],
    "comodoca.com": ["comodo", "sectigo"],
    "sectigo.com": ["sectigo", "comodo"],
    "pki.goog": ["google", "gts", "pki.goog"],
    "google.com": ["google", "gts", "pki.goog"],
    "letsencrypt.org": ["let's encrypt", "letsencrypt", "isrg"],
    "awstrust.com": ["amazon", "aws", "starfield"],
    "amazontrust.com": ["amazon", "aws", "starfield"],
    "amazonaws.com": ["amazon", "aws", "starfield"],
    "amazon.com": ["amazon", "aws", "starfield"],
    "certainly.com": ["certainly"],
    "globalsign.com": ["globalsign"],
    "godaddy.com": ["godaddy", "starfield"],
    "identrust.com": ["identrust"],
    "zerossl.com": ["zerossl"],
    "buypass.com": ["buypass"],
    "quovadisglobal.com": ["quovadis"],
    "entrust.net": ["entrust"],
    "entrust.com": ["entrust"],
    "ssl.com": ["ssl.com", "ssl corp"],
    "actalis.it": ["actalis"],
}

_CAA_PATTERN = re.compile(r'^\s*(\d+)\s+["\']?([a-zA-Z0-9]+)["\']?\s+["\']?([^"\'\r\n]*)["\']?')


@dataclass
class CaaPolicy:
    """Effective CAA policy for one domain name."""
    auth_issue: set = field(default_factory=set)
    auth_wild: set = field(default_factory=set)
    has_issue_tag: bool = False
    has_issuewild_tag: bool = False
    iodef_contacts: list = field(default_factory=list)
    records: list = field(default_factory=list)

    @property
    def has_policy(self):
        return self.has_issue_tag or self.has_issuewild_tag

    @property
    def issue_forbidden(self):
        """`issue ";"` with no CA listed: no CA may issue non-wildcard certificates."""
        return self.has_issue_tag and not self.auth_issue

    @property
    def wild_forbidden(self):
        """Wildcards are forbidden by an empty `issuewild` set, or by an empty `issue` set when `issuewild` is absent."""
        if self.has_issuewild_tag:
            return not self.auth_wild
        return self.issue_forbidden


def _first_present(*values):
    for value in values:
        if value is not None and not pd.isna(value):
            return value
    return None


def parse_caa_entry(raw_str):
    """
    Parses a single CAA record string into a structured dict (RFC 8659).
    Handles patterns like: 0 issue "digicert.com", 0 issuewild ";", 0 iodef "mailto:security@..."
    """
    if not raw_str or not isinstance(raw_str, str):
        return None
    m = _CAA_PATTERN.match(raw_str.strip())
    if not m:
        return None
    flag, tag, val = m.groups()
    return {"flag": int(flag), "tag": tag.lower(), "value": val.strip().strip('"').strip("'").strip()}


def caa_issuer_domain(value):
    """Returns the CA domain of an issue/issuewild value ('' for the empty ';' value)."""
    return str(value or "").split(";", 1)[0].strip().lower()


def extract_domain_caa_policy(pdns_df, domain):
    """
    Builds the CAA policy for `domain` from passive DNS / domain history rows.
    Only rows whose RRName is the domain itself are used, so subdomain CAA records
    returned by wildcard queries do not leak into the apex policy.
    """
    policy = CaaPolicy()
    if pdns_df is None or pdns_df.empty or "Field" not in pdns_df.columns or "Domain" not in pdns_df.columns:
        return policy

    dom_clean = str(domain).lower().strip()
    fields = pdns_df["Field"].astype(str).str.upper().str.replace(r"^(?:PDNS|DH):\s*", "", regex=True)
    mask = (pdns_df["Domain"].astype(str).str.lower() == dom_clean) & (fields == "CAA")
    if "RRName" in pdns_df.columns:
        rrnames = pdns_df["RRName"].astype(str).str.lower().str.rstrip(".")
        mask &= pdns_df["RRName"].isna() | (rrnames == dom_clean) | (rrnames == "") | (rrnames == "nan")
    caa_rows = pdns_df[mask]

    for _, row in caa_rows.iterrows():
        first_seen = _first_present(row.get("First Seen"), row.get("Date"))
        last_seen = _first_present(row.get("Last Seen"), row.get("Date"))
        for line in str(row.get("Value", "")).split("\n"):
            parsed = parse_caa_entry(line)
            if not parsed:
                continue
            parsed["First Seen"] = first_seen
            parsed["Last Seen"] = last_seen
            policy.records.append(parsed)

            tag, val = parsed["tag"], parsed["value"]
            if tag == "issue":
                policy.has_issue_tag = True
                ca_domain = caa_issuer_domain(val)
                if ca_domain:
                    policy.auth_issue.add(ca_domain)
            elif tag == "issuewild":
                policy.has_issuewild_tag = True
                ca_domain = caa_issuer_domain(val)
                if ca_domain:
                    policy.auth_wild.add(ca_domain)
            elif tag == "iodef" and val and val not in policy.iodef_contacts:
                policy.iodef_contacts.append(val)

    return policy


CAA_COVERAGE_LABELS = {
    "checked": "CAA queried directly",
    "complete": "Full pDNS results",
    "incomplete": "pDNS results incomplete",
}


def caa_coverage_status(coverage, domain):
    """
    How much an absent CAA record can be trusted for `domain`:
    'checked'    - a dedicated CAA lookup succeeded;
    'complete'   - the main pDNS query returned all records (not truncated);
    'incomplete' - truncated / failed / unknown, so 'no CAA seen' does not mean 'no CAA policy'.
    """
    entry = (coverage or {}).get(domain)
    if entry and entry.get("caa_checked"):
        return "checked"
    if entry and not entry.get("truncated"):
        return "complete"
    return "incomplete"


def cert_is_wildcard(cert):
    """True when the certificate covers a wildcard name (flag, CN, or any SAN)."""
    if safe_bool(cert.get("Has Wildcard SAN")):
        return True
    if str(cert.get("Common Name") or "").strip().startswith("*."):
        return True
    sans = cert.get("Alt Names List")
    return isinstance(sans, list) and any(str(s).strip().startswith("*.") for s in sans)


def is_issuer_authorized_by_caa(cert, policy):
    """
    Validates a certificate against the domain's CAA policy.
    Returns (is_authorized: bool, reason: str, matched_ca: str or None).
    """
    if not policy.has_policy:
        return True, "No restricting CAA policy enforced", None

    is_wildcard = cert_is_wildcard(cert)
    if is_wildcard:
        if policy.wild_forbidden:
            return False, "Wildcard certificates are prohibited by policy (`issuewild \";\"`).", None
        applicable_cas = policy.auth_wild if policy.has_issuewild_tag else policy.auth_issue
    else:
        if policy.issue_forbidden:
            return False, "Certificate issuance is prohibited by policy (`issue \";\"`).", None
        if not policy.has_issue_tag:
            return True, "Only issuewild is restricted; non-wildcard issuance unrestricted", None
        applicable_cas = policy.auth_issue

    issuer_text = " ".join(
        str(cert.get(key) or "").lower() for key in ("Issuer DN", "Issuer", "Issuer Org", "Issuer OU")
    )
    for ca_dom in sorted(applicable_cas):
        if ca_dom in issuer_text:
            return True, f"Authorized by CAA entry: {ca_dom}", ca_dom
        base_label = ca_dom.split(".")[0]
        if len(base_label) >= 4 and base_label in issuer_text:
            return True, f"Authorized by CAA brand: {base_label}", ca_dom
        for alias in KNOWN_CA_ALIASES.get(ca_dom, []):
            if alias in issuer_text:
                return True, f"Authorized by CA alias: {alias} ({ca_dom})", ca_dom

    return False, f"Issuer not listed in authorized CAs ({', '.join(sorted(applicable_cas))})", None

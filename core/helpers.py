"""Core text, string, and domain utility functions."""
import ipaddress
import math
import re
from collections import Counter

try:
    import tldextract
    # suffix_list_urls=() uses the bundled Public Suffix List snapshot (no network access at runtime)
    _TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
except ImportError:  # pragma: no cover - exercised only when tldextract is missing
    _TLD_EXTRACTOR = None

# Minimal multi-label suffix fallback used only when tldextract is unavailable
_FALLBACK_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp",
    "com.br", "com.cn", "com.mx", "co.in", "co.za", "com.tr", "com.ar", "com.sg", "com.hk", "co.kr",
}

_IPV4_PATTERN = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_MARKDOWN_SPECIALS = re.compile(r"([\\`*_{}\[\]()#+!|~<>$])")


def calculate_shannon_entropy(data_string):
    """Calculates the Shannon Entropy of a string to detect DGA/randomness."""
    if not data_string:
        return 0
    entropy = 0
    for count in Counter(data_string).values():
        p_x = float(count) / len(data_string)
        entropy -= p_x * math.log(p_x, 2)
    return entropy


def safe_bool(value, default=False):
    """Converts a possibly-missing value to bool. NaN/None/NaT return `default` (bool(NaN) is True in Python)."""
    flag = optional_bool(value)
    return default if flag is None else flag


def optional_bool(value):
    """Returns True/False for explicit boolean-like values, or None when the value is missing."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and math.isnan(value):
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes", "y"):
            return True
        if lowered in ("false", "0", "no", "n", ""):
            return False
        return None
    if isinstance(value, (list, tuple, set, dict)):
        return None
    try:
        import pandas as pd
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    return bool(value)


def refang_domain(domain_str):
    """Refangs defanged input and strips protocols, credentials, paths, ports, and trailing dots."""
    if not domain_str:
        return ""
    domain_str = str(domain_str).strip()
    domain_str = re.sub(r"^(?:hxxps?|https?|fxp|ftp)\[?:\]?//", "", domain_str, flags=re.IGNORECASE)
    for dot in ["[.]", "(.)", "{.}", "[dot]", "(dot)", "{dot}"]:
        domain_str = domain_str.replace(dot, ".")
    domain_str = domain_str.replace("[:]", ":")
    for char in ["[", "]", "(", ")", "{", "}"]:
        domain_str = domain_str.replace(char, "")
    domain_str = re.split(r"[/?#]", domain_str, maxsplit=1)[0]
    if "@" in domain_str:
        domain_str = domain_str.rsplit("@", 1)[1]
    # Strip a port only for host:port (IPv6 addresses contain several colons)
    if domain_str.count(":") == 1:
        domain_str = domain_str.split(":", 1)[0]
    return domain_str.strip().rstrip(".").lower()


def is_ip_address(val):
    """Returns True if the string is a valid IPv4 or IPv6 address."""
    if not val:
        return False
    try:
        ipaddress.ip_address(str(val).strip())
        return True
    except ValueError:
        return False


def normalize_cidr(value):
    """'104.21.59.7/24' -> '104.21.59.0/24' (IPv4 or IPv6 network in CIDR notation), or None when it is not one."""
    text = str(value or "").strip()
    if "/" not in text:
        return None
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        return None


def is_cidr(value):
    return normalize_cidr(value) is not None


def classify_targets(targets):
    """
    Classifies clean targets into domains, IPv4 addresses, IPv6 addresses and CIDR ranges (order preserved,
    deduplicated). CIDR ranges are looked up in VPNDB only; the other sources take single addresses.
    """
    domains, ipv4s, ipv6s, cidrs = [], [], [], []
    for t in targets:
        t_clean = str(t).strip()
        network = normalize_cidr(t_clean)
        if network:
            if network not in cidrs:
                cidrs.append(network)
            continue
        try:
            ip = ipaddress.ip_address(t_clean)
            bucket = ipv4s if ip.version == 4 else ipv6s
            if str(ip) not in bucket:
                bucket.append(str(ip))
        except ValueError:
            clean_dom = t_clean.lower()
            if clean_dom and clean_dom not in domains:
                domains.append(clean_dom)
    return {"domains": domains, "ipv4": ipv4s, "ipv6": ipv6s, "cidrs": cidrs}


def parse_raw_domain_inputs(raw_inputs):
    """Parses multiline or comma-separated domains/IPs into a clean, unique list."""
    targets = []
    for item in re.split(r"[\s,;]+", raw_inputs or ""):
        clean = refang_domain(item)
        if clean and clean not in targets:
            targets.append(clean)
    return targets


def registrable_domain(hostname):
    """Returns the registrable domain (eTLD+1) for a hostname, e.g. www.example.co.uk -> example.co.uk."""
    host = str(hostname or "").strip().lower().lstrip("*.").rstrip(".")
    if not host or is_ip_address(host):
        return host
    if _TLD_EXTRACTOR is not None:
        parts = _TLD_EXTRACTOR(host)
        if parts.domain and parts.suffix:
            return f"{parts.domain}.{parts.suffix}"
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _FALLBACK_MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def normalize_to_apex(targets):
    """
    Maps domain targets to their registrable (apex) domain, deduplicated in order; IPs pass through unchanged.
    Lookups already cover subdomains (wildcard pDNS, include_subdomains cert events), while Domain History, Risk,
    and Iris Investigate only resolve registered domains. Returns (targets, conversions) with (original, apex) pairs.
    """
    normalized, conversions = [], []
    for target in targets:
        apex = target if is_ip_address(target) else registrable_domain(target)
        if apex != target:
            conversions.append((target, apex))
        if apex and apex not in normalized:
            normalized.append(apex)
    return normalized, conversions


def domain_core_label(hostname):
    """Returns the registrable label without suffix, e.g. www.example.co.uk -> example (used for entropy scoring)."""
    reg = registrable_domain(hostname)
    if not reg or is_ip_address(reg):
        return reg
    if _TLD_EXTRACTOR is not None:
        return _TLD_EXTRACTOR(reg).domain or reg.split(".")[0]
    return reg.split(".")[0]


def extract_ip_addresses(text):
    """Extracts valid IPv4 and IPv6 addresses from free text, in order of appearance without duplicates."""
    found = []
    raw = str(text or "")
    for match in _IPV4_PATTERN.findall(raw):
        if match not in found:
            found.append(match)
    for candidate in _IPV6_CANDIDATE.findall(raw):
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if ip.version == 6 and str(ip) not in found:
            found.append(str(ip))
    return found


def ip_network_bucket(ip_str):
    """Groups an IP into its /24 (IPv4) or /48 (IPv6) network for clustering."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return "Unknown"
    prefix = 24 if ip.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def hostname_matches(target, name):
    """True when `name` (CN or SAN, wildcards allowed) covers `target` or is a subdomain/parent of it."""
    target = str(target or "").strip().lower().rstrip(".")
    name_clean = str(name or "").strip().lower().rstrip(".").replace("*.", "")
    if not target or not name_clean:
        return False
    if name_clean == target:
        return True
    # Require a dotted name so bare labels such as "com" or "localhost" never match everything
    if "." not in name_clean:
        return False
    return target.endswith("." + name_clean) or name_clean.endswith("." + target)


def md_escape(text):
    """Escapes Markdown control characters (including `$`, which Streamlit renders as LaTeX)."""
    return _MARKDOWN_SPECIALS.sub(r"\\\1", str(text))


def lookup_name(text):
    """A source or collection name with the old "Supplement" wording as "Lookup" ("DNSDB TXT Supplement" ->
    "DNSDB TXT Lookup", "CAA supplement" -> "CAA lookup"), for datasets and cache entries saved before the rename."""
    if not isinstance(text, str):
        return text
    return text.replace(" Supplement", " Lookup").replace(" supplement", " lookup")

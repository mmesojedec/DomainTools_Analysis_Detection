"""
Target input recognition: domains and IPs as before, plus certificate inputs ("seeds") that are resolved to the
domains and IPs they cover. Certificate inputs are hashes (auto-detected), prefixed lines such as `cn:Acme VPN`, or free text that is neither a
domain nor an IP (e.g. `DomainTools LLC`), which is searched as a certificate organization.
Pure functions: building CertsQL queries and deriving targets from certificate records needs no API access.
"""
import ipaddress
import json
import re
from dataclasses import dataclass

import pandas as pd

from core.helpers import is_ip_address, normalize_cidr, refang_domain, registrable_domain
from core.idn import to_ascii
from core.network_intel import is_public_ip

# prefix -> (kind label, description); a prefixed line is read whole, so values may contain spaces
CERT_PREFIXES = {
    "sha256": ("SHA-256", "Certificate SHA-256 fingerprint"),
    "sha1": ("SHA-1", "Certificate SHA-1 fingerprint"),
    "md5": ("MD5", "Certificate MD5 fingerprint"),
    "spki": ("Public key", "Subject public key SHA-256 (finds every certificate reusing the key)"),
    "serial": ("Serial", "Certificate serial number"),
    "cn": ("CN", "Subject common name, exact match"),
    "cn~": ("CN contains", "Subject common name containing the text (3-63 characters)"),
    "san": ("SAN", "Subject Alternative Name: hostname, wildcard (*.example.com), or IP"),
    "org": ("Organization", "Subject organization, exact match"),
    "org~": ("Organization contains", "Subject organization containing the text (3-63 characters)"),
    "issuer": ("Issuer", "Issuer common name or organization, exact match"),
}
_PREFIX_RE = re.compile(r"^(sha256|sha1|md5|spki|serial|cn~|cn|san|org~|org|issuer)\s*:\s*(.+)$", re.IGNORECASE)
_HEX_LENGTHS = {64: "sha256", 40: "sha1", 32: "md5"}
# A 16- or 20-byte serial number has the same length as an MD5 / SHA-1 fingerprint, so auto-detected values of
# these lengths are searched as both (one CertsQL clause, either field may match)
AMBIGUOUS_WITH_SERIAL = frozenset({"md5", "sha1"})
MIN_SERIAL_HEX, MAX_SERIAL_HEX = 8, 42   # serials are at most 20 bytes, plus an optional leading 00
_HEX_RE = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)
_COLON_HEX_RE = re.compile(r"^(?:[0-9a-f]{2}:)+[0-9a-f]{2}$", re.IGNORECASE)
CONTAINS_MIN, CONTAINS_MAX = 3, 63   # CertsQL `contains` operand length

# Shared CDN / platform certificate names: their SANs list unrelated customers, so they are never derived as targets
SHARED_SAN_SUFFIXES = ("cloudflaressl.com", "cloudflare-dns.com", "fastly.net", "akamaiedge.net", "edgekey.net",
                       "azureedge.net", "cloudfront.net", "herokuapp.com", "googleusercontent.com")

DERIVED_COLUMNS = ["Analyze", "Target", "Type", "Via", "Hostnames", "Certificates", "Seeds", "Example Certificate"]
HOSTNAME_COLUMNS = ["Focus", "Hostname", "Apex", "Via", "Certificates", "Seeds"]


@dataclass(frozen=True)
class InputItem:
    kind: str            # "domain", "ip", "cidr", or a CERT_PREFIXES key
    value: str
    auto: bool = False   # kind inferred (hash length) rather than given by a prefix

    @property
    def is_certificate(self):
        return self.kind in CERT_PREFIXES

    @property
    def ambiguous(self):
        """Auto-detected value that may be a fingerprint or a serial number."""
        return self.auto and self.kind in AMBIGUOUS_WITH_SERIAL

    @property
    def kind_name(self):
        if not self.is_certificate:
            return {"ip": "IP", "cidr": "CIDR range"}.get(self.kind, "Domain")
        return f"{CERT_PREFIXES[self.kind][0]} or serial" if self.ambiguous else CERT_PREFIXES[self.kind][0]

    @property
    def label(self):
        """Stable text form, also used in run keys: the plain value for domains / IPs, `kind:value` for seeds."""
        return self.value if not self.is_certificate else f"{self.kind}:{self.value}"

    @property
    def display(self):
        if not self.is_certificate:
            return f"{'IP' if self.kind == 'ip' else 'Domain'}: {self.value}"
        value = self.value if len(self.value) <= 24 else f"{self.value[:12]}…{self.value[-8:]}"
        return f"{self.kind_name}{' (auto)' if self.auto else ''}: {value}"


def _clean_hex(token):
    token = token.strip()
    if token[:2].lower() == "0x":
        token = token[2:]
    if _COLON_HEX_RE.match(token):
        token = token.replace(":", "")
    return token.lower() if _HEX_RE.match(token) else None


def _classify_token(token):
    hex_value = _clean_hex(token)
    if hex_value and len(hex_value) in _HEX_LENGTHS:
        return InputItem(_HEX_LENGTHS[len(hex_value)], hex_value, auto=True)
    if hex_value and MIN_SERIAL_HEX <= len(hex_value) <= MAX_SERIAL_HEX:
        return InputItem("serial", hex_value, auto=True)   # dotless hex is never a domain: other lengths are serials
    if token.startswith("*."):
        return InputItem("san", to_ascii(token.lower().rstrip(".")))
    network = normalize_cidr(refang_domain(token.split("/", 1)[0]) + "/" + token.split("/", 1)[1]) \
        if token.count("/") == 1 else None
    if network:   # a CIDR range (VPNDB); a single-address range (/32, /128) is a plain IP
        address, size = network.split("/")
        return InputItem("ip", address) if int(size) == ipaddress.ip_address(address).max_prefixlen \
            else InputItem("cidr", network)
    clean = refang_domain(token)
    if is_ip_address(clean):
        return InputItem("ip", clean)
    # dotless words are not domains (see _text_item); Unicode names are looked up in their punycode (xn--) form
    return InputItem("domain", to_ascii(clean)) if "." in clean else None


def _text_item(text):
    """Free text (e.g. a company name): a certificate organization search, `contains` when the length allows it."""
    text = text.strip().strip('"').strip("'").strip()
    if not text:
        return None
    return InputItem("org~" if CONTAINS_MIN <= len(text) <= CONTAINS_MAX else "org", text, auto=True)


def _prefixed_value(kind, value):
    value = value.strip().strip('"').strip("'").strip()
    if kind in ("sha256", "sha1", "md5", "spki"):
        return _clean_hex(value) or value.lower()
    if kind == "serial":
        value = value.replace(":", "").replace(" ", "").lower()
        return value[2:] if value.startswith("0x") else value
    if kind == "san":
        return to_ascii(value.lower().rstrip("."))
    if kind in ("cn", "cn~") and "." in value and " " not in value:   # a hostname, as certificates store it
        return to_ascii(value)
    return value


def idn_conversions(raw):
    """(as typed, punycode) for every Unicode domain or hostname in the target box."""
    found = []
    for token in re.split(r"[\s,;]+", str(raw or "")):
        token = token.split(":", 1)[1] if _PREFIX_RE.match(token) else token
        if token and not token.isascii() and "." in token:
            ascii_name = to_ascii(refang_domain(token) if not token.startswith("*.") else token.lower())
            if ascii_name != token and (token, ascii_name) not in found:
                found.append((token, ascii_name))
    return found


def parse_inputs(raw):
    """
    Parses the target box: prefixed certificate lines whole, other lines split on spaces / commas into domains, IPs and
    hashes. Words that are none of these (e.g. `DomainTools LLC`) are kept together as one organization search.
    Deduplicated.
    """
    items = []
    for line in str(raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        match = _PREFIX_RE.match(line)
        if match:
            kind = match[1].lower()
            value = _prefixed_value(kind, match[2])
            candidates = [InputItem(kind, value)] if value else []
        else:
            tokens = [token for token in re.split(r"[\s,;]+", line) if token]
            candidates = [_classify_token(token) for token in tokens]
            words = [token for token, item in zip(tokens, candidates) if item is None]
            if words:   # the whole line when nothing else was recognized, so "Acme, Inc." keeps its punctuation
                candidates.append(_text_item(line if len(words) == len(tokens) else " ".join(words)))
        for item in candidates:
            if item and item.label not in {i.label for i in items}:
                items.append(item)
    return items


# "Search as" choices in the query step: label -> (kind, auto). Auto SHA-256 also tries the value as a public key hash;
# auto MD5 / SHA-1 also match a serial number of the same length.
SEARCH_AS = {
    "SHA-256 (or public key)": ("sha256", True),
    "SHA-256": ("sha256", False),
    "Public key (SPKI)": ("spki", False),
    "SHA-1 or serial": ("sha1", True),
    "SHA-1": ("sha1", False),
    "MD5 or serial": ("md5", True),
    "MD5": ("md5", False),
    "Serial": ("serial", False),
    "CN": ("cn", False),
    "CN contains": ("cn~", False),
    "SAN": ("san", False),
    "Organization contains": ("org~", False),
    "Organization": ("org", False),
    "Issuer": ("issuer", False),
}


def search_as_label(item):
    """The SEARCH_AS label that reproduces how `item` would be searched."""
    auto = item.auto and item.kind in ("sha256", *AMBIGUOUS_WITH_SERIAL)
    return next(label for label, spec in SEARCH_AS.items() if spec == (item.kind, auto))


def item_for(value, label):
    """Certificate input for `value` searched as the SEARCH_AS `label` (value normalized for that field)."""
    kind, auto = SEARCH_AS[label]
    return InputItem(kind, _prefixed_value(kind, str(value)), auto=auto)


def input_problems(items):
    """Human-readable problems that would make a certificate query fail (checked before any API call)."""
    problems = []
    for item in items:
        if not item.value:
            problems.append(f"{item.kind_name}: enter a value to search")
        elif item.kind in ("sha256", "spki") and not (_HEX_RE.match(item.value) and len(item.value) == 64):
            problems.append(f"{item.label}: expected 64 hexadecimal characters")
        elif item.kind == "sha1" and not (_HEX_RE.match(item.value) and len(item.value) == 40):
            problems.append(f"{item.label}: expected 40 hexadecimal characters")
        elif item.kind == "md5" and not (_HEX_RE.match(item.value) and len(item.value) == 32):
            problems.append(f"{item.label}: expected 32 hexadecimal characters")
        elif item.kind in ("cn~", "org~") and not CONTAINS_MIN <= len(item.value) <= CONTAINS_MAX:
            problems.append(f"{item.label}: 'contains' text must be 3 to 63 characters")
    return problems


def _keyword_variants(value):
    """Keyword fields match byte for byte, so query the value as given plus lower- and upper-case forms."""
    return list(dict.fromkeys([value, value.lower(), value.upper()]))


def seed_query(item):
    """CertsQL document for a certificate input."""
    kind, value = item.kind, item.value
    if kind in ("sha256", "sha1", "md5"):
        body = f"{kind} in {json.dumps(_keyword_variants(value))}"
        if item.ambiguous:
            body += f"\nserial_number in {json.dumps(_keyword_variants(value))}"
    elif kind == "spki":
        body = f"public_key_sha256 in {json.dumps(_keyword_variants(value))}"
    elif kind == "serial":
        body = f"serial_number in {json.dumps(_keyword_variants(value))}"
    elif kind == "cn":
        body = f"subject_common_name equals {json.dumps(value)}"
    elif kind == "cn~":
        body = f"subject_common_name contains {json.dumps(value)}"
    elif kind == "org":
        body = f"subject_organization equals {json.dumps(value)}"
    elif kind == "org~":
        body = f"subject_organization contains {json.dumps(value)}"
    elif kind == "issuer":   # two lines in one clause: either field may match
        body = f"issuer_common_name equals {json.dumps(value)}\nissuer_organization equals {json.dumps(value)}"
    elif kind == "san":
        if is_ip_address(value):
            field = "san_ip_v4" if ipaddress.ip_address(value).version == 4 else "san_ip_v6"
            body = f"{field} between {json.dumps([value, value])}"
        else:
            body = f"san_dns equals {json.dumps(value)}"
    else:
        raise ValueError(f"Not a certificate input: {item.label}")
    return f"# CertsQL-1.0\n{body}\n"


def matched_kind(item, hits):
    """For an ambiguous fingerprint-or-serial input: which field the found certificates matched ("md5"/"sha1" or "serial")."""
    if not item.ambiguous or not hits:
        return item.kind
    value = item.value.lower()
    if any(str(hit.get(item.kind) or "").lower() == value for hit in hits):
        return item.kind
    if any(str(hit.get("serial_number") or "").lower().replace(":", "") == value for hit in hits):
        return "serial"
    return item.kind


def domain_search_query(domain):
    """Certificates naming the domain or any of its subdomains (one clause, so either line matches)."""
    domain = domain.lower().rstrip(".")
    return f"# CertsQL-1.0\nsan_dns equals {json.dumps(domain)}\nsan_dns ends_with {json.dumps('.' + domain)}\n"


def covering_wildcard(hostname):
    """The wildcard SAN that would also cover `hostname` (`*.example.com` for `api.example.com`), or None."""
    if hostname.startswith("*.") or "." not in hostname:
        return None
    parent = hostname.split(".", 1)[1]
    return f"*.{parent}" if "." in parent else None


def hostname_search_query(hostnames):
    """Certificates naming exactly these hostnames, or a wildcard covering one of them (one clause, any line matches)."""
    names = list(dict.fromkeys(n.lower().rstrip(".") for n in hostnames))
    names += [w for w in dict.fromkeys(covering_wildcard(n) for n in names) if w and w not in names]
    return "# CertsQL-1.0\n" + "".join(f"san_dns equals {json.dumps(name)}\n" for name in names)


def _is_shared_name(name):
    return any(name == suffix or name.endswith("." + suffix) for suffix in SHARED_SAN_SUFFIXES)


def _clean_name(name):
    """Lowercased certificate / observation name, or "" for names that are never analyzed (shared CDN, private IP)."""
    name = str(name or "").strip().lower().rstrip(".")
    bare = name[2:] if name.startswith("*.") else name
    if not bare or " " in bare or "." not in bare or _is_shared_name(bare):
        return ""
    if is_ip_address(bare):
        return bare if is_public_ip(bare) else ""
    return name if registrable_domain(bare) else ""


def _hostname_target(name):
    name = _clean_name(name)
    if not name or is_ip_address(name):
        return name or None
    return registrable_domain(name.removeprefix("*.")) or None


def _seed_names(seed_results):
    """(name, via, seed label, certificate SHA-256) for every name the seeds' certificates and observations mention."""
    for item, hits, observations in seed_results:
        for hit in hits or []:
            cert = str(hit.get("sha256") or "")
            sans = [*(hit.get("san_dns") or []), *(hit.get("san_ip_v4") or []), *(hit.get("san_ip_v6") or [])]
            for name in sans:
                yield name, "SAN IP" if is_ip_address(name) else "SAN DNS", item.label, cert
            if not sans:   # no SANs (common on self-signed / internal certificates): fall back to a hostname-like CN
                yield hit.get("subject_common_name"), "CN", item.label, cert
        for event in observations or []:
            cert = str(event.get("sha256") or item.value)
            for name, via in ((event.get("domain"), "Observed domain"), (event.get("hostname"), "Observed hostname"),
                              (event.get("ip"), "Observed IP")):
                yield name, via, item.label, cert


def _collect(entries, key, kind, via, seed, cert):
    entry = entries.setdefault(key, {"Type": kind, "Via": [], "Seeds": [], "Certs": []})
    for field, value in (("Via", via), ("Seeds", seed), ("Certs", cert)):
        if value and value not in entry[field]:
            entry[field].append(value)


def derive_targets(seed_results, max_selected=25):
    """
    Domains and IPs covered by the certificates (and certificate observations) found for each seed.
    `seed_results` is a list of (InputItem, certificate hits, observation events). Returns a DataFrame in
    DERIVED_COLUMNS order, ranked by how many certificates name a target; the first `max_selected` are pre-selected.
    """
    found = {}
    for name, via, seed, cert in _seed_names(seed_results):
        target = _hostname_target(name)
        if target:
            _collect(found, target, "IP" if is_ip_address(target) else "Domain", via, seed, cert)
    hostnames = derive_hostnames(seed_results)
    per_apex = hostnames.groupby("Apex")["Hostname"].nunique() if not hostnames.empty else pd.Series(dtype=int)
    rows = [{"Target": target, "Type": entry["Type"], "Via": ", ".join(entry["Via"]),
             "Hostnames": int(per_apex.get(target, 0)), "Certificates": len(entry["Certs"]),
             "Seeds": ", ".join(entry["Seeds"]), "Example Certificate": entry["Certs"][0] if entry["Certs"] else ""}
            for target, entry in found.items()]
    frame = pd.DataFrame(rows, columns=DERIVED_COLUMNS[1:])
    frame = frame.sort_values("Certificates", ascending=False, kind="stable").reset_index(drop=True)
    frame.insert(0, "Analyze", frame.index < max_selected)
    return frame


def derive_hostnames(seed_results):
    """
    Full hostnames (including wildcards such as `*.example.com`) the seeds' certificates and observations name, with
    their apex, in HOSTNAME_COLUMNS order. Ticked "Focus" hostnames become the run's hostname focus (a view filter;
    the apex is still looked up in full). IPs are not listed: they are analyzed as targets of their own.
    """
    found = {}
    for name, via, seed, cert in _seed_names(seed_results):
        name = _clean_name(name)
        if name and not is_ip_address(name):
            _collect(found, name, registrable_domain(name.removeprefix("*.")), via, seed, cert)
    rows = [{"Focus": False, "Hostname": name, "Apex": entry["Type"], "Via": ", ".join(entry["Via"]),
             "Certificates": len(entry["Certs"]), "Seeds": ", ".join(entry["Seeds"])} for name, entry in found.items()]
    frame = pd.DataFrame(rows, columns=HOSTNAME_COLUMNS)
    return frame.sort_values(["Apex", "Certificates", "Hostname"], ascending=[True, False, True], kind="stable") \
        .reset_index(drop=True)


def host_focus_from(hostnames):
    """{apex: [hostnames]} for the ticked rows of a derive_hostnames frame."""
    if hostnames is None or hostnames.empty:
        return {}
    ticked = hostnames[hostnames["Focus"].astype(bool)]
    return {apex: sorted(group["Hostname"]) for apex, group in ticked.groupby("Apex", sort=True)}


def run_key_labels(targets, seeds):
    """Labels that identify a run's target list: analysis targets plus the certificate inputs they came from."""
    return list(targets) + [f"seed:{label}" for label in seeds]

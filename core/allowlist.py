"""
Infrastructure allowlist: your own (or otherwise known-good) name servers, IP ranges, ASNs, certificate
organizations, web tracker IDs and registrars. Allowlisted values never link domains into clusters, and alerts whose
evidence names one are kept but drop to Low confidence, saying why. Saved in dt_settings.json (Settings → Brands &
allowlist), one entry per line:

    10.20.0.0/16, 203.0.113.7     IP addresses and ranges
    AS13335                       an ASN (its hosting IPs, when Iris or VPNDB knows the ASN)
    ns:corp-dns.example           a name server or its provider domain (a bare host name means the same)
    org:Example Corp              certificate subject organization (contains, any case)
    tracker:G-ABC123              a web tracker ID
    registrar:MarkMonitor         a registrar (contains, any case)
"""
import ipaddress
import re
from dataclasses import dataclass, field

from core.helpers import extract_ip_addresses

ALLOWLIST_SETTING = "infra_allowlist"
_PREFIXES = ("ns", "org", "tracker", "registrar", "asn", "ip")


@dataclass(frozen=True)
class Allowlist:
    networks: tuple = ()
    asns: frozenset = field(default_factory=frozenset)
    name_servers: tuple = ()
    orgs: tuple = ()
    trackers: frozenset = field(default_factory=frozenset)
    registrars: tuple = ()

    def __bool__(self):
        return bool(self.networks or self.asns or self.name_servers or self.orgs or self.trackers or self.registrars)

    def ip(self, value, asn=None):
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            return False
        return any(address in net for net in self.networks) or (asn is not None and int(asn) in self.asns)

    def name_server(self, host):
        host = str(host or "").lower().rstrip(".")
        return any(host == ns or host.endswith("." + ns) for ns in self.name_servers)

    def tracker(self, value):
        code = str(value or "").split(":", 1)[-1].strip().lower()
        return code in self.trackers

    def artifact(self, kind, value, asn=None):
        """Whether a correlation artifact (core.correlation types) is allowlisted."""
        if kind == "IP":
            return self.ip(value, asn)
        if kind in ("Name Server", "CNAME Target"):
            return self.name_server(value)
        if kind == "Web Tracker":
            return self.tracker(value)
        return False

    def in_text(self, text):
        """The first allowlisted value named in an alert's text (IOCs, logic), or None."""
        lowered = str(text or "").lower()
        for ip in extract_ip_addresses(lowered):
            if self.ip(ip):
                return ip
        for values in (self.name_servers, self.orgs, self.registrars, tuple(self.trackers)):
            for value in values:
                if value and value in lowered:
                    return value
        return None


def parse_allowlist(raw):
    """Allowlist from the text typed on Settings (commas or one entry per line; see the module docstring)."""
    networks, asns, name_servers, orgs, trackers, registrars = [], set(), [], [], set(), []
    for item in re.split(r"[\n,]", str(raw or "")):
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        prefix, _, rest = item.partition(":")
        kind, value = (prefix.lower(), rest.strip()) if prefix.lower() in _PREFIXES and rest else ("", item)
        if kind in ("", "ip"):
            try:
                networks.append(ipaddress.ip_network(value, strict=False))
                continue
            except ValueError:
                if kind == "ip":
                    continue
        if kind == "asn" or (not kind and re.fullmatch(r"(?i)as\d+", value)):
            digits = re.sub(r"(?i)^as", "", value)
            if digits.isdigit():
                asns.add(int(digits))
        elif kind == "org":
            orgs.append(value.lower())
        elif kind == "tracker":
            trackers.add(value.lower())
        elif kind == "registrar":
            registrars.append(value.lower())
        elif kind == "ns" or "." in value:
            name_servers.append(value.lower().rstrip("."))
    return Allowlist(tuple(networks), frozenset(asns), tuple(dict.fromkeys(name_servers)), tuple(dict.fromkeys(orgs)),
                     frozenset(trackers), tuple(dict.fromkeys(registrars)))

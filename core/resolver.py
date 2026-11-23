"""
DNS resolution tree and dangling DNS, like DomainTools' Super Resolver.

Every current name of the analyzed domains' DNS tree (the run's passive DNS: DNSDB `*.domain`) is resolved record by
record until IP addresses: A / AAAA directly, CNAME chains, the hosts of MX and NS records and the includes of SPF
records. Names outside the collected data are looked up in DNSDB one exact name at a time
(integrations.collector.resolve_names); until then they are "Not resolved yet".

A target that resolves nowhere is a dangling record: whoever claims the name (a deleted cloud resource, a lapsed
domain) receives what points to it: the subdomain's visitors (CNAME), the mail (MX), the whole zone (NS) or the right to
send as the domain (SPF). Its severity follows the record type, whether the target's own domain still has DNS records
(none: it may be unregistered, so anyone can register it) and whether the target is a takeover-prone service.

Everything here is pure: no API call and no Streamlit.
"""
import ipaddress
import re
from dataclasses import dataclass, field

import pandas as pd

from core.cname import classify_target
from core.hostnames import apex_of, clean_hostname
from core.intel_data import SEVERITY_RANK
from core.network_intel import is_public_ip

RESOLVE_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")
LOOKUP_TYPES = RESOLVE_TYPES + ("SOA",)          # SOA too: a domain that has one is delegated (registered)
CURRENT_DAYS = 90       # a record type of a name is current when seen within this many days of the newest record
MAX_STEPS = 10          # names followed per chain, SPF includes followed per record (SPF's own lookup limit)
# one row per (name, record type, value) DNSDB returned. Lookup: the looked-up name (exact: every record type), or
# "*.domain" / "*.domain/TYPE" for the discovery of a domain's current tree (time-fenced wildcard lookups). Type ""
# marks a name DNSDB has nothing for, or (Lookup "*.domain") whether the discovery was complete (Value COMPLETE).
LOOKUP_COLUMNS = ["Lookup", "Name", "Type", "Value", "Last Seen", "Looked Up At", "From Cache"]
COMPLETE, CUT_OFF = "complete", "cut off"
TREE_COLUMNS = ["Severity", "Domain", "Name", "Type", "Records", "Status", "Dangling", "Stale", "Reason", "Service",
                "Targets",
                "IPv4", "IPv6", "Origins", "Routing", "Warnings", "Path", "Last Seen"]
LOW_VISIBILITY = 5      # route collectors: a route fewer of them see is barely visible on the internet
ROUTING_COLUMNS = ["IP", "Prefix", "Origin", "AS Name", "Status", "IRR", "RPKI", "Collectors", "Origins"]

RESOLVES, DANGLING, PENDING, LOOP, NO_ADDRESS = "Resolves", "Dangling", "Not resolved yet", "Loop", "No address (CDN)"
STALE = "Stale record"
DANGLING_DEFINITION = ("Dangling DNS records point to resources that don't exist or are unclaimed. Attackers could "
                       "claim these resources to serve malicious content under your domain.")
STATUSES = {
    RESOLVES: "Every target resolves to IP addresses",
    DANGLING: "A target doesn't exist and can be claimed (a lapsed domain, a takeover-prone service, an unknown "
              "external name): whoever claims it receives what the record points to",
    STALE: "A target doesn't exist but nobody else can claim it (a certificate validation leftover on the CA's own "
           "domain, a missing name of the analyzed domain itself): broken or stale, remove it, not dangling",
    PENDING: "A target is outside the collected passive DNS and was not looked up in DNSDB yet: click Resolve",
    LOOP: "A CNAME chain returns to a name it already passed",
    NO_ADDRESS: "The chain ends at a CDN name DNSDB has no address for (CDN edges answer per client): not dangling",
}
# Certificate authorities' domain control validation (DCV) targets: a CNAME left behind after a certificate was issued
# points there and never resolves, but the name lives on the CA's own domain, so nobody else can claim it
CERT_VALIDATION_SUFFIXES = {"comodoca.com": "Sectigo (Comodo) certificate validation",
                            "sectigo.com": "Sectigo certificate validation",
                            "acm-validations.aws": "AWS ACM certificate validation",
                            "dcv.digicert.com": "DigiCert certificate validation"}
WHAT_IS_TAKEN = {"CNAME": "the subdomain's visitors and cookies", "MX": "the domain's incoming mail",
                 "NS": "the whole zone (every name under it)", "TXT": "the right to send mail as the domain (SPF)"}


def _naive(value):
    stamp = pd.to_datetime(value, errors="coerce", utc=True)
    return stamp.tz_convert(None) if pd.notna(stamp) else pd.NaT


def _name(value):
    return clean_hostname(str(value or "").strip().strip('"')).rstrip(".")


def _txt(value):
    """TXT rdata as one string (DNSDB splits long records into quoted pieces)."""
    return re.sub(r'"\s+"', "", str(value or "")).strip().strip('"')


@dataclass
class Index:
    """Current records per name: {name: {type: (last seen, [values])}} and which names' absence means something."""
    records: dict = field(default_factory=dict)
    looked: set = field(default_factory=set)          # names looked up in DNSDB (exact name, every type)
    covered: tuple = ()                               # analyzed domains whose passive DNS lookup was complete
    newest: object = pd.NaT

    def current(self, name):
        """{type: [values]} of the record types seen within CURRENT_DAYS of the newest record of the run."""
        cutoff = self.newest - pd.Timedelta(days=CURRENT_DAYS) if pd.notna(self.newest) else None
        return {kind: values for kind, (seen, values) in self.records.get(name, {}).items()
                if values and (cutoff is None or pd.isna(seen) or seen >= cutoff)}

    def seen(self, name, kind):
        return self.records.get(name, {}).get(kind, (pd.NaT, []))[0]

    def known(self, name):
        """True when the data says what `name` has (also when it has nothing): it was looked up, or it lies under an
        analyzed domain whose passive DNS lookup was complete."""
        return name in self.looked or any(name == d or name.endswith("." + d) for d in self.covered)


def _add(records, name, kind, seen, value):
    """Keeps, per name and type, the newest last seen and the values seen within a day of it."""
    if kind not in LOOKUP_TYPES or not name:
        return
    value = _txt(value) if kind == "TXT" else str(value or "").strip().rstrip(".").lower()
    if not value:
        return
    newest, values = records.setdefault(name, {}).get(kind, (pd.NaT, []))
    if pd.isna(newest) or (pd.notna(seen) and seen > newest + pd.Timedelta(days=1)):
        records[name][kind] = (seen, [value])
    elif pd.isna(seen) or seen >= newest - pd.Timedelta(days=1):
        records[name][kind] = (max(newest, seen) if pd.notna(seen) else newest,
                               values + ([value] if value not in values else []))


def build_index(pdns, lookups=None, coverage=None, domains=()):
    """The Index from the run's passive DNS (`pdns`: RRName, Field, Value, Last Seen) and DNSDB lookups (LOOKUP_COLUMNS)."""
    records, newest = {}, pd.NaT
    if pdns is not None and not pdns.empty and {"RRName", "Field", "Value", "Last Seen"} <= set(pdns.columns):
        # engine event frames prefix the type ("pDNS: A") and hold Domain History rows: passive DNS rows only
        kinds = pdns["Field"].astype(str).str.upper().str.replace(r"^PDNS:\s*", "", regex=True)
        seen = pd.to_datetime(pdns["Last Seen"], errors="coerce", utc=True).dt.tz_convert(None)
        keep = kinds.isin(LOOKUP_TYPES) & seen.notna() & pdns["RRName"].notna()
        frame, kinds, seen = pdns[keep], kinds[keep], seen[keep]
        newest = seen.max()
        for name, kind, value, stamp in zip(frame["RRName"], kinds, frame["Value"], seen):
            for part in str(value).split("\n"):
                _add(records, _name(name), kind, stamp, part)
    looked, discovered = set(), set()
    if lookups is not None and not lookups.empty:
        for row in lookups.to_dict("records"):
            name = _name(row["Name"])
            lookup = str(row.get("Lookup") or name)
            if lookup.startswith("*."):     # discovery of a domain's tree: its records, not proof of absence by name
                if lookup == f"*.{name}" and not row.get("Type") and row.get("Value") == COMPLETE:
                    discovered.add(name)
            else:
                looked.add(name)
            _add(records, name, str(row.get("Type") or ""), _naive(row.get("Last Seen")), row.get("Value"))
    if pd.isna(newest) and records:
        stamps = [seen for kinds in records.values() for seen, _ in kinds.values() if pd.notna(seen)]
        newest = max(stamps) if stamps else pd.NaT
    covered = tuple(_name(d) for d in domains
                    if not (coverage or {}).get(d, {}).get("truncated") or _name(d) in discovered)
    return Index(records, looked, covered, newest)


@dataclass
class Host:
    """Where one target name ends: its chain, addresses, and the names that are dead or not looked up yet."""
    chain: list
    ipv4: list = field(default_factory=list)
    ipv6: list = field(default_factory=list)
    dead: list = field(default_factory=list)       # (name, why)
    pending: list = field(default_factory=list)
    loop: bool = False
    cdn: bool = False


def resolve_host(name, index, max_steps=MAX_STEPS):
    """Follows `name` through current CNAMEs (the newest of CNAME vs A / AAAA wins) to its addresses."""
    chain = [name]
    for _ in range(max_steps):
        current = index.current(name)
        cnames, ipv4, ipv6 = current.get("CNAME", []), current.get("A", []), current.get("AAAA", [])
        newer_cname = cnames and (not (ipv4 or ipv6) or index.seen(name, "CNAME") >=
                                  max(index.seen(name, "A") if ipv4 else pd.Timestamp.min,
                                      index.seen(name, "AAAA") if ipv6 else pd.Timestamp.min))
        if newer_cname:
            target = cnames[0]
            if target in chain:
                return Host(chain + [target], loop=True)
            chain.append(target)
            name = target
            continue
        if ipv4 or ipv6:
            return Host(chain, ipv4=list(ipv4), ipv6=list(ipv6))
        if not index.known(name):
            return Host(chain, pending=[name])
        if classify_target(name)[0] == "CDN":
            return Host(chain, cdn=True)
        return Host(chain, dead=[(name, "no CNAME, A or AAAA record in DNSDB")])
    return Host(chain)


def spf_terms(text):
    """(includes and redirects, a: / mx: hosts, ip4 / ip6 networks) of an SPF record; None when it is not SPF."""
    text = _txt(text)
    if not text.lower().startswith("v=spf1"):
        return None
    includes, hosts, nets = [], [], []
    for term in text.split()[1:]:
        term = term.lstrip("+-~?")
        key, sep, value = term.partition(":")
        if not sep:
            key, sep, value = term.partition("=")
        key, value = key.lower(), value.strip()
        if not value or "%" in value:     # bare a / mx (the domain itself) and macros are not followed
            continue
        if key in ("include", "redirect"):
            includes.append(_name(value))
        elif key in ("a", "mx"):
            hosts.append((key, _name(value.split("/")[0])))
        elif key in ("ip4", "ip6"):
            nets.append(value)
    return includes, hosts, nets


def resolve_spf(text, index, seen=None, depth=0):
    """Follows an SPF record's includes (each include's own SPF TXT record) and hosts: (targets, ipv4, ipv6, dead,
    pending), `dead` as (name, why)."""
    terms = spf_terms(text)
    seen = seen if seen is not None else set()
    targets, ipv4, ipv6, dead, pending = [], [], [], [], []
    if terms is None or depth > MAX_STEPS:
        return targets, ipv4, ipv6, dead, pending
    includes, hosts, nets = terms
    for net in nets:
        (ipv6 if ":" in net else ipv4).append(net)
    for include in includes:
        if include in seen:
            continue
        seen.add(include)
        targets.append(include)
        spf = [t for t in index.current(include).get("TXT", []) if t.lower().startswith("v=spf1")]
        if spf:
            more = resolve_spf(spf[0], index, seen, depth + 1)
            for bucket, extra in zip((targets, ipv4, ipv6, dead, pending), more):
                bucket += [x for x in extra if x not in bucket]
        elif not index.known(include):
            pending.append(include)
        else:
            dead.append((include, "no SPF record in DNSDB"))
    for kind, host in hosts:
        targets.append(host)
        names = [h.split()[-1] for h in index.current(host).get("MX", [])] if kind == "mx" else [host]
        if kind == "mx" and not names:
            if index.known(host):
                dead.append((host, "no MX record in DNSDB"))
            else:
                pending.append(host)
        for name in names:
            found = resolve_host(name, index)
            ipv4 += found.ipv4
            ipv6 += found.ipv6
            dead += found.dead
            pending += found.pending
    return targets, ipv4, ipv6, dead, pending


def _apex_state(name, index, domains):
    """How the registrable domain of a dead `name` stands: "own" (an analyzed domain), "lapsed" (looked up: no NS / SOA
    record now), "pending" (not looked up yet) or "active"."""
    apex = apex_of(name)
    if not apex or apex in domains:
        return apex, "own"
    if not index.known(apex):
        return apex, "pending"
    return apex, "active" if index.current(apex) else "lapsed"


def _danger(kind, name, why, index, domains):
    """(severity, reason, service) of a dead target of a `kind` record; severity None when nobody else can claim the
    target (a stale record, not a dangling one)."""
    service_type, service = classify_target(name)
    apex, state = _apex_state(name, index, domains)
    taken = WHAT_IS_TAKEN.get(kind, "what points to it")
    validation = next((label for suffix, label in CERT_VALIDATION_SUFFIXES.items()
                       if name == suffix or name.endswith("." + suffix)), "")
    if validation:
        return None, f"{name}: {why}. A certificate validation (DCV) record left behind after issuance: the target is " \
                     f"on the certificate authority's own domain, so it cannot be claimed. Remove the stale record", \
            validation
    if state == "own":
        return None, f"{name}: {why}. It is a name of the analyzed domain itself, so it is broken, not claimable from " \
                     "outside. Remove or fix the record", service
    if state == "lapsed":
        return ("Critical" if kind != "TXT" else "High",
                f"{name}: {why}, and its domain {apex} has no current DNS record: it may be unregistered or lapsed. "
                f"Whoever registers {apex} receives {taken}", service)
    if service_type == "Takeover-prone":
        return "Critical", f"{name}: {why} on {service}, where anyone can create the missing resource and receive " \
                           f"{taken} (subdomain takeover)", service
    severity = {"NS": "High", "CNAME": "High", "MX": "High", "TXT": "Medium"}.get(kind, "Medium")
    note = " (its domain was not looked up yet)" if state == "pending" else ""
    return severity, f"{name}: {why}{note}. If the name can be claimed, its owner receives {taken}", service


def _worst(severities):
    ranked = [s for s in severities if s]
    return min(ranked, key=lambda s: SEVERITY_RANK.get(s, 9)) if ranked else ""


def routing_table(*origin_frames, findings=None):
    """
    {ip: ROUTING_COLUMNS dict} from BGPDB origin rows (core.bgp.ORIGIN_COLUMNS: the run's hosting IPs and the IPs the
    resolution reached): per IP its most specific prefix, the usual origin there (core.bgp.main_origins), its RPKI /
    IRR status, how many route collectors see it, every origin seen, and `findings` ({ip: text}, core.bgp.ip_table).
    """
    from core import bgp
    frames = [f for f in origin_frames if f is not None and not f.empty]
    if not frames:
        return {}
    origins = pd.concat(frames, ignore_index=True).drop_duplicates(["IP", "Prefix", "Origin"])
    origins = origins[origins["Prefix"].astype(str) != ""]     # looked up, nothing announced
    if origins.empty:
        return {}
    usual = bgp.main_origins(origins)
    if usual.empty:
        return {}
    lengths = usual["Prefix"].astype(str).str.extract(r"/(\d+)\+?$")[0].astype(float)
    best = usual.assign(_len=lengths).sort_values(["IP", "_len", "Updates"], ascending=[True, False, False]) \
        .drop_duplicates("IP")
    every = origins.groupby("IP")["Origin"].agg(lambda s: sorted(set(s)))
    table = {}
    for row in best.to_dict("records"):
        ip = str(row["IP"])
        table[ip] = {"IP": ip, "Prefix": row["Prefix"], "Origin": row["Origin"], "AS Name": row.get("AS Name") or "",
                     "Status": row["Status"], "IRR": row["IRR"], "RPKI": row["RPKI"],
                     "Collectors": int(row.get("Collectors") or 0), "Origins": every.get(row["IP"], []),
                     "Findings": (findings or {}).get(ip, "")}
    return table


INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10",
    "::1/128"))


def address_class(value):
    """"internal" (RFC 1918, loopback, link-local, ULA), "bogon" (other reserved space: not routable on the
    internet, e.g. 0.0.0.0/8, 100.64.0.0/10, documentation, multicast, 240.0.0.0/4) or "" for an address or range."""
    try:
        net = ipaddress.ip_network(str(value).strip().rstrip("+"), strict=False)
    except ValueError:
        return ""
    if any(net.version == n.version and net.subnet_of(n) for n in INTERNAL_NETWORKS):
        return "internal"
    return "" if net.network_address.is_global and not net.network_address.is_multicast else "bogon"


def address_warning(value):
    kind = address_class(value)
    if kind == "internal":
        return f"Internal IP {value} in public DNS"
    if kind == "bogon":
        return f"Bogon address {value}: reserved space, not routable on the internet"
    return ""


def routing_warnings(ip, route):
    """What looks wrong in an IP's routing: a bogon origin or prefix, an unauthorized origin, several origins, a barely
    visible route."""
    from core import bgp
    warnings = []
    if bgp.is_private_asn(route["Origin"]):
        warnings.append(f"BGP {ip}: bogon origin {route['Origin']} (private or reserved AS number)")
    if address_class(route["Prefix"]) == "bogon":
        warnings.append(f"BGP {ip}: bogon prefix {route['Prefix']} (reserved space)")
    if route["Status"] == bgp.UNAUTHORIZED:
        warnings.append(f"BGP {ip}: {route['Prefix']} announced by {route['Origin']}, which RPKI / IRR does not "
                        f"authorize (RPKI {route['RPKI']}, IRR {route['IRR']})")
    others = [o for o in route["Origins"] if o != route["Origin"]]
    if others:
        warnings.append(f"BGP {ip}: also announced by {', '.join(others)}")
    if 0 < route["Collectors"] < LOW_VISIBILITY:
        warnings.append(f"BGP {ip}: {route['Prefix']} seen by only {route['Collectors']} route collector(s)")
    if route.get("Findings"):
        warnings.append(f"BGP {ip}: {route['Findings']}")
    return list(dict.fromkeys(warnings))


def tree_ips(tree):
    """The public addresses (no ranges) the tree resolves to."""
    if tree is None or tree.empty:
        return []
    ips = {ip for column in ("IPv4", "IPv6") for values in tree[column] for ip in values if "/" not in ip}
    return sorted(ip for ip in ips if is_public_ip(ip))


def build_tree(index, domains, routing=None):
    """
    One row (TREE_COLUMNS) per current (name, record type) of the analyzed domains, resolved to addresses; and the
    names still to look up (to resolve those rows, or to check the domain of a dead target).
    `routing`: routing_table, for each address's origin network and routing warnings.
    """
    domains = [_name(d) for d in domains if d and "/" not in str(d)]
    own = set(domains)
    routing = routing or {}
    rows, todo = [], set()
    names = sorted(n for n in index.records if any(n == d or n.endswith("." + d) for d in domains))
    for name in names:
        domain = next((d for d in sorted(domains, key=len, reverse=True) if name == d or name.endswith("." + d)), "")
        current = index.current(name)
        for kind in RESOLVE_TYPES:
            values = current.get(kind)
            if not values:
                continue
            row = {"Domain": domain, "Name": name, "Type": kind, "Records": values, "Status": RESOLVES,
                   "Dangling": [], "Stale": [], "Reason": [], "Service": [], "Targets": [], "IPv4": [], "IPv6": [],
                   "Origins": [],
                   "Routing": [], "Warnings": [],
                   "Path": "", "Last Seen": index.seen(name, kind), "_sev": []}
            dead, pending = [], []
            if kind in ("A", "AAAA"):
                row["IPv4" if kind == "A" else "IPv6"] = list(values)
            elif kind == "CNAME":
                if not (current.get("A") or current.get("AAAA")) or index.seen(name, "CNAME") >= max(
                        index.seen(name, "A") if current.get("A") else pd.Timestamp.min,
                        index.seen(name, "AAAA") if current.get("AAAA") else pd.Timestamp.min):
                    found = resolve_host(values[0], index)
                    row.update(Targets=found.chain, IPv4=found.ipv4, IPv6=found.ipv6,
                               Path=" → ".join([name] + found.chain))
                    dead, pending = found.dead, found.pending
                    if found.loop:
                        row["Status"] = LOOP
                    elif found.cdn:
                        row["Status"] = NO_ADDRESS
                else:
                    continue    # replaced by A / AAAA records since: the address rows stand for the name
            elif kind in ("MX", "NS"):
                hosts = [v.split()[-1].rstrip(".") for v in values]
                hosts = [h for h in hosts if h and h != "."]     # "0 ." is a null MX: the domain takes no mail
                row["Targets"] = hosts
                for host in hosts:
                    found = resolve_host(host, index)
                    row["IPv4"] += found.ipv4
                    row["IPv6"] += found.ipv6
                    dead += found.dead
                    pending += found.pending
            elif kind == "TXT":
                spf = [v for v in values if v.lower().startswith("v=spf1")]
                if not spf:
                    continue
                row["Records"] = spf
                targets, ipv4, ipv6, dead, pending = resolve_spf(spf[0], index)
                row.update(Targets=targets, IPv4=ipv4, IPv6=ipv6)
            for ip in row["IPv4"] + row["IPv6"]:
                warning = address_warning(ip)
                if warning:
                    row["Warnings"].append(warning)
                    row["_sev"].append("Low")
                route = routing.get(ip)
                if route:
                    row["Origins"].append(f"{route['Origin']} {route['AS Name']}".strip())
                    row["Routing"].append(f"{ip}: {route['Prefix']} {route['Origin']} · {route['Status']} · "
                                          f"{route['Collectors']} collectors")
                    row["Warnings"] += routing_warnings(ip, route)
            for target, why in dict.fromkeys(dead):
                severity, reason, service = _danger(kind, target, why, index, own)
                row["Dangling" if severity else "Stale"].append(target)
                row["Reason"].append(reason)
                row["Service"].append(service)
                row["_sev"].append(severity)
                apex, state = _apex_state(target, index, own)
                if state == "pending" and severity:
                    todo.add(apex)
            if row["Status"] == RESOLVES:     # claimable first, then unknown, then stale (not claimable)
                row["Status"] = DANGLING if row["Dangling"] else PENDING if pending else STALE if row["Stale"] \
                    else RESOLVES
            todo.update(pending)
            row["Severity"] = _worst(row.pop("_sev"))
            for column in ("IPv4", "IPv6", "Origins", "Routing", "Warnings", "Dangling", "Stale", "Service"):
                row[column] = list(dict.fromkeys(v for v in row[column] if v))
            rows.append(row)
    frame = pd.DataFrame(rows, columns=TREE_COLUMNS)
    if not frame.empty:
        frame = frame.assign(_r=frame["Severity"].map(SEVERITY_RANK).fillna(9)) \
            .sort_values(["_r", "Domain", "Name", "Type"], kind="stable").drop(columns="_r").reset_index(drop=True)
    return frame, sorted(todo)


def lookup_rows(name, records, looked_up_at=None, from_cache=False, lookup=None):
    """
    LOOKUP_COLUMNS rows from DNSDB records: of an exact-name lookup of `name` (one empty row: nothing found), or with
    `lookup` ("*.domain" or "*.domain/TYPE", a discovery of the tree of domain `name`) of every name under it.
    """
    name = _name(name)
    rows = []
    for obj in records or []:
        kind = str(obj.get("rrtype", "")).upper()
        owner = _name(obj.get("rrname"))
        if kind not in LOOKUP_TYPES or not (owner == name or (lookup and owner.endswith("." + name))):
            continue
        stamp = pd.to_datetime(obj.get("time_last") or obj.get("zone_time_last"), unit="s", errors="coerce")
        rdata = obj.get("rdata")
        for value in rdata if isinstance(rdata, list) else [rdata]:
            rows.append({"Lookup": lookup or name, "Name": owner, "Type": kind, "Value": str(value),
                         "Last Seen": stamp, "Looked Up At": looked_up_at, "From Cache": from_cache})
    if rows or lookup:
        return rows
    return [{"Lookup": name, "Name": name, "Type": "", "Value": "", "Last Seen": pd.NaT,
             "Looked Up At": looked_up_at, "From Cache": from_cache}]


def discovery_marker(domain, complete, looked_up_at=None, from_cache=False):
    """The row saying whether the discovery of `domain`'s current tree returned every record (COMPLETE)."""
    domain = _name(domain)
    return {"Lookup": f"*.{domain}", "Name": domain, "Type": "", "Value": COMPLETE if complete else CUT_OFF,
            "Last Seen": pd.NaT, "Looked Up At": looked_up_at, "From Cache": from_cache}


def discovered_domains(lookups):
    """The domains whose current tree was discovered (whatever the outcome)."""
    if lookups is None or lookups.empty or "Lookup" not in lookups:
        return set()
    marks = lookups[(lookups["Lookup"] == "*." + lookups["Name"].astype(str)) & (lookups["Type"].fillna("") == "")]
    return set(marks["Name"])


def merge_lookups(old, new):
    """Lookups of both, the newest lookup (by Lookup) replacing older rows of the same lookup."""
    frames = [_with_lookup(f) for f in (old, new) if f is not None and not f.empty]
    if not frames:
        return pd.DataFrame(columns=LOOKUP_COLUMNS)
    if len(frames) == 1:
        return frames[0].reset_index(drop=True)
    old, new = frames
    return pd.concat([old[~old["Lookup"].isin(set(new["Lookup"]))], new], ignore_index=True)[LOOKUP_COLUMNS]


def _with_lookup(frame):
    """Lookups saved before the Lookup column: each was an exact-name lookup of its Name."""
    if "Lookup" not in frame:
        frame = frame.assign(Lookup=frame["Name"])
    return frame.reindex(columns=LOOKUP_COLUMNS)


def summary(tree):
    """Counts for the page and the report: names, records, resolving, dangling per severity, pending, warnings."""
    if tree is None or tree.empty:
        return {"Names": 0, "Records": 0, "Resolves": 0, "Dangling": 0, "Stale": 0, "Pending": 0, "Warnings": 0,
                "IPs": 0, "Critical": 0, "High": 0}
    dangling = tree[tree["Status"] == DANGLING]
    ips = {ip for column in ("IPv4", "IPv6") for ips in tree[column] for ip in ips if "/" not in ip}
    return {"Names": tree["Name"].nunique(), "Records": len(tree), "Resolves": int((tree["Status"] == RESOLVES).sum()),
            "Dangling": len(dangling), "Stale": int((tree["Status"] == STALE).sum()),
            "Pending": int((tree["Status"] == PENDING).sum()),
            "Warnings": int(tree["Warnings"].map(bool).sum()), "IPs": len(ips),
            "Critical": int((dangling["Severity"] == "Critical").sum()),
            "High": int((dangling["Severity"] == "High").sum())}


def display(tree):
    """The tree with list cells as text (tables, CSV and the report)."""
    if tree is None or tree.empty:
        return pd.DataFrame(columns=TREE_COLUMNS)
    joined = {c: tree[c].map(lambda v: ", ".join(v) if isinstance(v, list) else v)
              for c in ("Records", "Dangling", "Stale", "Service", "Targets", "IPv4", "IPv6", "Origins", "Warnings")}
    joined["Routing"] = tree["Routing"].map(lambda v: " | ".join(v) if isinstance(v, list) else v)
    joined["Reason"] = tree["Reason"].map(lambda v: " | ".join(v) if isinstance(v, list) else v)
    return tree.assign(**joined)


ORIGIN_SUMMARY_COLUMNS = ["Origin", "AS Name", "Names", "IPs", "Prefixes", "Valid", "Unauthorized", "Not in RPKI / IRR",
                          "Min Collectors", "Record Types"]


def origins(tree, routing=None):
    """
    The origin networks (BGPDB) of the tree's addresses, like the Super Resolver's origins: per origin the names, IPs
    and prefixes that reach it, its routes by RPKI / IRR status, the least visible route and the record types.
    """
    from core import bgp
    if tree is None or tree.empty or not routing:
        return pd.DataFrame(columns=ORIGIN_SUMMARY_COLUMNS)
    rows = {}
    for name, kind, ips in zip(tree["Name"], tree["Type"], tree["IPv4"] + tree["IPv6"]):
        for ip in ips:
            route = routing.get(ip)
            if route is None:
                continue
            entry = rows.setdefault(route["Origin"], {"Origin": route["Origin"], "AS Name": route["AS Name"],
                                                      "Names": set(), "IPs": {}, "Prefixes": set(), "Types": set()})
            entry["Names"].add(name)
            entry["IPs"][ip] = route
            entry["Prefixes"].add(route["Prefix"])
            entry["Types"].add(kind)
    out = []
    for entry in rows.values():
        statuses = [r["Status"] for r in entry["IPs"].values()]
        out.append({"Origin": entry["Origin"], "AS Name": entry["AS Name"], "Names": len(entry["Names"]),
                    "IPs": len(entry["IPs"]), "Prefixes": len(entry["Prefixes"]),
                    "Valid": statuses.count(bgp.VALID), "Unauthorized": statuses.count(bgp.UNAUTHORIZED),
                    "Not in RPKI / IRR": statuses.count(bgp.UNVERIFIED),
                    "Min Collectors": min(r["Collectors"] for r in entry["IPs"].values()),
                    "Record Types": ", ".join(t for t in RESOLVE_TYPES if t in entry["Types"])})
    frame = pd.DataFrame(out, columns=ORIGIN_SUMMARY_COLUMNS)
    return frame.sort_values(["Unauthorized", "Names"], ascending=False).reset_index(drop=True)


RESOLVED_ROUTING_COLUMNS = ["IP", "Reached By", "Prefix", "Origin", "AS Name", "Status", "RPKI", "IRR", "Collectors",
                            "Other Origins", "Warnings"]


def resolved_routing(tree, routing, hosting=None):
    """
    RESOLVED_ROUTING_COLUMNS: one row per address of the tree that the run's hosting lookups do not cover (`hosting`:
    their origin rows), with the records that reach it and its routing; unauthorized and barely visible first.
    """
    from core import bgp
    skip = routed_set(hosting)
    reached = {}
    for name, kind, ips in zip(tree["Name"], tree["Type"], tree["IPv4"] + tree["IPv6"]) if not tree.empty else ():
        for ip in ips:
            if ip in routing and ip not in skip:
                reached.setdefault(ip, []).append(f"{name} {kind}")
    rows = []
    for ip, names in reached.items():
        route = routing[ip]
        rows.append({"IP": ip, "Reached By": ", ".join(dict.fromkeys(names)), "Prefix": route["Prefix"],
                     "Origin": route["Origin"], "AS Name": route["AS Name"], "Status": route["Status"],
                     "RPKI": route["RPKI"], "IRR": route["IRR"], "Collectors": route["Collectors"],
                     "Other Origins": ", ".join(o for o in route["Origins"] if o != route["Origin"]),
                     "Warnings": " | ".join(routing_warnings(ip, route))})
    frame = pd.DataFrame(rows, columns=RESOLVED_ROUTING_COLUMNS)
    if frame.empty:
        return frame
    order = frame.assign(_u=(frame["Status"] != bgp.UNAUTHORIZED).astype(int), _w=(frame["Warnings"] == "").astype(int))
    return order.sort_values(["_u", "_w", "Collectors", "IP"]).drop(columns=["_u", "_w"]).reset_index(drop=True)


def routed_set(*origin_frames):
    """Every address looked up in BGPDB (also those with no announcement)."""
    return {str(ip) for frame in origin_frames if frame is not None and not frame.empty for ip in frame["IP"]}


def unrouted_ips(tree, *origin_frames):
    """The tree's public addresses not looked up in BGPDB yet."""
    known = routed_set(*origin_frames)
    return [ip for ip in tree_ips(tree) if ip not in known]


def dataset_routing(ds):
    """routing_table of a Dataset: the run's BGPDB hosting lookups (with their findings) and the resolution's own."""
    hosting = getattr(ds, "bgp_origins", None)
    findings = {}
    if hosting is not None and not hosting.empty:
        from core import bgp
        table = bgp.ip_table(hosting, ds.bgp_routes, bgp.findings(hosting, ds.bgp_asns, ds.bgp_routes), ds.enrichment)
        findings = {str(ip): text for ip, text in zip(table["IP"], table["Findings"]) if str(text or "").strip()}
    return routing_table(hosting, getattr(ds, "resolution_routing", None), findings=findings)


def dataset_tree(ds):
    """(tree, names still to look up, routing table) of a Dataset, built once per set of lookups."""
    key = ("resolution_tree", id(getattr(ds, "resolutions", None)), id(getattr(ds, "resolution_routing", None)))
    if key not in ds.derived:
        routing = dataset_routing(ds)
        index = build_index(ds.pdns_utc, getattr(ds, "resolutions", None), ds.pdns_coverage, ds.selected_domains)
        ds.derived[key] = build_tree(index, ds.selected_domains, routing) + (routing,)
    return ds.derived[key]

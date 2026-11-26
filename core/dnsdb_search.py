"""
DNSDB search page (top menu): one DNSDB query built from what the analyst types (a domain, a wildcard, an IP, a CIDR,
an IP range, a regex or a glob) and the options picked, shown as the API request, a curl command, a dnsdbq / dnsdbflex
command and a DNSDB Scout share link before anything is sent; then the records it returns, with the domains and IPs
they name for a new run.

The Scout share link is the one Scout's own *Share Link* builds: `https://scout.dnsdb.info/dashboard?share=` and the
URL-encoded base64 of a compact JSON object with Scout's form keys, in Scout's order (standard searches:
use_standard_search, use_rrset / use_rdata, the value, the bailiwick or rdata type, use_deaggregate, verb_lookup, rtype,
limit, time fence; flexible searches: use_flexible_search, flexible_syntax, the value, the exclusion, flexible_field,
rtype, limit, time fence). Keys left at Scout's defaults are left out, and Scout gives no link over 1,800 characters.
"""
import base64
import ipaddress
import json
import re
import shlex
import urllib.parse
from dataclasses import asdict, dataclass, replace

import pandas as pd

from core.helpers import is_ip_address, normalize_cidr, refang_domain, registrable_domain

API_BASE = "https://api.dnsdb.info/dnsdb/v2"
SCOUT_URL = "https://scout.dnsdb.info/dashboard"
SCOUT_DEFAULT_LIMIT = 5000      # Scout leaves this limit out of its share link
SCOUT_MAX_LINK = 1800           # Scout gives no share link above this length
MAX_VALUE = 4096                # characters of a flexible search value or exclusion (DNSDB's limit)
CLIENT = {"swclient": "DT_Analytics", "version": "2.0.0"}

# key: (label, what it searches, family). "lookup" families are DNSDB lookups; "flex" are Flexible Search.
SEARCHES = {
    "rrset": ("RRset: name", "DNS records whose owner name is the name (`*.example.com`: every name under it, "
                             "`www.example.*`: every name starting with it)", "lookup"),
    "rdata_ip": ("RData: IP", "Names that resolved to the address, CIDR range (`a.b.c.d/len`) or address range "
                              "(`first-last`)", "lookup"),
    "rdata_name": ("RData: name", "Records whose value is the name: who points to it by CNAME, NS, MX, … "
                                  "(`*.example.com` and `www.example.*` wildcards work here too)", "lookup"),
    "regex": ("Flexible: regex", "Names (or record values) matching an extended regular expression (egrep style, "
                                 "no back-references)", "flex"),
    "glob": ("Flexible: glob", "Names (or record values) matching a glob: `*` any characters, `[a-z]` a range, "
                               "`[!a-z]` not in it", "flex"),
    "rrset_raw": ("RRset: raw (hex)", "Records whose owner name is the hex-encoded wire-format name", "lookup"),
    "rdata_raw": ("RData: raw (hex)", "Records whose value is the hex-encoded wire-format data", "lookup"),
}
FLEX_FIELDS = {"rrnames": "Owner names (rrnames)", "rdata": "Record values (rdata)"}
RRTYPES = ("ANY", "A", "AAAA", "CNAME", "NS", "MX", "TXT", "SOA", "PTR", "SRV", "CAA", "HTTPS", "SVCB", "SPF", "NAPTR",
           "HINFO", "RP", "DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "ANY-DNSSEC")
DNSSEC_TYPES = {"DS", "DNSKEY", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM", "DLV", "CDS", "CDNSKEY", "TA", "ANY-DNSSEC"}
FLEX_RDATA_TYPES = {"ANY", "SOA", "CNAME", "HINFO", "MX", "NS", "NAPTR", "PTR", "RP", "SRV", "SPF", "TXT"}
NAME_RDATA_TYPES = {"CNAME", "NS", "MX", "PTR", "SRV", "SOA"}   # their value is (or starts with) a host name
_REGEX_SIGNS = re.compile(r"[\^$\\()|+?{}]")
_HEX = re.compile(r"^(?:[0-9a-fA-F]{2})+$")
_IP_RANGE = re.compile(r"^\s*([0-9a-fA-F:.]+)\s*-\s*([0-9a-fA-F:.]+)\s*$")

RECORD_COLUMNS = ["RRName", "RRType", "RData", "Bailiwick", "Count", "First Seen", "Last Seen"]
TARGET_COLUMNS = ["Analyze", "Target", "Via", "Records", "Names", "Last Seen"]


@dataclass(frozen=True)
class Search:
    mode: str = "rrset"          # a SEARCHES key
    value: str = ""
    rrtype: str = "ANY"
    bailiwick: str = ""           # RRset name lookups only
    field: str = "rrnames"        # flexible searches: rrnames or rdata
    exclude: str = ""             # flexible searches: results matching it are left out
    limit: int = 5000
    after: int | None = None      # epoch seconds: seen after (last seen, or first seen when `strict`)
    before: int | None = None     # epoch seconds: seen before (first seen, or last seen when `strict`)
    strict: bool = False          # the records' whole observation inside the window
    aggregated: bool = True       # lookups: one record per RRset; False adds `aggr=f` (one per time slice)

    @property
    def flex(self):
        return SEARCHES.get(self.mode, ("", "", "lookup"))[2] == "flex"

    @property
    def label(self):
        return SEARCHES.get(self.mode, (self.mode,))[0]

    def to_dict(self):
        return asdict(self)


def from_dict(data):
    """A Search back from to_dict (a run's Data sources row), ignoring keys it no longer has."""
    fields = Search.__dataclass_fields__
    return Search(**{k: v for k, v in (data or {}).items() if k in fields})


def _ip_range(text):
    match = _IP_RANGE.match(str(text or ""))
    return bool(match) and all(is_ip_address(part) for part in match.groups())


def _undefang(text):
    """The text with only defanging brackets undone ([.] and [:]), so a glob's [a-z] stays as typed."""
    return str(text or "").strip().replace("[.]", ".").replace("[:]", ":")


def _name_part(value):
    """A lookup value without its allowed wildcard (`*.` in front or `.*` at the end)."""
    value = value[2:] if value.startswith("*.") else value
    return value[:-2] if value.endswith(".*") else value


def detect(text):
    """
    The search a typed value most likely means: an IP, CIDR or address range → RData IP; `*.example.com` or
    `www.example.*` → an RRset wildcard; regex signs (^ $ \\ ( ) | + ? { }) → regex; any other `*` or `[` → glob;
    anything else → an RRset name lookup.
    """
    value = _undefang(text)
    if not value:
        return "rrset"
    if is_ip_address(value) or normalize_cidr(value) or _ip_range(value):
        return "rdata_ip"
    rest = _name_part(value)
    if "*" not in rest and "[" not in rest and not _REGEX_SIGNS.search(rest):
        return "rrset"
    if _REGEX_SIGNS.search(value):
        return "regex"
    return "glob"


def clean_value(mode, text):
    """The value as sent: trimmed; names refanged; a CIDR written address,length."""
    value = str(text or "").strip()
    if mode in ("regex", "glob"):
        return value
    if mode in ("rrset_raw", "rdata_raw"):
        return value.replace(" ", "").lower()
    if mode == "rdata_ip":
        value = value.replace("[.]", ".").replace("[:]", ":")
        if cidr := normalize_cidr(value):
            return cidr.replace("/", ",")
        return value.replace(" ", "")
    if value.startswith("*.") or value.endswith(".*"):
        head, tail = ("*.", value[2:]) if value.startswith("*.") else ("", value)
        tail, end = (tail[:-2], ".*") if tail.endswith(".*") else (tail, "")
        return head + (refang_domain(tail) or tail) + end
    return refang_domain(value) or value


def problems(search):
    """What would make DNSDB refuse the search (or not search what is meant), as short sentences."""
    issues = []
    value = clean_value(search.mode, search.value)
    if not value:
        return ["Type what to search for."]
    if search.flex:
        if len(value) > MAX_VALUE or len(search.exclude) > MAX_VALUE:
            issues.append(f"A flexible search value or exclusion is at most {MAX_VALUE:,} characters.")
        if search.rrtype in DNSSEC_TYPES:
            issues.append(f"Flexible search does not cover DNSSEC records ({search.rrtype}).")
        if search.field == "rdata" and search.rrtype not in FLEX_RDATA_TYPES:
            issues.append(f"Flexible search on record values covers only {', '.join(sorted(FLEX_RDATA_TYPES - {'ANY'}))}"
                          f" (and ANY): not {search.rrtype}. For addresses, use *RData: IP*.")
        if search.mode == "regex":
            for name, pattern in (("The regex", value), ("The exclusion", search.exclude)):
                if not pattern:
                    continue
                if re.search(r"\\[1-9]", pattern):
                    issues.append(f"{name} uses a back-reference, which DNSDB does not support.")
                try:
                    re.compile(pattern)
                except re.error as exc:
                    issues.append(f"{name} does not parse: {exc}.")
    elif search.mode == "rdata_ip":
        if not (is_ip_address(value) or normalize_cidr(value.replace(",", "/")) or _ip_range(value)):
            issues.append("Not an IP address, CIDR range (a.b.c.d/len) or address range (first-last).")
    elif search.mode in ("rrset_raw", "rdata_raw"):
        if not _HEX.match(value):
            issues.append("Raw searches take hex digits, two per byte (e.g. 076578616d706c6503636f6d00).")
    else:
        inner = _name_part(_undefang(search.value))
        if "*" in inner or "[" in inner:
            issues.append("A lookup takes `*` only as `*.example.com` or `www.example.*`: use *Flexible: glob* for "
                          "other patterns.")
        if _REGEX_SIGNS.search(inner):
            issues.append("This looks like a regular expression: use *Flexible: regex*.")
    if search.after and search.before and search.after >= search.before:
        issues.append("*Seen after* is not before *Seen before*: nothing can match.")
    return issues


def notes(search):
    """Advice that does not stop the search (an option it ignores, a pattern that may miss)."""
    out = []
    value = clean_value(search.mode, search.value)
    if search.mode == "rdata_ip" and search.rrtype not in ("ANY", "A", "AAAA"):
        out.append("An IP search returns A and AAAA records only: the record type is not sent.")
    if search.mode == "glob" and value and not value.endswith(("*", ".")):
        out.append("DNSDB names end with a dot (`example.com.`): end the glob with `.` or `*` to match whole names.")
    if search.mode == "regex" and value and "^" not in value and "$" not in value:
        out.append("Not anchored: the regex matches anywhere in a name (`paypal` finds `mypaypal-help.com.`). Use `^` "
                   "for the start and `\\.$` for the end (names end with a dot).")
    return out


def _q(text, safe=""):
    return urllib.parse.quote(str(text), safe=safe)


def path(search):
    """The request path under API_BASE."""
    value = clean_value(search.mode, search.value)
    rrtype = search.rrtype or "ANY"
    if search.flex:
        return f"/{search.mode}/{search.field}/{_q(value)}" + (f"/{rrtype}" if rrtype != "ANY" else "")
    if search.mode == "rdata_ip":
        return f"/lookup/rdata/ip/{_q(value, safe=',-')}"
    kind, typ = {"rrset": ("rrset", "name"), "rrset_raw": ("rrset", "raw"), "rdata_name": ("rdata", "name"),
                 "rdata_raw": ("rdata", "raw")}[search.mode]
    tail = ""
    if search.mode == "rrset" and search.bailiwick.strip():
        tail = f"/{rrtype}/{_q(refang_domain(search.bailiwick) or search.bailiwick.strip(), safe='*')}"
    elif rrtype != "ANY":
        tail = f"/{rrtype}"
    return f"/lookup/{kind}/{typ}/{_q(value, safe='*')}{tail}"


def _time_params(search):
    params = {}
    if search.after:
        params["time_first_after" if search.strict else "time_last_after"] = int(search.after)
    if search.before:
        params["time_last_before" if search.strict else "time_first_before"] = int(search.before)
    return params


def params(search):
    """Query parameters, in a fixed order."""
    out = {"limit": int(search.limit)}
    if not search.flex and not search.aggregated:
        out["aggr"] = "f"
    out.update(_time_params(search))
    if search.flex and search.exclude.strip():
        out["exclude"] = search.exclude.strip()
    return {**out, **CLIENT}


def url(search):
    return f"{API_BASE}{path(search)}?{urllib.parse.urlencode(params(search), quote_via=urllib.parse.quote)}"


def curl(search):
    """curl with the key from $DNSDB_API_KEY; -g so curl leaves [ ] { } in a glob or regex alone."""
    return (f'curl -s -g -H "X-API-Key: $DNSDB_API_KEY" -H \'Accept: application/x-ndjson\' '
            f'{shlex.quote(url(search))}')


def _tail(parts, search, rrtype=True):
    """The options dnsdbq and dnsdbflex share: -t, -l, the time fence (-A, -B, -c)."""
    if rrtype and search.rrtype and search.rrtype != "ANY":
        parts += ["-t", search.rrtype]
    parts += ["-l", str(int(search.limit))]
    if search.after:
        parts += ["-A", str(int(search.after))]
    if search.before:
        parts += ["-B", str(int(search.before))]
    if search.strict and (search.after or search.before):
        parts.append("-c")
    return " ".join(parts)


def _flex_glob(search):
    """(method, pattern, field) of the dnsdbflex search for `search`, or None when dnsdbflex has none (IP, raw)."""
    value = clean_value(search.mode, search.value)
    if search.flex:
        return search.mode, value, search.field
    if search.mode not in ("rrset", "rdata_name"):
        return None   # Flexible Search indexes names and name-like values, not addresses or raw data
    if search.mode == "rdata_name" and search.rrtype not in FLEX_RDATA_TYPES:
        return None
    if search.mode == "rrset" and search.rrtype in DNSSEC_TYPES:
        return None
    pattern = value if value.endswith(("*", ".")) else f"{value}."   # DNSDB names end with a dot
    return "glob", pattern, "rrnames" if search.mode == "rrset" else "rdata"


def flex_cli(search):
    """
    The dnsdbflex command (Flexible Search: regex or glob; it returns the matching names or values, not their
    records). A name lookup becomes the same glob (`example.com` → `example.com.`, `*.example.com` →
    `*.example.com.`); "" for a search dnsdbflex cannot make (an IP, a raw value, a type it does not index).
    """
    flex = _flex_glob(search)
    if not flex:
        return ""
    method, pattern, field = flex
    parts = ["dnsdbflex", f"--{method}", shlex.quote(pattern)]
    if search.flex and search.exclude.strip():
        parts += ["--exclude", shlex.quote(search.exclude.strip())]
    parts += ["-s", field]
    return _tail(parts, search)


def cli(search):
    """
    The dnsdbq command, as DNSDB Scout writes it. A Flexible Search has no dnsdbq form of its own: dnsdbflex finds
    the names and hands them to dnsdbq for their records (`dnsdbflex … -F | dnsdbq -f -j`, one dnsdbq query per name).
    """
    if search.flex:
        return f"{flex_cli(search)} -F | dnsdbq -f -j"
    value = clean_value(search.mode, search.value)
    flag = {"rrset": "-r", "rrset_raw": "-R", "rdata_name": "-n", "rdata_ip": "-i", "rdata_raw": "-N"}[search.mode]
    if search.mode == "rdata_ip" and normalize_cidr(value.replace(",", "/")):
        value = value.replace(",", "/")   # dnsdbq writes a CIDR with a slash
    parts = ["dnsdbq", flag, shlex.quote(value)]
    if search.mode == "rrset" and search.bailiwick.strip():
        parts += ["-b", shlex.quote(search.bailiwick.strip())]
    if not search.aggregated:
        parts.append("-g")
    return _tail(parts, search, rrtype=search.mode != "rdata_ip")


def scout_state(search):
    """Scout's share object for the search (Scout's keys and order), or None when Scout has no form for it."""
    value = clean_value(search.mode, search.value)
    if search.mode == "rrset_raw" or not value:
        return None
    state = {}
    if search.flex:
        state.update(use_flexible_search=True, flexible_syntax=search.mode, flexible_search_val_raw=value)
        if search.exclude.strip():
            state["flexible_search_exclude_raw"] = search.exclude.strip()
        state["flexible_field"] = search.field
    else:
        state["use_standard_search"] = True
        if search.mode == "rrset":
            state.update(use_rrset=True, rrset_search_domain_raw=value)
            if search.bailiwick.strip():
                state["rrset_search_bailiwick_raw"] = search.bailiwick.strip()
        else:
            state.update(use_rdata=True, rrdata_search_domain_raw=value,
                         rdata_type={"rdata_ip": "ip", "rdata_name": "name", "rdata_raw": "raw"}[search.mode])
        if not search.aggregated:
            state["use_deaggregate"] = True
        state["verb_lookup"] = True
    if search.mode != "rdata_ip":
        state["rtype"] = search.rrtype or "ANY"
    if int(search.limit) != SCOUT_DEFAULT_LIMIT:
        state["limit"] = str(int(search.limit))
    if search.after or search.before:
        state["use_timefence"] = True
        if search.after:
            state.update(timefence_start=int(search.after), time_first_after=search.strict,
                         time_last_after=not search.strict, use_timefence_strict=search.strict)
        if search.before:
            state.update(timefence_end=int(search.before), time_last_before=search.strict,
                         time_first_before=not search.strict, use_timefence_strict=search.strict)
    return state


def scout_link(search):
    """The DNSDB Scout share link (opens Scout with the search filled in; Scout runs it with your Scout key), or ""."""
    state = scout_state(search)
    if not state:
        return ""
    encoded = base64.b64encode(json.dumps(state, separators=(",", ":"), ensure_ascii=False).encode()).decode()
    link = f"{SCOUT_URL}?share={_q(encoded)}"
    return link if len(link) <= SCOUT_MAX_LINK else ""


def scout_state_of(link):
    """The share object inside a Scout share link (for tests and for reading a pasted link), or None."""
    query = urllib.parse.parse_qs(urllib.parse.urlparse(str(link or "")).query)
    try:
        return json.loads(base64.b64decode(query["share"][0]))
    except (KeyError, IndexError, ValueError):
        return None


def describe(search):
    """One sentence: what the search asks DNSDB."""
    what = SEARCHES.get(search.mode, ("", ""))[1]
    value = clean_value(search.mode, search.value)
    if search.mode == "rdata_ip":
        value = value.replace(",", "/")   # the API's address,length read as a CIDR
    bits = [f"**{search.label}** for `{value}`" if value else f"**{search.label}**"]
    if search.flex:
        bits.append(f"in {FLEX_FIELDS[search.field].lower()}")
    if search.mode != "rdata_ip" and search.rrtype != "ANY":
        bits.append(f"type {search.rrtype}")
    if search.mode == "rrset" and search.bailiwick.strip():
        bits.append(f"bailiwick {search.bailiwick.strip()}")
    lead = what if what[1:2].isupper() else what[:1].lower() + what[1:]   # keep "DNS", lower "Names"
    return " ".join(bits) + f": {lead}."


def _epoch(value):
    if value in (None, ""):
        return pd.NaT
    parsed = pd.to_datetime(value, unit="s", errors="coerce", utc=True)
    return parsed.tz_localize(None) if pd.notna(parsed) else pd.NaT


def _rdata_text(rdata):
    return "\n".join(str(r) for r in rdata) if isinstance(rdata, list) else str(rdata or "")


def records_frame(records):
    """The returned records as a table (lookups: one row per RRset or value; flexible search: names or values)."""
    rows = []
    for obj in records or []:
        if not isinstance(obj, dict):
            continue
        rows.append({"RRName": str(obj.get("rrname") or "").rstrip("."), "RRType": str(obj.get("rrtype") or ""),
                     "RData": _rdata_text(obj.get("rdata")), "Bailiwick": str(obj.get("bailiwick") or "").rstrip("."),
                     "Count": obj.get("count"),
                     "First Seen": _epoch(obj.get("time_first") or obj.get("zone_time_first")),
                     "Last Seen": _epoch(obj.get("time_last") or obj.get("zone_time_last"))})
    frame = pd.DataFrame(rows, columns=RECORD_COLUMNS)
    frame["Count"] = pd.to_numeric(frame["Count"], errors="coerce").astype("Int64")
    return frame.drop(columns=[c for c in ("RRName", "RData", "Bailiwick", "Count", "First Seen", "Last Seen")
                               if frame[c].replace("", None).isna().all()]) if not frame.empty else frame


def _rdata_names(obj):
    """Host names in a record's value (CNAME / NS / MX / PTR / SRV / SOA)."""
    rrtype = str(obj.get("rrtype") or "").upper()
    if rrtype not in NAME_RDATA_TYPES:
        return []
    names = []
    for value in obj.get("rdata") if isinstance(obj.get("rdata"), list) else [obj.get("rdata")]:
        words = str(value or "").split()
        if not words:
            continue
        name = words[-1] if rrtype in ("MX", "SRV") else words[0]
        names.append(name.rstrip(".").lower())
    return [n for n in names if n and not is_ip_address(n)]


def _public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def targets(records, preselect=0, searched=""):
    """
    (domains, IPs) the records name, most records first, the first `preselect` ticked *Analyze*. Domains: the
    registered domains of the owner names (`Via` Owner name) and of host names in CNAME / NS / MX / PTR / SRV / SOA
    values (`Via` the record type); IPs: the public addresses in A / AAAA values. `searched` (the searched
    domain or IP address): left out.
    """
    domains, ips = {}, {}

    def add(table, key, via, name, seen):
        entry = table.setdefault(key, {"Via": [], "Records": 0, "Names": set(), "Last Seen": pd.NaT})
        if via not in entry["Via"]:
            entry["Via"].append(via)
        entry["Records"] += 1
        if name:
            entry["Names"].add(name)
        if pd.notna(seen) and (pd.isna(entry["Last Seen"]) or seen > entry["Last Seen"]):
            entry["Last Seen"] = seen

    skip = set()
    if searched:
        skip.add(searched if is_ip_address(searched) else registrable_domain(searched.lstrip("*.").rstrip(".*")))
    for obj in records or []:
        if not isinstance(obj, dict):
            continue
        seen = _epoch(obj.get("time_last") or obj.get("zone_time_last"))
        rrname = str(obj.get("rrname") or "").rstrip(".").lower()
        rrtype = str(obj.get("rrtype") or "").upper()
        if rrname and not rrname.endswith((".in-addr.arpa", ".ip6.arpa")):
            domain = registrable_domain(rrname)
            if domain and "." in domain and not is_ip_address(domain):
                add(domains, domain, "Owner name", rrname, seen)
        for name in _rdata_names(obj):
            domain = registrable_domain(name)
            if domain and "." in domain:
                add(domains, domain, rrtype, name, seen)
        if rrtype in ("A", "AAAA"):
            values = obj.get("rdata") if isinstance(obj.get("rdata"), list) else [obj.get("rdata")]
            for value in values:
                ip = str(value or "").strip()
                if is_ip_address(ip) and _public(ip):
                    add(ips, ip, rrtype, rrname, seen)

    def frame(table):
        rows = [{"Analyze": False, "Target": key, "Via": ", ".join(entry["Via"]), "Records": entry["Records"],
                 "Names": len(entry["Names"]), "Last Seen": entry["Last Seen"]}
                for key, entry in table.items() if key not in skip]
        out = pd.DataFrame(rows, columns=TARGET_COLUMNS)
        if out.empty:
            return out
        out = out.sort_values(["Records", "Target"], ascending=[False, True]).reset_index(drop=True)
        out.loc[out.index[:preselect], "Analyze"] = True
        return out

    return frame(domains), frame(ips)


def type_counts(records):
    """Records per record type, most first."""
    return pd.Series([str(o.get("rrtype") or "") for o in records or [] if isinstance(o, dict)],
                     dtype=str).value_counts()


MAX_VALUES = 1000   # lines one page turns into searches (commands and Scout links only)


def split_values(text):
    """The typed values, one per line (blank lines and repeats dropped, a trailing comma or semicolon removed)."""
    values = [line.strip().rstrip(",;").strip() for line in str(text or "").splitlines()]
    return list(dict.fromkeys(v for v in values if v))


def expand(template, values, auto=True, subdomains=False):
    """
    One Search per value, with `template`'s options: the search type detected per value (`auto`) or the template's
    own; `subdomains` turns a plain name (an RRset name lookup) into `*.name`, every name under it. Options that do not
    apply to a value's search type (bailiwick, Flexible Search field and exclusion) are dropped for it.
    """
    out = []
    for value in values[:MAX_VALUES]:
        mode = detect(value) if auto else template.mode
        if subdomains and mode == "rrset" and not value.startswith("*.") and not value.endswith(".*"):
            value = f"*.{value}"
        flex = SEARCHES[mode][2] == "flex"
        out.append(replace(template, mode=mode, value=value,
                           bailiwick=template.bailiwick if mode == "rrset" else "",
                           field=template.field if flex else "rrnames", exclude=template.exclude if flex else ""))
    return out


BATCH_COLUMNS = ["Value", "Search", "Problem", "Scout link", "curl", "dnsdbq", "dnsdbflex"]


def batch_frame(searches):
    """One row per search: the value as sent, its type, the first problem (if any), the Scout link and commands."""
    rows = []
    for search in searches:
        issues = problems(search)
        value = clean_value(search.mode, search.value)
        rows.append({"Value": value.replace(",", "/") if search.mode == "rdata_ip" else value, "Search": search.label,
                     "Problem": issues[0] if issues else "", "Scout link": "" if issues else scout_link(search),
                     "curl": curl(search), "dnsdbq": cli(search), "dnsdbflex": flex_cli(search)})
    return pd.DataFrame(rows, columns=BATCH_COLUMNS)


def mode_counts(values):
    """How many values each search type gets when detected per value: {label: count}, most first."""
    counts = pd.Series([SEARCHES[detect(v)][0] for v in values], dtype=str).value_counts()
    return dict(counts.items())


def listing(frame, column, labels=True):
    """
    The batch_frame `column` (curl, dnsdbq, dnsdbflex or Scout link) as one text to copy, lines with none left out.
    `labels`: each entry under a `# value · search type` line, entries a blank line apart; else one bare entry per line.
    """
    rows = [(row["Value"], row["Search"], row[column]) for _, row in frame.iterrows() if row[column]]
    if not labels:
        return "\n".join(entry for _, _, entry in rows)
    return "\n\n".join(f"# {value} · {search}\n{entry}" for value, search, entry in rows)

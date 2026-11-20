"""
IrisQL search: an Iris Investigate query written in IrisQL (one condition per line, AND on its own line) finds domains;
their records become a domain table and an IP table to pick the targets of an analysis run from.
"""
import ipaddress
import json
import re
import shlex

import pandas as pd

from config import IRIS_INVESTIGATE_BATCH_SIZE
from core.helpers import is_ip_address, normalize_cidr
from integrations.enrichment import extract_iris_profile, unwrap_value

HEADER = "# IrisQL-1.0"
ENDPOINT = "https://api.domaintools.com/v1/iris-investigate/"
SORT_FIELDS = ("", "risk_score", "create_date", "first_seen", "expiration_date", "domain")
EXAMPLES = {
    "Domain name contains a word": 'domain contains "domaintools"',
    "Risky look-alikes created recently": 'DOMAIN CONTAINS "bank"\nDOMAIN CONTAINS "finance"\nAND\n'
                                         'CREATE_DATE WITHIN "The last 30 days"\nAND\nRISK_SCORE GREATER_THAN 75',
    "Domains on the same IPs, created recently": 'IP IN ["198.202.211.1", "198.202.211.2"]\nAND\n'
                                                  'CREATE_DATE WITHIN "The last 30 days"',
    "Same registrant organization": 'REGISTRANT_ORG EXACTLY_MATCH "DomainTools, LLC"',
    "Same name server domain": 'NAMESERVER_DOMAIN MATCHES "example.com"\nAND\nFIRST_SEEN WITHIN "The last 7 days"',
    "Same Google Analytics 4 code": 'GA4 MATCHES "G-RPLVMKCB3Y"',
    "Website title and TLDs": 'WEBSITE_TITLE CONTAINS "login"\nAND\nTLD IN ["top", "xyz", "online"]\nAND\n'
                              'CREATE_DATE WITHIN "The last 30 days"',
}
DOMAIN_COLUMNS = ["Analyze", "Domain", "Risk Score", "Active", "Create Date", "First Seen", "Expiration Date",
                  "Registrar", "Registrant Org", "TLD", "IPs", "ASNs", "Countries", "Name Servers", "Website Title",
                  "Tags"]
IP_COLUMNS = ["Analyze", "IP", "Result Domains", "Iris Domains", "ASN", "ISP", "Country", "Domains"]
_CONDITION = re.compile(r"^\s*(\S+)\s+(\S+)\s+\S")
# Operators Iris accepts per field (Iris Investigate search reference); any other operator gets an HTTP 400.
_TEXT = ("BEGINS_WITH", "CONTAINS", "CONTAINS_ALL", "DOES_NOT_CONTAIN", "DOES_NOT_CONTAIN_ALL", "DOES_NOT_EXACTLY_MATCH",
         "DOES_NOT_MATCH", "EXACTLY_MATCH", "EXISTS", "MATCHES")
_RANGE = ("DOES_NOT_MATCH", "GREATER_THAN", "GREATER_THAN_OR_EQUAL", "LESS_THAN", "LESS_THAN_OR_EQUAL_TO", "MATCHES")
_DATE = _RANGE + ("WITHIN",)
_ADDRESS = _RANGE + ("IN", "NOT_IN")
_KEYWORD = ("BEGINS_WITH", "DOES_NOT_MATCH", "EXISTS", "MATCHES")
_LISTED = _KEYWORD + ("IN", "NOT_IN")
_PRESENCE = ("DOES_NOT_MATCH", "EXISTS", "MATCHES")
_CONTACT = ("BEGINS_WITH", "CONTAINS", "CONTAINS_ALL", "DOES_NOT_CONTAIN", "DOES_NOT_CONTAIN_ALL",
            "DOES_NOT_EXACTLY_MATCH", "EXACTLY_MATCH", "EXISTS")
_TRACKERS = ("ADSENSE", "BAIDU_ANALYTICS", "FACEBOOK", "GOOGLE_ANALYTICS", "GA4", "GOOGLE_TAG_MANAGER", "HOTJAR",
             "MATOMO", "STATCOUNTER_PROJECT", "STATCOUNTER_SECURITY", "YANDEX_METRICA")
FIELD_OPERATORS = {
    "DOMAIN": ("BEGINS_WITH", "CONTAINS", "DOES_NOT_CONTAIN", "DOES_NOT_EXACTLY_MATCH", "DOES_NOT_MATCH", "ENDS_WITH",
               "EXACTLY_IN", "EXACTLY_MATCH", "IN", "MATCHES", "NOT_EXACTLY_IN", "NOT_IN"),
    **dict.fromkeys(("CREATE_DATE", "EXPIRATION_DATE", "FIRST_SEEN", "SSL_NOT_AFTER", "SSL_NOT_BEFORE"), _DATE),
    **dict.fromkeys(("RANK", "RISK_SCORE", "ASN", "SSL_DURATION"), _RANGE),
    "ACTIVE": ("MATCHES",),
    "TAGS": ("CONTAINS", "CONTAINS_ALL", "DOES_NOT_CONTAIN", "DOES_NOT_CONTAIN_ALL"),
    **dict.fromkeys(("TLD", "EMAIL", "EMAIL_DOMAIN"), _LISTED),
    **dict.fromkeys(("WEBSITE_TITLE", "SERVER_TYPE", "REGISTRANT", "REGISTRANT_ORG", "REGISTRAR", "SSL_ORG"), _TEXT),
    "WHOIS": ("CONTAINS", "CONTAINS_ALL"),
    **dict.fromkeys(("CONTACT_NAME", "CONTACT_STREET"), _CONTACT),
    "ISP_NAME": tuple(op for op in _CONTACT if op != "BEGINS_WITH"),
    **dict.fromkeys(("IP", "NAMESERVER_IP", "MAILSERVER_IP"), _ADDRESS),
    **dict.fromkeys(("REDIRECT_DOMAIN", "CONTACT_PHONE", "IP_COUNTRY_CODE", "NAMESERVER_DOMAIN",
                     "MAILSERVER_DOMAIN", "ADMIN_CONTACT_EMAIL", "BILLING_CONTACT_EMAIL", "EMAIL_DNS_SOA",
                     "REGISTRANT_CONTACT_EMAIL", "TECHNICAL_CONTACT_EMAIL", "SSL_EMAIL", "SSL_HASH", "SSL_SUBJECT"),
                    _KEYWORD),
    "SSL_ALT_NAMES": ("BEGINS_WITH", "CONTAINS", "DOES_NOT_CONTAIN", "DOES_NOT_MATCH", "EXISTS", "MATCHES"),
    "SSL_ISSUER_COMMON_NAME": ("BEGINS_WITH", "CONTAINS", "DOES_NOT_CONTAIN", "DOES_NOT_MATCH", "ENDS_WITH", "MATCHES"),
    # name server and mail server hosts (FQDNs): MATCHES, DOES_NOT_MATCH and EXISTS only (no BEGINS_WITH / CONTAINS)
    **dict.fromkeys(("NAMESERVER_HOST", "MAILSERVER_HOST") + _TRACKERS, _PRESENCE),
    "HISTORICAL_REGISTRANT": ("MATCHES",),
}
# Fields the IrisQL reference lists without their operators: the editor suggests them (with the operator its examples
# use), but a query with them is not checked here; Iris decides.
UNCHECKED_FIELDS = {"MISC_EMAIL": _KEYWORD, "HISTORICAL_EMAIL": ("MATCHES",), "HISTORICAL_FREE_TEXT": ("MATCHES",)}
# WITHIN takes a relative date: "The last N day(s) / week(s) / month(s) / year(s)"
_WITHIN = re.compile(r'^\s*\S+\s+WITHIN\s+(.*?)\s*$', re.IGNORECASE)
_WINDOW = re.compile(r'^"the last [1-9][0-9]* (day|week|month|year)s?"$', re.IGNORECASE)


_CIDR = re.compile(r'"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}"')
TOO_MANY = "Maximum 10000"


def similar_query(target):
    """
    Domain profile's IrisQL search for a target: domains on the IP (an IP), on the range's addresses (a CIDR range:
    Iris takes no ranges, so the first and last address), or whose name contains the domain's first label.
    """
    target = str(target).strip()
    if is_ip_address(target):
        return f'# IrisQL-1.0\nip matches "{target}"'
    if cidr := normalize_cidr(target):
        network = ipaddress.ip_network(cidr)
        return (f'# IrisQL-1.0\nip greater_than_or_equal "{network[0]}"\nAND\n'
                f'ip less_than_or_equal_to "{network[-1]}"')
    return f'# IrisQL-1.0\nDOMAIN CONTAINS "{target.split(".")[0]}"'


# Iris Investigate refuses (HTTP 413) any query matching more than MAX_MATCHES domains, whatever page_size asks for;
# these conditions narrow a query under it
MAX_MATCHES = 10_000
NARROWING = {
    "Created in the last 30 days": 'CREATE_DATE WITHIN "The last 30 days"',
    "Created in the last 7 days": 'CREATE_DATE WITHIN "The last 7 days"',
    "First seen in the last 30 days": 'FIRST_SEEN WITHIN "The last 30 days"',
    "Risk score above 70": "RISK_SCORE GREATER_THAN 70",
    "Risk score above 90": "RISK_SCORE GREATER_THAN 90",
}
DEFAULT_NARROWING = ("Created in the last 30 days",)


def narrow(query, labels):
    """`query` with each NARROWING condition of `labels` ANDed on (conditions already in it are not repeated)."""
    text = str(query or "").rstrip()
    present = {line.strip().upper() for line in text.splitlines()}
    for label in labels or ():
        clause = NARROWING.get(label)
        if clause and clause.upper() not in present:
            text += f"\nAND\n{clause}"
            present.add(clause.upper())
    return text


def network_query(value, narrowing=DEFAULT_NARROWING):
    """
    IrisQL for the domains Iris sees on a routing artifact: an origin network (`AS13335` → `asn matches "13335"`) or an
    announced prefix (its first and last address, as similar_query), narrowed by `narrowing` (NARROWING labels; by
    default to domains created in the last 30 days, since a CDN or cloud network matches more than Iris returns).
    None for anything else.
    """
    text = str(value or "").strip().upper().rstrip("+")
    if text.startswith("AS") and text[2:].isdigit():
        query = f'# IrisQL-1.0\nasn matches "{int(text[2:])}"'
    elif normalize_cidr(text.lower()):
        query = similar_query(text.lower())
    else:
        return None
    return narrow(query, narrowing)


def error_hint(error):
    """What to do about an Iris answer that is about the query itself, or ''."""
    if TOO_MANY in str(error or ""):
        return (f"Iris refuses a query that matches more than {MAX_MATCHES:,} domains, whatever *Domains to fetch* "
                "or `page_size` ask for: it never returns the first N of a larger match. Narrow the query with one of "
                "the conditions below (or your own, e.g. `TLD IN`, `REGISTRAR`), then Search again.")
    if "not supported for this field" in str(error or ""):
        return "Each field takes its own operators; the warning above the Search button names the ones allowed."
    return ""


def operator_problem(line):
    """Why Iris would reject the operator of this condition (field-specific rules), or None; unknown fields pass."""
    match = _CONDITION.match(line)
    if not match:
        return None
    field, operator = match.group(1).split(":")[-1].upper(), match.group(2).upper()
    allowed = FIELD_OPERATORS.get(field)
    if allowed is None or operator in allowed:
        return None
    if operator == "DOES_NOT_EXIST" and "EXISTS" in allowed:
        return f"`{line}`: write `{field} EXISTS false` instead."
    better = " (`MATCHES` is the exact match here)" if operator == "EXACTLY_MATCH" and "MATCHES" in allowed else ""
    return f"`{line}`: {field} does not support {operator}{better}. Allowed: {', '.join(allowed)}."


def normalize(text):
    """
    The query as sent: trimmed, blank lines dropped, the `# IrisQL-1.0` version line added when missing. Comment lines
    (`#` / `//`) are dropped: the IrisQL reference documents no comments besides the version line.
    """
    lines = [line.rstrip() for line in str(text or "").strip().splitlines() if line.strip()]
    if lines and lines[0].strip().lower() == HEADER.lower():
        lines = lines[1:]
    lines = [line for line in lines if not line.strip().startswith(("#", "//"))]
    return "\n".join([HEADER] + lines)


def problems(query):
    """What is wrong with a normalized query before it is sent (Iris answers a 400 for these), or []."""
    body = [line.strip() for line in query.splitlines()[1:] if line.strip() and not line.strip().startswith("#")]
    if not body:
        return ["Add at least one condition, e.g. `domain contains \"domaintools\"`."]
    found = []
    if body[0].upper() == "AND" or body[-1].upper() == "AND":
        found.append("`AND` goes between two conditions, on its own line.")
    for line in body:
        if line.upper() != "AND" and not _CONDITION.match(line):
            found.append(f"`{line}` is not a condition (FIELD OPERATOR value, one per line).")
        elif re.search(r"\s(AND|OR)\s", re.sub(r'"[^"]*"', '""', line), flags=re.IGNORECASE):
            found.append(f"`{line}`: put each condition and each `AND` on its own line.")
        elif issue := operator_problem(line):
            found.append(issue)
        elif (within := _WITHIN.match(line)) and not _WINDOW.match(within.group(1)):
            found.append(f"`{line}`: `WITHIN` takes a relative date such as `\"The last 30 days\"` (days, weeks, "
                         "months or years).")
        elif _CIDR.search(line) and _CONDITION.match(line).group(1).split(":")[-1].upper().endswith("IP"):
            found.append(f"`{line}`: Iris does not take CIDR ranges; list the IPs (`IP IN [\"1.2.3.4\", \"1.2.3.5\"]`) or "
                         "use `IP GREATER_THAN_OR_EQUAL \"1.2.3.0\"` AND `IP LESS_THAN_OR_EQUAL_TO \"1.2.3.255\"`.")
    return found


def _values(items, key):
    out = []
    for item in items or []:
        value = unwrap_value(item.get(key)) if isinstance(item, dict) else item
        if value not in (None, "") and str(value) not in out:
            out.append(str(value))
    return out


def domain_frame(records, preselect=0):
    """One row per domain of an IrisQL answer; the `preselect` riskiest are ticked for analysis."""
    rows = []
    for record in records or []:
        if not isinstance(record, dict) or not record.get("domain"):
            continue
        profile = extract_iris_profile(record)
        risk = record.get("domain_risk") or {}
        rows.append({
            "Analyze": False,
            "Domain": str(record["domain"]).lower(),
            "Risk Score": risk.get("risk_score") if isinstance(risk, dict) else None,
            "Active": record.get("active"),
            "Create Date": profile["create_date"],
            "First Seen": profile["first_seen"],
            "Expiration Date": profile["expiration_date"],
            "Registrar": profile["registrar"],
            "Registrant Org": str(unwrap_value(record.get("registrant_org")) or ""),
            "TLD": str(record.get("tld") or ""),
            "IPs": ", ".join(ip["ip"] for ip in profile["ips"]),
            "ASNs": ", ".join(dict.fromkeys(str(ip["asn"]) for ip in profile["ips"] if ip["asn"])),
            "Countries": ", ".join(dict.fromkeys(ip["country"] for ip in profile["ips"] if ip["country"])),
            "Name Servers": ", ".join(profile["name_servers"]),
            "Website Title": str(record.get("website_title") or ""),
            "Tags": ", ".join(_values(record.get("tags"), "label")),
        })
    frame = pd.DataFrame(rows, columns=DOMAIN_COLUMNS).drop_duplicates("Domain")
    if preselect and not frame.empty:
        top = frame.sort_values("Risk Score", ascending=False, na_position="last").head(preselect).index
        frame.loc[top, "Analyze"] = True
    frame["Risk Score"] = pd.to_numeric(frame["Risk Score"], errors="coerce").astype("Int64")
    return frame.reset_index(drop=True)


def ip_frame(records):
    """One row per hosting IP of an IrisQL answer: how many result domains use it and how many domains Iris has on it."""
    seen = {}
    for record in records or []:
        if not isinstance(record, dict) or not record.get("domain"):
            continue
        for ip in extract_iris_profile(record)["ips"]:
            if not is_ip_address(ip["ip"]):
                continue
            row = seen.setdefault(ip["ip"], {"Analyze": False, "IP": ip["ip"], "Domains": [], "Iris Domains": ip["count"],
                                             "ASN": ip["asn"], "ISP": ip["isp"], "Country": ip["country"]})
            row["Domains"].append(str(record["domain"]).lower())
    rows = [{**row, "Result Domains": len(set(row["Domains"])), "Domains": ", ".join(sorted(set(row["Domains"])))}
            for row in seen.values()]
    frame = pd.DataFrame(rows, columns=IP_COLUMNS)
    for col in ("Iris Domains", "ASN"):
        frame[col] = pd.to_numeric(frame[col], errors="coerce").astype("Int64")
    return frame.sort_values(["Result Domains", "IP"], ascending=[False, True]).reset_index(drop=True)


def selected(frame, column):
    return frame.loc[frame["Analyze"].fillna(False).astype(bool), column].tolist() if not frame.empty else []


def query_cost(max_results, page_size):
    """Iris Investigate queries one search may use: one per page."""
    return max(1, -(-int(max_results) // int(page_size)))


def analysis_cost(domains):
    """Iris Investigate queries the analysis of `domains` uses (batches of 100); other sources count per domain."""
    return -(-len(domains) // IRIS_INVESTIGATE_BATCH_SIZE) if domains else 0


def commands(query, page_size, sort_by=""):
    """The same search as a DomainTools Python SDK command line, a curl command and a Python script (no credential values)."""
    params = {"page_size": page_size, **({"sort_by": sort_by} if sort_by else {})}
    flags = f" --page-size {page_size}" + (f" --sort-by {sort_by}" if sort_by else "")
    url = ENDPOINT + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    return {
        "DomainTools Python SDK": f"domaintools iris_investigate --irisql {shlex.quote(query)}{flags} "
                           '-u "$DT_API_USERNAME" -k "$DT_API_KEY"',
        "curl": f"curl -X POST '{url}' \\\n  -H \"X-Api-Key: $DT_API_KEY\" \\\n"
                f"  --data-binary @- <<'EOF' | jq .\n{query}\nEOF",
        "Python script": "import json, os\n\nfrom domaintools import API\n\n"
                      "api = API(os.environ[\"DT_API_USERNAME\"], os.environ[\"DT_API_KEY\"])\n"
                      f"results = api.iris_investigate(irisql={json.dumps(query)}, "
                      + ", ".join(f"{k}={json.dumps(v)}" for k, v in params.items()) + ").response()\n"
                      "print(json.dumps(results, indent=2))",
    }

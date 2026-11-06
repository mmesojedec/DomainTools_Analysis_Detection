"""
CertsQL search: a Certificate Search query written in CertsQL (one predicate per line, AND on its own line between
clauses) finds certificates; the domains and IPs they name become tables to pick the targets of an analysis run from.

The field and operator rules follow the Certificates API (technology preview) user guide: an invalid field-and-operator
combination, a wrong operand type or a query over the limits is answered with HTTP 400, so they are caught here first.
"""
import difflib
import json
import re
from datetime import date, timedelta

import pandas as pd

from core.cert_inputs import derive_hostnames, derive_targets

HEADER = "# CertsQL-1.0"
ENDPOINT = "https://api.domaintools.com/v1/certificates/search"
DOC_NOTE = "Certificates API (technology preview) user guide: CertsQL query language, operators and field catalog"

# --- operators -------------------------------------------------------------------------------------------------------
EQUALITY = ("equals", "does_not_equal")
MEMBERSHIP = ("in", "not_in")
PRESENCE = ("exists", "does_not_exist")
TEXT = ("begins_with", "does_not_begin_with", "ends_with", "does_not_end_with", "contains", "does_not_contain")
AFFIX = TEXT[:4]
RANGE = ("greater_than", "greater_than_or_equal", "less_than", "less_than_or_equal", "between")
OPERATORS = EQUALITY + MEMBERSHIP + PRESENCE + TEXT + RANGE
BASE = EQUALITY + MEMBERSHIP + PRESENCE   # every top-level field (booleans: no membership)
NOT_IN_API = {   # written in CertsQL material, answered "UNKNOWN_KEYWORD" by the API
    "within": "`within` is not supported by the Certificates API yet: use `between [\"YYYY-MM-DD\", \"YYYY-MM-DD\"]` "
              "or `greater_than` / `less_than` with a date.",
    "matches_element": "`matches_element ( … )` is not supported by the Certificates API yet: query the subfields "
                       "with dotted names (e.g. `certificate_policy.policy_oid equals \"2.23.140.1.2.1\"`), each on "
                       "its own clause.",
}

# --- field catalog: field -> value type ----------------------------------------------------------------------------
_TYPES = {
    "keyword": ("sha256", "sha1", "md5", "serial_number", "public_key_sha256", "authority_key_id", "subject_key_id",
                "san_fascn"),
    "text": ("issuer_common_name", "subject_common_name", "issuer_organization", "subject_organization",
             "issuer_locality", "subject_locality", "issuer_state_or_province", "subject_state_or_province",
             "issuer_organizational_unit", "subject_organizational_unit", "issuer_dc", "subject_dc",
             "san_krb5_principal", "san_permanent_identifier", "san_xmpp_jid"),
    "integer": ("validity_duration_days", "public_key_bits", "san_count", "tls_feature_ids"),
    "date": ("validity_not_before", "validity_not_after"),
    "boolean": ("is_self_signed", "is_precertificate", "has_wildcard_san", "has_embedded_scts"),
    "country": ("issuer_country", "subject_country"),
    "enum": ("public_key_algorithm", "public_key_curve", "signature_algorithm", "validation_level", "key_usage",
             "extended_key_usage"),
    "dn": ("issuer_dn", "subject_dn", "san_directory"),
    "dns": ("san_dns",),
    "ipv4": ("san_ip_v4",),
    "ipv6": ("san_ip_v6",),
    "uri": ("san_uri",),
    "email": ("subject_email_address", "san_upn", "san_smtp_utf8_mailbox"),
    "oid": ("extended_key_usage_oids", "extension_oids"),
    "nested": ("basic_constraints", "certificate_policy", "name_constraints", "signed_certificate_timestamp"),
}
FIELD_TYPES = {field: kind for kind, fields in _TYPES.items() for field in fields}
_FULL_TEXT = {"issuer_common_name", "subject_common_name", "issuer_organization", "subject_organization",
              "issuer_organizational_unit", "subject_organizational_unit", "san_dns", "san_krb5_principal",
              "san_permanent_identifier", "san_xmpp_jid"}
_AFFIX_TEXT = {"issuer_locality", "subject_locality", "issuer_state_or_province", "subject_state_or_province",
               "issuer_dc", "subject_dc"}
_RANGED = {"validity_not_before", "validity_not_after", "validity_duration_days", "public_key_bits", "san_count",
           "san_ip_v4", "san_ip_v6"}


def _top_level_operators(field):
    kind = FIELD_TYPES[field]
    if kind == "nested":
        return PRESENCE
    allowed = EQUALITY + PRESENCE if kind == "boolean" else BASE
    if field in _FULL_TEXT:
        allowed += TEXT
    elif field in _AFFIX_TEXT:
        allowed += AFFIX
    if field in _RANGED:
        allowed += RANGE
    return allowed


_INT_RANGE = EQUALITY + MEMBERSHIP + RANGE[:4] + ("between",) + PRESENCE
_LIST = EQUALITY + MEMBERSHIP + PRESENCE
SUBFIELDS = {   # nested-object subfield -> (value type, operators)
    "basic_constraints.is_ca": ("boolean", EQUALITY + PRESENCE),
    "basic_constraints.max_path_len": ("integer", _INT_RANGE),
    "basic_constraints.critical": ("boolean", EQUALITY + PRESENCE),
    "certificate_policy.policy_oid": ("oid", ("equals", "in", "exists")),
    "certificate_policy.cps_uris": ("uri", ("equals", "exists")),
    "certificate_policy.user_notices": ("text", ("equals", "contains", "exists")),
    **dict.fromkeys(("name_constraints.permitted_dns", "name_constraints.excluded_dns"), ("dns", _LIST + TEXT)),
    **dict.fromkeys(("name_constraints.permitted_ip_ranges", "name_constraints.excluded_ip_ranges"), ("cidr", _LIST)),
    **dict.fromkeys(("name_constraints.permitted_email", "name_constraints.excluded_email"), ("email", _LIST)),
    **dict.fromkeys(("name_constraints.permitted_uri", "name_constraints.excluded_uri"), ("uri", _LIST)),
    **dict.fromkeys(("name_constraints.permitted_directory", "name_constraints.excluded_directory"),
                    ("dn", EQUALITY + PRESENCE)),
    "name_constraints.critical": ("boolean", EQUALITY + PRESENCE),
    "signed_certificate_timestamp.log_id": ("keyword", ("equals", "in", "exists")),
    "signed_certificate_timestamp.timestamp": ("date", ("equals",) + RANGE + ("exists",)),
    "signed_certificate_timestamp.version": ("integer", ("equals", "in", "exists")),
}
FIELDS = {**{field: (kind, _top_level_operators(field)) for field, kind in FIELD_TYPES.items()}, **SUBFIELDS}

# Certificate Search sorts every match by one certificate field before paging (text, multi-value and nested fields
# are not sortable): field -> (label, (wording of descending, wording of ascending)). sha256 ascending is the API default.
SORT_FIELDS = {
    "validity_not_before": ("Issue date", ("Newest first", "Oldest first")),
    "validity_not_after": ("Expiry date", ("Latest expiry first", "Soonest expiry first")),
    "validity_duration_days": ("Validity length", ("Longest first", "Shortest first")),
    "public_key_bits": ("Key size", ("Largest first", "Smallest first")),
    "sha256": ("SHA-256", ("f → 0", "0 → f (API default)")),
}
SORT_ORDERS = ("desc", "asc")
DEFAULT_SORT = ("validity_not_before", "desc")


def sort_term(field, order):
    """The request's sort term for `field` / `order`; None for the API default (SHA-256 ascending, sent as no sort)."""
    if field not in SORT_FIELDS or order not in SORT_ORDERS:
        raise ValueError(f"not a sortable field and order: {field!r} {order!r}")
    return None if (field, order) == ("sha256", "asc") else {"field": field, "order": order}


def order_label(field, order):
    """How `order` reads for `field`: "Newest first"."""
    return SORT_FIELDS[field][1][SORT_ORDERS.index(order)]


def sort_text(term):
    """A sort term as one phrase, for the results line: "issue date, newest first"."""
    if not term:
        return "SHA-256, the API default"
    if isinstance(term, str):   # a search kept from before the sort became field + order
        return term
    label, words = SORT_FIELDS.get(term["field"], (term["field"], ("descending", "ascending")))
    return f"{label[0].lower() + label[1:]}, {words[SORT_ORDERS.index(term.get('order', 'asc'))].lower()}"
LIMITS = {"clauses": 32, "per_clause": 256, "predicates": 1024, "bytes": 65536, "array": 1000}
CONTAINS_MIN, CONTAINS_MAX = 3, 63

CERTIFICATE_COLUMNS = ["Use", "Common Name", "SANs", "Issuer", "Validation", "Not Before", "Not After", "Days",
                       "Key", "Self-signed", "SHA-256", "Public Key SHA-256"]
_LINE = re.compile(r"^\s*(\S+)\s+(\S+)(?:\s+(.*\S))?\s*$")


def examples(today=None):
    """Example queries, with dates relative to `today` (CertsQL has no relative dates)."""
    today = today or date.today()
    ago_30, ago_365, in_30 = (today - timedelta(days=30)).isoformat(), (today - timedelta(days=365)).isoformat(), \
        (today + timedelta(days=30)).isoformat()
    now = today.isoformat()
    return {
        "Certificates for a domain and its subdomains": 'san_dns equals "domaintools.com"\n'
                                                        'san_dns ends_with ".domaintools.com"',
        "Brand look-alikes on new certificates": f'san_dns contains "domaintools"\nAND\n'
                                                 f'validity_not_before greater_than "{ago_30}"',
        "Login hostnames from free CAs, last 30 days": 'san_dns contains "login"\nAND\n'
                                                       'issuer_organization in ["Let\'s Encrypt", "ZeroSSL", '
                                                       '"Google Trust Services"]\nAND\n'
                                                       f'validity_not_before greater_than "{ago_30}"',
        "Expiring in the next 30 days": 'san_dns ends_with ".domaintools.com"\nAND\n'
                                        f'validity_not_after between ["{now}", "{in_30}"]',
        "Same public key (key reuse)": 'public_key_sha256 equals '
                                       '"a7409242e3852e39c175789f4debfb16d998a595a9da21a0f46aaae197305ef8"',
        "Self-signed, still valid": f'is_self_signed equals true\nAND\nvalidity_not_after greater_than "{now}"\nAND\n'
                                    'san_dns contains "login"',
        "Weak RSA keys, still valid": 'public_key_algorithm equals "rsa"\nAND\npublic_key_bits less_than 2048\nAND\n'
                                      f'validity_not_after greater_than "{now}"',
        "Long validity": 'validity_duration_days greater_than 200\nAND\n'
                         'is_self_signed equals false\nAND\n'
                         f'validity_not_before greater_than "{ago_365}"',
        "Non-CA certificates with critical basic constraints": 'basic_constraints.is_ca equals false\nAND\n'
                                                               'basic_constraints.critical equals true\nAND\n'
                                                               'san_dns ends_with ".domaintools.com"',
        "Brand names not issued to the brand": 'san_dns contains "domaintools"\nAND\n'
                                               'subject_organization does_not_equal "DomainTools, LLC"',
        "DV policy, no subject organization": 'certificate_policy.policy_oid equals "2.23.140.1.2.1"\nAND\n'
                                              'subject_organization does_not_exist true\nAND\n'
                                              'san_dns ends_with ".domaintools.com"',
    }


def normalize(text):
    """The query as sent: trimmed, blank lines dropped, the `# CertsQL-1.0` version line added when missing."""
    lines = [line.rstrip() for line in str(text or "").strip().splitlines() if line.strip()]
    if not lines or lines[0].strip().lower() != HEADER.lower():
        lines.insert(0, HEADER)
    else:
        lines[0] = HEADER
    return "\n".join(lines)


def _is_comment(line):
    return line.startswith("#") or line.startswith("//")


def _clauses(query):
    """[[predicate lines]] split at AND lines; None marks an empty clause (AND first, last or twice)."""
    clauses, current = [], []
    for line in (line.strip() for line in query.splitlines()[1:]):
        if not line or _is_comment(line):
            continue
        if line.upper() == "AND":
            clauses.append(current or None)
            current = []
        else:
            current.append(line)
    clauses.append(current or None)
    return clauses


def _operand_problem(field, kind, operator, value, line):
    if operator in PRESENCE:
        return None if value is True else f"`{line}`: `{operator}` takes the operand `true`."
    if operator in MEMBERSHIP:
        if not isinstance(value, list) or not value:
            return f"`{line}`: `{operator}` takes a non-empty JSON array, e.g. `[\"a\", \"b\"]`."
        if len(value) > LIMITS["array"]:
            return f"`{line}`: at most {LIMITS['array']:,} values in one `{operator}` array."
        values = value
    elif operator == "between":
        if not isinstance(value, list) or len(value) != 2:
            return f"`{line}`: `between` takes two values, `[min, max]`."
        values = value
    else:
        if isinstance(value, list):
            return f"`{line}`: `{operator}` takes one value, not an array (use `in` for a list)."
        values = [value]
    for item in values:
        if kind == "boolean" and not isinstance(item, bool):
            return f"`{line}`: {field} is true or false, without quotes."
        if kind == "integer" and (isinstance(item, bool) or not isinstance(item, int)):
            return f"`{line}`: {field} is a number, without quotes."
        if kind == "date" and not (isinstance(item, str) or (isinstance(item, int) and not isinstance(item, bool))):
            return f"`{line}`: {field} is a date: `\"YYYY-MM-DD\"` (or ISO 8601 with time, UTC)."
        if kind not in ("boolean", "integer", "date") and not isinstance(item, str):
            return f"`{line}`: {field} values are quoted strings."
    if operator in ("contains", "does_not_contain") and not CONTAINS_MIN <= len(str(value).strip()) <= CONTAINS_MAX:
        return f"`{line}`: `{operator}` takes {CONTAINS_MIN} to {CONTAINS_MAX} characters."
    if kind == "country" and any(len(str(item)) != 2 for item in values):
        return f"`{line}`: country codes are two letters (ISO 3166-1 alpha-2), e.g. \"US\"."
    return None


def _predicate_problem(line):
    match = _LINE.match(line)
    if not match:
        return f"`{line}` is not a predicate (field operator value, one per line)."
    field, operator, operand = match.group(1).lower(), match.group(2).lower(), match.group(3)
    if operator in NOT_IN_API:
        return f"`{line}`: {NOT_IN_API[operator]}"
    if field not in FIELDS:
        close = difflib.get_close_matches(field, list(FIELDS), n=1)
        return f"`{line}`: unknown field `{field}`" + (f" (did you mean `{close[0]}`?)" if close else "") + "."
    kind, allowed = FIELDS[field]
    if operator not in OPERATORS:
        close = difflib.get_close_matches(operator, OPERATORS, n=1)
        return f"`{line}`: unknown operator `{operator}`" + (f" (did you mean `{close[0]}`?)" if close else "") + "."
    if operator not in allowed:
        hint = " Nested objects only take `exists true` / `does_not_exist true`; query a subfield with a dotted name " \
               f"(e.g. `{next(s for s in SUBFIELDS if s.startswith(field + '.'))}`)." if kind == "nested" else ""
        return f"`{line}`: {field} does not support `{operator}`. Allowed: {', '.join(allowed)}.{hint}"
    if operand is None:
        return f"`{line}`: add a value after `{operator}`."
    try:
        value = json.loads(operand)
    except ValueError:
        return f"`{line}`: the value must be JSON: quote text (`\"text\"`), numbers and true / false without quotes."
    return _operand_problem(field, kind, operator, value, line)


def problems(query):
    """What the Certificates API would reject in a normalized query (HTTP 400), or []."""
    clauses = _clauses(query)
    if clauses == [None]:
        return ["Add at least one predicate, e.g. `san_dns ends_with \".example.com\"`."]
    found = []
    if None in clauses:
        found.append("`AND` goes between two predicates, on its own line (no `AND` first, last or twice in a row).")
    clauses = [clause for clause in clauses if clause]
    block = False   # inside a `field matches_element (` … `)` block: reported once, on its first line
    for line in (line for clause in clauses for line in clause):
        if block or line == ")":
            block = line != ")"
            continue
        block = line.endswith("(")
        if re.search(r"\s(AND|OR)\s", re.sub(r'"(?:\\.|[^"\\])*"', '""', line), flags=re.IGNORECASE):
            found.append(f"`{line}`: put each predicate and each `AND` on its own line (lines in one clause are "
                         "OR'ed, so no `OR` is needed).")
        elif issue := _predicate_problem(line):
            found.append(issue)
    if len(clauses) > LIMITS["clauses"]:
        found.append(f"At most {LIMITS['clauses']} clauses (AND-separated groups) per query.")
    if any(len(clause) > LIMITS["per_clause"] for clause in clauses):
        found.append(f"At most {LIMITS['per_clause']} predicate lines in one clause.")
    if sum(len(clause) for clause in clauses) > LIMITS["predicates"]:
        found.append(f"At most {LIMITS['predicates']:,} predicate lines per query.")
    if len(query.encode()) > LIMITS["bytes"]:
        found.append(f"The query is over {LIMITS['bytes']:,} bytes.")
    return found


def error_hint(error):
    """What to do about a Certificate Search answer that is about the query itself, or ''."""
    text = str(error or "")
    if "UNKNOWN_KEYWORD" in text:
        return ("The API did not recognize a keyword: `within` and `matches_element` are not supported yet, and every "
                "field and operator is lowercase snake_case (`san_dns ends_with`).")
    if re.search(r"\b50[234]\b", text) or "timed out" in text.lower() or "Connection error" in text:
        return ("The Certificates API (technology preview) is not answering right now; the query itself may be fine. "
                "Try again in a few minutes. Successful searches are cached, so a retry costs nothing for them.")
    if "HTTP 422" in text:
        return "A request value is out of bounds (the page size is 1 to 500)."
    if "HTTP 400" in text:
        return "The query was rejected; the message names the line or value. The checks above the Search button " \
               "follow the CertsQL field catalog."
    return ""


# --- result tables ---------------------------------------------------------------------------------------------------
class _Source:
    """Stands in for a certificate input in cert_inputs.derive_targets: every target comes from the query."""
    label = "CertsQL"


def _key(hit):
    algorithm, bits, curve = hit.get("public_key_algorithm"), hit.get("public_key_bits"), hit.get("public_key_curve")
    return " ".join(str(part) for part in (algorithm, curve or bits) if part)


def certificate_frame(hits):
    """One row per certificate of a CertsQL answer, newest first; all are used for the domain and IP tables."""
    rows = [{
        "Use": True,
        "Common Name": hit.get("subject_common_name") or "",
        "SANs": ", ".join([*(hit.get("san_dns") or []), *(hit.get("san_ip_v4") or []), *(hit.get("san_ip_v6") or [])]),
        "Issuer": hit.get("issuer_organization") or hit.get("issuer_common_name") or "",
        "Validation": str(hit.get("validation_level") or "").upper(),
        "Not Before": str(hit.get("validity_not_before") or "")[:10],
        "Not After": str(hit.get("validity_not_after") or "")[:10],
        "Days": hit.get("validity_duration_days"),
        "Key": _key(hit),
        "Self-signed": bool(hit.get("is_self_signed")),
        "SHA-256": hit.get("sha256") or "",
        "Public Key SHA-256": hit.get("public_key_sha256") or "",
    } for hit in hits or [] if isinstance(hit, dict)]
    frame = pd.DataFrame(rows, columns=CERTIFICATE_COLUMNS).drop_duplicates("SHA-256")
    frame["Days"] = pd.to_numeric(frame["Days"], errors="coerce").astype("Int64")
    return frame.sort_values("Not Before", ascending=False, kind="stable").reset_index(drop=True)


def used_hits(hits, certificates):
    """The hits whose certificate row is ticked *Use*."""
    used = set(certificates.loc[certificates["Use"].astype(bool), "SHA-256"]) if not certificates.empty else set()
    return [hit for hit in hits or [] if hit.get("sha256") in used]


def target_frames(hits, preselect=0):
    """(domains, IPs, hostnames) the certificates name; the `preselect` most-named domains / IPs are ticked."""
    derived = derive_targets([(_Source, hits, [])], max_selected=0)
    derived = derived.drop(columns=["Seeds"])
    frames = []
    for kind in ("Domain", "IP"):
        frame = derived[derived["Type"] == kind].drop(columns=["Type"]).reset_index(drop=True)
        frame["Analyze"] = frame.index < preselect
        frames.append(frame)
    hostnames = derive_hostnames([(_Source, hits, [])]).drop(columns=["Focus", "Seeds"])
    return frames[0], frames[1], hostnames


def selected(frame, column):
    return frame.loc[frame["Analyze"].astype(bool), column].tolist() if not frame.empty else []


def query_cost(max_results, page_size):
    """Certificate Search requests one search may use: one per page."""
    return max(1, -(-int(max_results) // int(page_size)))


def payload(query, limit, sort=None):
    return {"query_string": query, "limit": int(limit), **({"sort": [sort]} if sort else {})}


def commands(query, limit, sort=None):
    """The same search as curl and Python code; the key comes from $DT_CERT_API_KEY, else $DT_API_KEY (no values)."""
    body = json.dumps(payload(query, limit, sort), indent=2)
    return {
        "curl": f"curl -X POST '{ENDPOINT}' \\\n  -H \"X-Api-Key: ${{DT_CERT_API_KEY:-$DT_API_KEY}}\" -H 'Content-Type: application/json' "
                f"\\\n  --data-binary @- <<'EOF' | jq .\n{body}\nEOF",
        "Python (requests)": "import json, os, requests\n\n"
                             f"body = {body}\n"
                             f"response = requests.post({json.dumps(ENDPOINT)}, json=body, timeout=60,\n"
                             "    headers={\"X-Api-Key\": os.environ.get(\"DT_CERT_API_KEY\") or os.environ[\"DT_API_KEY\"]})\n"
                             "response.raise_for_status()\n"
                             "answer = response.json()\n"
                             "print(json.dumps(answer, indent=2))\n"
                             "# answer[\"hits\"], answer[\"total\"]; send answer[\"cursor\"] back as body[\"cursor\"] "
                             "for the next page",
    }

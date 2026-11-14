"""
CertsQL search: a Certificate Search query written in CertsQL (one predicate per line, AND on its own line between
clauses) finds certificates; the domains and IPs they name become tables to pick the targets of an analysis run from.

The field and operator rules follow the Certificates API (technology preview) user guide and its latest release notes
(ja4x; part fields `.local_part` / `.domain` / `.host` / `.scheme`; `within`, `contains_ip` and `overlaps_range` on IP
range fields, which no longer take equals / in; `arc_begins_with` on OIDs; `matches_element` blocks; at least one
predicate that is not negated): an invalid field-and-operator combination, a wrong operand type or a query over the
limits is answered with HTTP 400, so they are caught here first.
"""
import difflib
import ipaddress
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
IP_RANGE = ("within", "contains_ip", "overlaps_range")   # IP range fields: the range lies in / holds / overlaps
OID_PREFIX = ("arc_begins_with",)                      # OID fields: whole arcs, "1.3.6.1" matches 1.3.6.1.x, not 1.3.6.10
ELEMENT = ("matches_element", "does_not_match_element")   # `field matches_element (` … `)`: one element matches all
OPERATORS = EQUALITY + MEMBERSHIP + PRESENCE + TEXT + RANGE + IP_RANGE + OID_PREFIX + ELEMENT
BASE = EQUALITY + MEMBERSHIP + PRESENCE   # every top-level field (booleans: no membership)
NEGATED = frozenset(("does_not_equal", "not_in", "does_not_exist", "does_not_begin_with", "does_not_end_with",
                     "does_not_contain", "does_not_match_element"))
JA4X = re.compile(r"^[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$")
_OID = re.compile(r"^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))*$")

# --- field catalog: field -> value type ----------------------------------------------------------------------------
_TYPES = {
    "keyword": ("sha256", "sha1", "md5", "serial_number", "public_key_sha256", "authority_key_id", "subject_key_id",
                "san_fascn"),
    "ja4x": ("ja4x",),   # JA4X: how the certificate was generated (issuer RDN, subject RDN and extension OID hashes)
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
        return PRESENCE + ELEMENT
    allowed = EQUALITY + PRESENCE if kind == "boolean" else BASE
    if field in _FULL_TEXT:
        allowed += TEXT
    elif field in _AFFIX_TEXT:
        allowed += AFFIX
    if field in _RANGED:
        allowed += RANGE
    if kind == "oid":
        allowed += OID_PREFIX
    if kind in ("email", "uri"):   # multi-value with part fields: bind parts to the same address
        allowed += ELEMENT
    return allowed


_INT_RANGE = EQUALITY + MEMBERSHIP + RANGE[:4] + ("between",) + PRESENCE
_LIST = EQUALITY + MEMBERSHIP + PRESENCE
SUBFIELDS = {   # nested-object subfield -> (value type, operators)
    "basic_constraints.is_ca": ("boolean", EQUALITY + PRESENCE),
    "basic_constraints.max_path_len": ("integer", _INT_RANGE),
    "basic_constraints.critical": ("boolean", EQUALITY + PRESENCE),
    "certificate_policy.policy_oid": ("oid", ("equals", "in", "exists") + OID_PREFIX),
    "certificate_policy.cps_uris": ("uri", ("equals", "exists")),
    "certificate_policy.user_notices": ("text", ("equals", "contains", "exists")),
    **dict.fromkeys(("name_constraints.permitted_dns", "name_constraints.excluded_dns"), ("dns", _LIST + TEXT)),
    **dict.fromkeys(("name_constraints.permitted_ip_ranges", "name_constraints.excluded_ip_ranges"),
                    ("ip_range", IP_RANGE + PRESENCE)),
    **dict.fromkeys(("name_constraints.permitted_email", "name_constraints.excluded_email"), ("email", _LIST)),
    **dict.fromkeys(("name_constraints.permitted_uri", "name_constraints.excluded_uri"), ("uri", _LIST)),
    **dict.fromkeys(("name_constraints.permitted_directory", "name_constraints.excluded_directory"),
                    ("dn", EQUALITY + PRESENCE)),
    "name_constraints.critical": ("boolean", EQUALITY + PRESENCE),
    "signed_certificate_timestamp.log_id": ("keyword", ("equals", "in", "exists")),
    "signed_certificate_timestamp.timestamp": ("date", ("equals",) + RANGE + ("exists",)),
    "signed_certificate_timestamp.version": ("integer", ("equals", "in", "exists")),
}
# Part fields: one part of an email address (local_part, domain) or a URI (host, scheme), as `field.part`. URI fields
# differ in which parts they have: a name-constraint URI is a host pattern, so it has no scheme.
_PART_OPERATORS = {"local_part": ("text", _LIST + TEXT), "domain": ("dns", _LIST + TEXT),
                   "host": ("dns", _LIST + TEXT), "scheme": ("enum", _LIST)}
_PARTS = {
    **dict.fromkeys(("subject_email_address", "san_upn", "san_smtp_utf8_mailbox"), ("local_part", "domain")),
    **dict.fromkeys(("san_uri", "certificate_policy.cps_uris"), ("host", "scheme")),
    **dict.fromkeys(("name_constraints.permitted_uri", "name_constraints.excluded_uri"), ("host",)),
}
PART_FIELDS = {f"{field}.{part}": _PART_OPERATORS[part] for field, parts in _PARTS.items() for part in parts}
FIELDS = {**{field: (kind, _top_level_operators(field)) for field, kind in FIELD_TYPES.items()}, **SUBFIELDS,
          **PART_FIELDS}
ELEMENT_FIELDS = tuple(field for field, (_, operators) in FIELDS.items() if "matches_element" in operators)


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
                       "Key", "Self-signed", "SHA-256", "Public Key SHA-256", "JA4X"]
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
        "JA4X: Sliver / Havoc C2 certificates, still valid": 'ja4x in ["000000000000_4f24da86fad6_bf0f0589fc03", '
                                                             '"000000000000_7c32fa18c13e_bf0f0589fc03"]\nAND\n'
                                                             f'validity_not_after greater_than "{now}"',
        "JA4X: Cobalt Strike default certificate, last 30 days": 'ja4x equals '
                                                                 '"2166164053c1_2166164053c1_30d204a01551"\nAND\n'
                                                                 f'validity_not_before greater_than "{ago_30}"',
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


_BLOCK = re.compile(r"^(\S+)\s+(matches_element|does_not_match_element)\s*\($", flags=re.IGNORECASE)


def _clauses(query):
    """
    [[items]] split at AND lines; None marks an empty clause (AND first, last or twice). An item is a predicate line,
    or a `field matches_element (` … `)` block as a tuple of its lines (AND lines inside the block stay in it).
    """
    clauses, current, block = [], [], None
    for line in (line.strip() for line in query.splitlines()[1:]):
        if not line or _is_comment(line):
            continue
        if block is not None:
            block.append(line)
            if line == ")":
                current.append(tuple(block))
                block = None
        elif line.upper() == "AND":
            clauses.append(current or None)
            current = []
        elif _BLOCK.match(line):
            block = [line]
        else:
            current.append(line)
    if block is not None:   # never closed
        current.append(tuple(block))
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
    if kind == "ja4x" and any(not JA4X.match(item) for item in values):
        return (f"`{line}`: a JA4X fingerprint is three 12-character lowercase hex parts joined by `_`, e.g. "
                "`\"2166164053c1_2166164053c1_30d204a01551\"`.")
    if operator == "arc_begins_with" and not _OID.match(value):
        return f"`{line}`: `arc_begins_with` takes a dotted OID prefix of whole arcs, e.g. `\"1.3.6.1.4.1\"`."
    if operator == "contains_ip" and not _is_ip(value):
        return f"`{line}`: `contains_ip` takes one IP address, e.g. `\"10.1.2.3\"`."
    if operator in ("within", "overlaps_range") and not _is_network(value):
        return f"`{line}`: `{operator}` takes an IP range in CIDR notation, e.g. `\"10.0.0.0/8\"`."
    return None


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_network(value):
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        return False
    return True


def _not_allowed(line, field, kind, operator, allowed):
    hint = ""
    if kind == "nested":
        hint = (" Nested objects take `exists true` / `does_not_exist true` or a `matches_element (` … `)` block; "
                f"query a subfield with a dotted name (e.g. `{next(s for s in SUBFIELDS if s.startswith(field + '.'))}`).")
    elif operator in ELEMENT:
        hint = f" `{operator}` works on {', '.join(ELEMENT_FIELDS)}."
    elif operator == "within" and kind == "date":
        hint = " `within` is for IP ranges; for a date window use `between [\"YYYY-MM-DD\", \"YYYY-MM-DD\"]`."
    elif kind == "ip_range":
        hint = " IP range fields take `within` / `overlaps_range` with a CIDR, or `contains_ip` with an address."
    return f"`{line}`: {field} does not support `{operator}`. Allowed: {', '.join(allowed)}.{hint}"


def _predicate_problem(line, parent=None):
    """What is wrong with one predicate line, or None; inside a `matches_element` block the field is relative to
    `parent` (`policy_oid` means `certificate_policy.policy_oid`)."""
    match = _LINE.match(line)
    if not match:
        return f"`{line}` is not a predicate (field operator value, one per line)."
    field, operator, operand = match.group(1).lower(), match.group(2).lower(), match.group(3)
    if parent:
        field = f"{parent}.{field}"
    if field not in FIELDS:
        names = [name for name in FIELDS if not parent or name.startswith(parent + ".")]
        close = difflib.get_close_matches(field, names, n=1)
        close = [name[len(parent) + 1:] for name in close] if parent else close
        where = f" in {parent}" if parent else ""
        return f"`{line}`: unknown field `{match.group(1)}`{where}" + (f" (did you mean `{close[0]}`?)" if close else "") + "."
    kind, allowed = FIELDS[field]
    if operator not in OPERATORS:
        close = difflib.get_close_matches(operator, OPERATORS, n=1)
        return f"`{line}`: unknown operator `{operator}`" + (f" (did you mean `{close[0]}`?)" if close else "") + "."
    if operator in ELEMENT and operator in allowed:
        return f"`{line}`: `{operator}` opens a block: end the line with `(`, put the predicates on the next lines " \
               "and close it with `)` on its own line."
    if operator not in allowed:
        return _not_allowed(line, field, kind, operator, allowed)
    if operand is None:
        return f"`{line}`: add a value after `{operator}`."
    try:
        value = json.loads(operand)
    except ValueError:
        return f"`{line}`: the value must be JSON: quote text (`\"text\"`), numbers and true / false without quotes."
    return _operand_problem(field, kind, operator, value, line)


def _block_problems(block):
    """What is wrong with a `field matches_element (` … `)` block: its field and operator, its closing `)`, and each
    predicate in it (fields relative to the block's field, AND lines between its clauses)."""
    header = block[0]
    match = _BLOCK.match(header)
    parent, operator = match.group(1).lower(), match.group(2).lower()
    if parent not in FIELDS:
        close = difflib.get_close_matches(parent, ELEMENT_FIELDS, n=1)
        return [f"`{header}`: unknown field `{parent}`" + (f" (did you mean `{close[0]}`?)" if close else "") + "."]
    kind, allowed = FIELDS[parent]
    if operator not in allowed:
        return [_not_allowed(header, parent, kind, operator, allowed)]
    found = []
    closed = block[-1] == ")"
    inner = list(block[1:-1] if closed else block[1:])
    if not closed:
        found.append(f"`{header}`: close the block with `)` on its own line.")
    groups, current = [], []
    for line in inner:
        if line.upper() == "AND":
            groups.append(current)
            current = []
        else:
            current.append(line)
    groups.append(current)
    if not any(groups):
        found.append(f"`{header}`: put at least one predicate between `(` and `)`.")
    elif not all(groups):
        found.append(f"`{header}`: `AND` goes between two predicates inside the block.")
    for line in (line for group in groups for line in group):
        if _BLOCK.match(line):
            found.append(f"`{line}`: a `matches_element` block can't hold another block.")
        elif issue := _predicate_problem(line, parent):
            found.append(issue)
    return found


def _negated(item):
    if isinstance(item, tuple):
        return _BLOCK.match(item[0]).group(2).lower() == "does_not_match_element"
    match = _LINE.match(item)
    return bool(match) and match.group(2).lower() in NEGATED


def problems(query):
    """What the Certificates API would reject in a normalized query (HTTP 400), or []."""
    clauses = _clauses(query)
    if clauses == [None]:
        return ["Add at least one predicate, e.g. `san_dns ends_with \".example.com\"`."]
    found = []
    if None in clauses:
        found.append("`AND` goes between two predicates, on its own line (no `AND` first, last or twice in a row).")
    clauses = [clause for clause in clauses if clause]
    items = [item for clause in clauses for item in clause]
    for item in items:
        if isinstance(item, tuple):
            found.extend(_block_problems(item))
        elif re.search(r"\s(AND|OR)\s", re.sub(r'"(?:\\.|[^"\\])*"', '""', item), flags=re.IGNORECASE):
            found.append(f"`{item}`: put each predicate and each `AND` on its own line (lines in one clause are "
                         "OR'ed, so no `OR` is needed).")
        elif issue := _predicate_problem(item):
            found.append(issue)
    if items and all(_negated(item) for item in items):
        found.append("Every query needs at least one predicate that is not negated (not `does_not_…`, `not_in`): a "
                     "query of only negations would match almost every certificate. Add what the certificates have, "
                     "e.g. `san_dns ends_with \".example.com\"`.")
    lines = [len(item) if isinstance(item, tuple) else 1 for item in items]
    if len(clauses) > LIMITS["clauses"]:
        found.append(f"At most {LIMITS['clauses']} clauses (AND-separated groups) per query.")
    if any(sum(len(i) if isinstance(i, tuple) else 1 for i in clause) > LIMITS["per_clause"] for clause in clauses):
        found.append(f"At most {LIMITS['per_clause']} predicate lines in one clause.")
    if sum(lines) > LIMITS["predicates"]:
        found.append(f"At most {LIMITS['predicates']:,} predicate lines per query.")
    if len(query.encode()) > LIMITS["bytes"]:
        found.append(f"The query is over {LIMITS['bytes']:,} bytes.")
    return found


RELEASE_KEYWORDS = ("ja4x", "within", "contains_ip", "overlaps_range", "arc_begins_with", "matches_element",
                    "does_not_match_element", ".local_part", ".domain", ".host", ".scheme")


def error_hint(error, query=""):
    """What to do about a Certificate Search answer that is about the query itself, or ''."""
    text = str(error or "")
    if "UNKNOWN_KEYWORD" in text:
        used = [word for word in RELEASE_KEYWORDS if re.search(rf"(?<![\w.]){re.escape(word)}\b", query or "")
                or (word.startswith(".") and word in (query or ""))]
        if used:
            return (f"The API did not recognize a keyword. This query uses {', '.join(f'`{w}`' for w in used)}, "
                    "from the latest CertsQL release: the Certificates API you reach doesn't accept it yet. Try "
                    "again once the release is live, or write the query without it.")
        return ("The API did not recognize a keyword: every field and operator is lowercase snake_case "
                "(`san_dns ends_with`), and the fields and operators of the latest CertsQL release (`ja4x`, "
                "`within`, `matches_element`, …) may not be live on the API yet.")
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
        "JA4X": hit.get("ja4x") or "",
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

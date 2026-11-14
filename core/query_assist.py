"""
Autocomplete data for the IrisQL and CertsQL query editors (views/query_editor.py): every field with the operators the
API accepts for it, and for each operator either a short list of values to pick from or the empty quotes /
brackets the value goes in (no made-up value to delete). Built from the same rule tables the pages check queries with (core/irisql.py, core/certsql.py), so a
suggestion is never something the check would then flag.
"""
from core import certsql, irisql

LANGUAGES = ("irisql", "certsql")

# --- IrisQL value kinds (Iris search reference) -------------------------------------------------------------------
_IRIS_DATES = {"CREATE_DATE", "EXPIRATION_DATE", "FIRST_SEEN", "SSL_NOT_AFTER", "SSL_NOT_BEFORE"}
_IRIS_NUMBERS = {"RANK", "RISK_SCORE", "ASN", "SSL_DURATION"}
_IRIS_ADDRESSES = {"IP", "NAMESERVER_IP", "MAILSERVER_IP"}
_IRIS_LISTS = {"IN", "NOT_IN", "EXACTLY_IN", "NOT_EXACTLY_IN", "CONTAINS_ALL", "DOES_NOT_CONTAIN_ALL"}
IRIS_WITHIN = ("The last 7 days", "The last 30 days")   # phrases confirmed against the live API


def _template(text="", cursor=None):
    """Value syntax to insert after the operator, and where the cursor goes in it. Never a made-up value: only the
    quotes / brackets the value goes in (empty for a bare number), or the one value the operator accepts."""
    return {"text": text, "cursor": len(text) if cursor is None else cursor}


QUOTED, LIST, PAIR, NUMBERS, BARE = _template('""', 1), _template('[""]', 2), _template('["", ""]', 2), \
    _template("[]", 1), _template()
ELEMENT_BLOCK = _template("(\n  \n)", 4)   # CertsQL `matches_element`: the cursor on the indented line inside


def _iris_kind(field):
    if field in _IRIS_DATES:
        return "date"
    if field in _IRIS_NUMBERS:
        return "number"
    if field in _IRIS_ADDRESSES:
        return "IP address"
    if field == "ACTIVE":
        return "true / false"
    if field in irisql.FIELD_OPERATORS and irisql.FIELD_OPERATORS[field] == ("DOES_NOT_MATCH", "EXISTS", "MATCHES"):
        return "tracker / presence"
    return "text"


def iris_choices(field, operator):
    """The values to pick from after `field operator` when there are only a few (nothing is inserted before)."""
    if operator == "WITHIN":
        return list(IRIS_WITHIN)
    if operator == "EXISTS" or _iris_kind(field) == "true / false":
        return ["true", "false"]
    return []


def iris_template(field, operator):
    """What IrisQL needs after `field operator` for a value you type: quotes, brackets, or nothing (numbers)."""
    if iris_choices(field, operator):
        return BARE
    if operator in _IRIS_LISTS or field == "TAGS":
        return LIST
    return BARE if _iris_kind(field) == "number" else QUOTED


def _iris_catalog():
    fields = [{"name": field, "kind": _iris_kind(field), "operators": [
        {"name": op, "template": iris_template(field, op), "values": iris_choices(field, op)} for op in operators]}
        for field, operators in irisql.FIELD_OPERATORS.items()]
    return {"language": "irisql", "header": irisql.HEADER, "ignoreCase": True, "fields": fields,
            "operators": sorted({op for ops in irisql.FIELD_OPERATORS.values() for op in ops}),
            "fieldPrefix": ":"}   # `parsed_whois:REGISTRANT`: the field is the part after the last colon


def certs_choices(field, operator):
    kind = certsql.FIELDS[field][0]
    return ["true", "false"] if kind == "boolean" and operator in certsql.EQUALITY else []


def certs_template(field, operator):
    """What CertsQL needs after `field operator` (JSON: strings quoted, numbers bare); `exists` / `does_not_exist`
    accept only `true`, so that one is written for you."""
    kind = certsql.FIELDS[field][0]
    if operator in certsql.PRESENCE:
        return _template("true")
    if operator in certsql.ELEMENT:   # a block: the subfield predicates go on the lines between ( and )
        return ELEMENT_BLOCK
    if certs_choices(field, operator):
        return BARE
    if kind == "integer":
        return NUMBERS if operator in certsql.MEMBERSHIP or operator == "between" else BARE
    if operator in certsql.MEMBERSHIP:
        return LIST
    return PAIR if operator == "between" else QUOTED


def _certs_catalog():
    fields = [{"name": field, "kind": kind, "operators": [
        {"name": op, "template": certs_template(field, op), "values": certs_choices(field, op)} for op in operators]}
        for field, (kind, operators) in certsql.FIELDS.items()]
    return {"language": "certsql", "header": certsql.HEADER, "ignoreCase": False, "fields": fields,
            "operators": list(certsql.OPERATORS), "fieldPrefix": ""}


def catalog(language):
    """What the editor suggests for `language`: fields (with kind), each field's operators and value templates."""
    if language not in LANGUAGES:
        raise ValueError(f"unknown query language {language!r}")
    return _iris_catalog() if language == "irisql" else _certs_catalog()


def line_marks(language, text):
    """{line index in `text`: problem} for the lines a page warning names, so the editor can flag them in place."""
    module = irisql if language == "irisql" else certsql
    marks = {}
    lines = [line.strip() for line in str(text or "").splitlines()]
    for issue in module.problems(module.normalize(text)):
        if not issue.startswith("`") or "`: " not in issue and "` is not" not in issue:
            continue
        quoted = issue[1:issue.index("`", 1)]
        for index, line in enumerate(lines):
            if line == quoted and index not in marks:
                marks[index] = issue
    return marks

import json

import pytest

from core import certsql, irisql, query_assist

_VALUES = {"contains_ip": "10.1.2.3", "within": "10.0.0.0/8", "overlaps_range": "10.0.0.0/8", "arc_begins_with": "1.3.6.1"}
_JA4X = "2166164053c1_2166164053c1_30d204a01551"


def _fill(template, operator, field=""):
    """The value as a user would finish it inside the inserted quotes / brackets (or after the cursor, for a number)."""
    text = template["text"]
    if text == "":
        return "1"
    if text == "[]":
        return "[1, 2]" if operator == "between" else "[1]"
    if text.startswith("("):   # a matches_element block: one predicate on a part or subfield of `field`
        sub = next(name for name in certsql.FIELDS if name.startswith(field + "."))[len(field) + 1:]
        return text.replace("\n  \n", f"\n  {sub} exists true\n")
    value = _JA4X if field == "ja4x" else _VALUES.get(operator, "abc")
    return text.replace('""', f'"{value}"')


@pytest.mark.parametrize("language,module", [("irisql", irisql), ("certsql", certsql)])
def test_every_suggested_field_operator_and_value_passes_the_page_check(language, module):
    cat = query_assist.catalog(language)
    assert cat["header"] == module.HEADER and cat["fields"]
    for field in cat["fields"]:
        assert field["operators"], field["name"]
        for op in field["operators"]:
            values = op["values"] or [None]
            for value in values:
                operand = (value if value in ("true", "false") else f'"{value}"') if value else _fill(op["template"], op["name"], field["name"])
                line = f"{field['name']} {op['name']} {operand}"
                if field["name"] in ("issuer_country", "subject_country"):   # two-letter codes
                    line = line.replace('"abc"', '"US"')
                if module is certsql and (op["name"] in certsql.NEGATED):   # a query also needs a positive predicate
                    line += '\nAND\nsan_dns ends_with ".example.com"'
                assert module.problems(module.normalize(line)) == [], line


def test_catalogs_follow_the_rule_tables():
    iris = {f["name"]: f for f in query_assist.catalog("irisql")["fields"]}
    assert set(iris) == set(irisql.FIELD_OPERATORS)
    assert [op["name"] for op in iris["NAMESERVER_DOMAIN"]["operators"]] == list(irisql.FIELD_OPERATORS["NAMESERVER_DOMAIN"])
    assert "EXACTLY_MATCH" not in {op["name"] for op in iris["NAMESERVER_DOMAIN"]["operators"]}
    certs = {f["name"]: f for f in query_assist.catalog("certsql")["fields"]}
    assert set(certs) == set(certsql.FIELDS) and "basic_constraints.is_ca" in certs
    assert [op["name"] for op in certs["basic_constraints"]["operators"]] == list(certsql.PRESENCE + certsql.ELEMENT)
    assert {op["name"] for op in certs["name_constraints.permitted_ip_ranges"]["operators"]} == \
        {"within", "contains_ip", "overlaps_range", "exists", "does_not_exist"}
    assert "ja4x" in certs and "san_uri.host" in certs and "subject_email_address.local_part" in certs
    assert "contains" not in {op["name"] for op in certs["sha256"]["operators"]}
    with pytest.raises(ValueError):
        query_assist.catalog("sql")


def test_nothing_is_inserted_that_has_to_be_deleted():
    t = query_assist
    assert t.iris_template("RISK_SCORE", "GREATER_THAN_OR_EQUAL") == {"text": "", "cursor": 0}   # just type the number
    assert t.iris_template("SSL_DURATION", "DOES_NOT_MATCH") == {"text": "", "cursor": 0}
    assert t.iris_template("CREATE_DATE", "GREATER_THAN") == {"text": '""', "cursor": 1}
    assert t.iris_template("TLD", "IN") == {"text": '[""]', "cursor": 2}
    assert t.iris_template("FIRST_SEEN", "WITHIN")["text"] == "" and t.iris_choices("FIRST_SEEN", "WITHIN") == \
        ["The last 7 days", "The last 30 days"]
    assert t.iris_choices("GA4", "EXISTS") == ["true", "false"] and t.iris_choices("ACTIVE", "MATCHES") == ["true", "false"]
    assert t.certs_template("validity_not_after", "between") == {"text": '["", ""]', "cursor": 2}
    assert t.certs_template("public_key_bits", "less_than") == {"text": "", "cursor": 0}
    assert t.certs_template("san_count", "between") == {"text": "[]", "cursor": 1}
    assert t.certs_template("san_dns", "in") == {"text": '[""]', "cursor": 2}
    assert t.certs_template("is_self_signed", "equals")["text"] == "" and t.certs_choices("is_self_signed", "equals")
    assert t.certs_template("subject_organization", "does_not_exist") == {"text": "true", "cursor": 4}   # only value
    for language in t.LANGUAGES:
        for field in t.catalog(language)["fields"]:
            for op in field["operators"]:
                assert op["template"]["text"] in ("", '""', '[""]', '["", ""]', "[]", "true", "(\n  \n)"), \
                    (field["name"], op)
                if op["template"]["text"] == "true":
                    assert op["name"] in ("exists", "does_not_exist"), (field["name"], op)
    assert json.dumps(t.catalog("certsql"))   # sent to the browser as JSON


def test_line_marks_point_at_the_lines_a_warning_names():
    text = '# IrisQL-1.0\nNAMESERVER_DOMAIN EXACTLY_MATCH "example.com"\nAND\nFIRST_SEEN WITHIN "The last 7 days"'
    marks = query_assist.line_marks("irisql", text)
    assert list(marks) == [1] and "EXACTLY_MATCH" in marks[1]
    marks = query_assist.line_marks("certsql", 'sha256 contains "abcd"\nAND\nis_self_signed equals true')
    assert list(marks) == [0] and "does not support" in marks[0]
    assert query_assist.line_marks("certsql", "") == {}   # "add a predicate" names no line


def test_the_editor_component_bundles_codemirror_and_the_page_rules():
    from views import query_editor
    assert "CodeMirror" in query_editor._JS and "export default function" in query_editor._JS
    assert ".dtq-editor" in query_editor._CSS and ".CodeMirror-hints" in query_editor._CSS

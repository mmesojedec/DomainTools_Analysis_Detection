from datetime import date
from types import SimpleNamespace

import pytest

from core import certsql
from integrations import certificates


def hit(sha, sans, issuer="Let's Encrypt", not_before="2026-10-10T05:48:16Z", ips=()):
    return {"sha256": sha, "san_dns": list(sans), "san_ip_v4": list(ips), "subject_common_name": sans[0] if sans else "",
            "issuer_organization": issuer, "validation_level": "dv", "validity_not_before": not_before,
            "validity_not_after": "2027-01-08T05:48:15Z", "validity_duration_days": 89, "public_key_algorithm": "rsa",
            "public_key_bits": 2048, "is_self_signed": False, "public_key_sha256": "k" + sha}


def check(body):
    return certsql.problems(certsql.normalize(body))


def test_normalize_adds_the_version_line():
    assert certsql.normalize('san_dns ends_with ".a.com"\n\n') == '# CertsQL-1.0\nsan_dns ends_with ".a.com"'
    assert certsql.normalize('# certsql-1.0\nis_self_signed equals true').startswith("# CertsQL-1.0\n")


def test_every_example_is_valid_and_dates_follow_today():
    for name, body in certsql.examples().items():
        assert check(body) == [], name
    assert '"2026-10-05"' in certsql.examples(date(2026, 11, 4))["Brand look-alikes on new certificates"]


def test_problems_catch_what_the_certificates_api_rejects():
    assert check("") and check('AND\nis_self_signed equals true') and check('is_self_signed equals true\nAND\nAND\nsan_count equals 1')
    assert "own line" in check('san_dns ends_with ".a.com" AND is_self_signed equals true')[0]
    assert check('subject_organization contains "pay and go"') == []          # AND inside a quoted value
    assert check('# comment\n// comment\nis_self_signed equals true') == []
    cases = {
        'sha256 contains "abcd"': "does not support `contains`",
        'is_self_signed in [true]': "does not support `in`",
        'basic_constraints equals true': "dotted name",
        'is_self_signed equals "true"': "true or false",
        'public_key_bits less_than "2048"': "a number",
        'san_dns ends_with example.com': "must be JSON",
        'san_dns contains "lo"': "3 to 63",
        'issuer_contry equals "US"': "did you mean `issuer_country`",
        'san_dns end_with ".a.com"': "did you mean `ends_with`",
        'is_self_signed exists false': "operand `true`",
        'validity_not_after between ["2026-11-01"]': "two values",
        'san_dns in []': "non-empty JSON array",
        'issuer_country equals "USA"': "two letters",
        'issuer_locality contains "Paris"': "does not support `contains`",
        'validity_not_after within "the next 30 days"': "for a date window use `between",
        'certificate_policy.cps_uris ends_with "/cps.pdf"': "does not support `ends_with`",
        'name_constraints.permitted_ip_ranges equals "10.0.0.0/8"': "IP range fields take",
        'name_constraints.permitted_ip_ranges in ["10.0.0.0/8"]': "does not support `in`",
        'name_constraints.permitted_ip_ranges contains_ip "10.0.0.0/8"': "one IP address",
        'name_constraints.excluded_ip_ranges overlaps_range "10.0.0"': "CIDR",
        'ja4x equals "2166164053C1_2166164053c1_30d204a01551"': "lowercase hex",
        'ja4x contains "2166164053c1"': "does not support `contains`",
        'extension_oids arc_begins_with "1.3.6."': "dotted OID prefix",
        'san_dns arc_begins_with "1.3.6"': "does not support `arc_begins_with`",
        'san_uri.port equals "443"': "unknown field `san_uri.port`",
        'name_constraints.permitted_uri.scheme equals "https"': "unknown field",
        'san_dns matches_element (': "works on",
        'certificate_policy matches_element "x"': "opens a block",
        'sha256 does_not_equal "00"': "at least one predicate that is not negated",
        'subject_organization does_not_exist true': "not negated",
    }
    for body, expected in cases.items():
        found = check(body)
        assert len(found) == 1 and expected in found[0], (body, found)
    block = 'certificate_policy matches_element (\n  policy_oid equals "2.23.140.1.2.1"\nAND\n  cps_uris.host ends_with ' \
            '"letsencrypt.org"\n)\nAND\nsan_dns contains "login"'
    assert check(block) == []   # AND inside the block stays in it; subfields are relative to the block's field
    assert check('san_uri does_not_match_element (\n  scheme equals "http"\nAND\n  host ends_with ".corp"\n)\n'
                  'AND\nis_self_signed equals true') == []
    assert ["unknown field `policy_id` in certificate_policy (did you mean `policy_oid`?)" in i
            for i in check('certificate_policy matches_element (\n  policy_id equals "x"\n)')] == [True]
    assert "close the block" in check('certificate_policy matches_element (\n  policy_oid equals "x"')[0]
    assert "at least one predicate" in check('certificate_policy matches_element (\n)')[0]
    assert "not negated" in check('certificate_policy does_not_match_element (\n  policy_oid equals "x"\n)')[0]
    for ok in ('ja4x in ["000000000000_4f24da86fad6_bf0f0589fc03", "2166164053c1_2166164053c1_30d204a01551"]',
               'name_constraints.permitted_ip_ranges within "10.0.0.0/8"',
               'name_constraints.permitted_ip_ranges contains_ip "2001:db8::1"',
               'name_constraints.excluded_ip_ranges overlaps_range "192.168.0.0/16"',
               'extension_oids arc_begins_with "1.3.6.1.4.1.11129"',
               'certificate_policy.policy_oid arc_begins_with "2.23.140.1"',
               'subject_email_address.domain ends_with ".example.com"', 'san_upn.local_part equals "admin"',
               'san_uri.scheme in ["http", "ftp"]', 'name_constraints.permitted_uri.host ends_with ".corp"',
               'sha256 does_not_equal "00"\nsan_dns ends_with ".a.com"'):   # one positive line is enough
        assert check(ok) == [], ok
    for ok in ('basic_constraints.max_path_len between [0, 1]', 'signed_certificate_timestamp exists true',
               'san_ip_v4 between ["1.2.3.0", "1.2.3.255"]', 'validity_not_before greater_than 1767225600000',
               'issuer_locality begins_with "Par"', 'name_constraints.permitted_dns ends_with ".corp"'):
        assert check(ok) == [], ok
    assert "32 clauses" in " ".join(check("\nAND\n".join(["is_self_signed equals true"] * 33)))


def test_error_hints():
    unknown = "HTTP 400: Failed to scan the query (error: CQLScanningErrorCode.UNKNOWN_KEYWORD)"
    assert "snake_case" in certsql.error_hint(unknown)
    hint = certsql.error_hint(unknown, '# CertsQL-1.0\nja4x equals "x"\nAND\nsan_uri.host ends_with ".a.com"')
    assert "`ja4x`, `.host`" in hint and "doesn't accept it yet" in hint
    assert "This query uses" not in certsql.error_hint(unknown, 'san_dns contains "withinbrand"')
    assert certsql.error_hint("HTTP 400: 'contains' operand must be between 3 and 63 characters")
    assert certsql.error_hint("timeout") == ""
    assert "not answering" in certsql.error_hint("RetryError: too many 502 error responses")
    assert "not answering" in certsql.error_hint("Server error (HTTP 502): The upstream service is currently unavailable.")


def test_tables_follow_the_certificates_ticked_use():
    hits = [hit("a1", ["*.shop.example.com", "shop.example.com", "example.com"], ips=["8.8.8.8"]),
            hit("b2", ["login.example.com", "evil.net"]), hit("c3", ["sni123.cloudflaressl.com", "x.org"])]
    certs = certsql.certificate_frame(hits)
    assert list(certs.columns) == certsql.CERTIFICATE_COLUMNS and certs["Use"].all() and len(certs) == 3
    assert certs.iloc[0]["Key"] == "rsa 2048" and certs.iloc[0]["Not Before"] == "2026-10-10"
    domains, ips, hosts = certsql.target_frames(certsql.used_hits(hits, certs), preselect=1)
    assert list(domains["Target"])[0] == "example.com" and domains.iloc[0]["Certificates"] == 2
    assert "cloudflaressl.com" not in set(domains["Target"])                 # shared CDN names are left out
    assert certsql.selected(domains, "Target") == ["example.com"] and list(ips["Target"]) == ["8.8.8.8"]
    assert "*.shop.example.com" in set(hosts["Hostname"])
    certs.loc[certs["SHA-256"] == "b2", "Use"] = False
    domains, _, _ = certsql.target_frames(certsql.used_hits(hits, certs))
    assert "evil.net" not in set(domains["Target"]) and certsql.selected(domains, "Target") == []


def test_commands_carry_the_body_and_no_key_value():
    cmds = certsql.commands(certsql.normalize('is_self_signed equals true'), 100, certsql.sort_term("validity_not_after", "asc"))
    assert "${DT_CERT_API_KEY:-$DT_API_KEY}" in cmds["curl"] and '"limit": 100' in cmds["curl"]
    assert '"field": "validity_not_after"' in cmds["curl"] and "os.environ" in cmds["Python (requests)"]
    assert certsql.query_cost(1200, 500) == 3


def test_fetch_follows_the_cursor_and_keeps_pages_before_an_error(monkeypatch):
    pages = [({"hits": [hit("a1", ["a.com"]), hit("b2", ["b.com"])], "total": {"value": 10000, "relation": "gte"},
               "cursor": "c2"}, None),
             ({"hits": [hit("c3", ["c.com"])], "cursor": "c3"}, None)]
    calls = []
    monkeypatch.setattr(certificates, "load_cert_api_key", lambda: "k")
    monkeypatch.setattr(certificates, "_post", lambda path, body, key: (calls.append(body), pages[len(calls) - 1])[1])
    query = certsql.normalize('san_dns contains "login"')
    result = certificates.fetch_certsql(query, 3, ("validity_not_before", "desc"), page_size=2)
    assert [h["sha256"] for h in result.data] == ["a1", "b2", "c3"] and result.truncated
    assert result.extras == {"total": 10000, "relation": "gte", "pages": 2}
    assert calls[0] == {"query_string": query, "limit": 2, "sort": [{"field": "validity_not_before", "order": "desc"}]}
    assert calls[1]["cursor"] == "c2" and calls[1]["limit"] == 1
    assert certificates.fetch_certsql(query, 3, ("validity_not_before", "desc"), page_size=2).cached_at   # cached

    pages[1] = (None, "HTTP 400: bad cursor")
    calls.clear()
    failed = certificates.fetch_certsql(query, 5, (), page_size=2)
    assert failed.error and len(failed.data) == 2


def test_api_error_messages_are_kept():
    class Response:
        def __init__(self, body):
            self.body = body

        def json(self):
            return self.body
    assert certificates._error_message(Response({"error": {"code": "invalid_operand", "message": "too short"}})) \
        == ": too short"
    assert certificates._error_message(Response({"detail": [{"msg": "limit must be <= 500"}]})) == ": limit must be <= 500"
    assert certificates._error_message(Response([])) == ""
    assert certificates._error_message(Response({"error": "The upstream service is currently unavailable."})) \
        == ": The upstream service is currently unavailable."


def test_a_certsql_search_becomes_its_own_lookup_queries_tool():
    from core.lookup_queries import TOOLS, build_lookup_queries, request_counts
    from integrations.http import FetchResult
    from views.certsql_view import search_status

    query = certsql.normalize('san_dns ends_with ".domaintools.com"')
    result = FetchResult("Certificate Search", "CertsQL", data=[hit("a1", ["a.com"])], record_count=1, truncated=True,
                         extras={"total": 10000, "relation": "gte", "pages": 3})
    row = search_status({"query": query, "max_results": 1500, "sort": "Newest first (not before)", "result": result})
    assert row["Source"] == "CertsQL" and row["Status"] == "OK" and row["Detail"].startswith("1 of 10,000+")
    queries = build_lookup_queries(SimpleNamespace(statuses=[row]))
    assert TOOLS[:2] == ["IrisQL", "CertsQL"] and list(queries["Tool"]) == ["CertsQL"]
    assert queries.iloc[0]["Query"] == query and "certificates/search" in queries.iloc[0]["Command"]
    assert list(request_counts(queries)) == [3]


def test_certsql_is_a_data_source_with_its_own_page():
    from views.navigation import SPECS
    from views.sidebar import CERTSQL_MODE, QUERY_MODES, STICKY_KEYS
    assert QUERY_MODES[CERTSQL_MODE] == "certsql" and "certsql" in SPECS and not SPECS["certsql"].analyst_only
    assert {"certsql_query", "certsql_max_results", "certsql_sort", "certsql_preselect"} <= set(STICKY_KEYS)


def test_sort_is_a_field_and_an_order():
    assert certsql.sort_term("validity_not_before", "desc") == {"field": "validity_not_before", "order": "desc"}
    assert certsql.sort_term("validity_not_after", "asc") == {"field": "validity_not_after", "order": "asc"}
    assert certsql.sort_term("sha256", "asc") is None   # the API default: no sort sent
    assert certsql.sort_term("sha256", "desc") == {"field": "sha256", "order": "desc"}
    with pytest.raises(ValueError):
        certsql.sort_term("san_dns", "asc")   # multi-value: not sortable
    assert certsql.order_label("validity_not_before", "desc") == "Newest first"
    assert certsql.order_label("validity_not_after", "asc") == "Soonest expiry first"
    assert certsql.order_label("public_key_bits", "asc") == "Smallest first"
    assert certsql.sort_text({"field": "validity_not_before", "order": "desc"}) == "issue date, newest first"
    assert certsql.sort_text(None) == "SHA-256, the API default"
    for field, (_label, words) in certsql.SORT_FIELDS.items():
        assert field in certsql.FIELD_TYPES and len(words) == 2, field   # a real top-level field, both directions worded
        assert certsql.FIELD_TYPES[field] in ("date", "integer", "keyword"), field

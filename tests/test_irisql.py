from core import irisql
from integrations import enrichment
from views.navigation import SPECS


def record(domain, risk, ips=(), registrar="NameCheap, Inc."):
    return {"domain": domain, "domain_risk": {"risk_score": risk}, "active": True, "tld": domain.rsplit(".", 1)[-1],
            "create_date": {"value": "2026-10-01", "count": 1}, "registrar": {"value": registrar, "count": 9},
            "ip": [{"address": {"value": ip, "count": count}, "asn": [{"value": 13335, "count": 1}],
                    "isp": {"value": "Cloudflare", "count": 1}, "country_code": {"value": "us", "count": 1}}
                   for ip, count in ips],
            "name_server": [{"host": {"value": "ns1.example.net", "count": 1}}], "tags": [{"label": "watch"}]}


def test_normalize_adds_the_version_line_and_drops_blank_lines():
    assert irisql.normalize('domain contains "domaintools"\n\n') == '# IrisQL-1.0\ndomain contains "domaintools"'
    assert irisql.normalize('# irisql-1.0\n  DOMAIN CONTAINS "x"') == '# IrisQL-1.0\n  DOMAIN CONTAINS "x"'


def test_problems_catch_what_iris_rejects():
    assert irisql.problems(irisql.normalize('domain contains "domaintools"')) == []
    assert irisql.problems(irisql.normalize(irisql.EXAMPLES["Risky look-alikes created recently"])) == []
    assert irisql.problems(irisql.normalize("")) and irisql.problems(irisql.normalize('AND\nTLD IN ["com"]'))
    combined = irisql.problems(irisql.normalize('DOMAIN CONTAINS "a" AND TLD IN ["com"]'))
    assert combined and "own line" in combined[0]
    assert irisql.problems(irisql.normalize('WEBSITE_TITLE CONTAINS "log in and pay"')) == []   # AND inside a value


def test_operators_iris_rejects_for_a_field_are_caught_before_sending():
    query = irisql.normalize('NAMESERVER_DOMAIN EXACTLY_MATCH "example.com"\nAND\nFIRST_SEEN WITHIN "The last 7 days"')
    issue = irisql.problems(query)
    assert len(issue) == 1 and "NAMESERVER_DOMAIN does not support EXACTLY_MATCH" in issue[0] and "MATCHES" in issue[0]
    assert irisql.problems(irisql.normalize("active exactly_match true"))
    assert "EXISTS false" in irisql.problems(irisql.normalize("GA4 DOES_NOT_EXIST true"))[0]
    for ok in ('ISP_NAME EXACTLY_MATCH "Cloudflare, Inc."', 'REGISTRANT_ORG EXACTLY_MATCH "x"', 'TAGS CONTAINS ["a"]',
               'parsed_whois:REGISTRANT MATCHES "x"', 'SOME_NEW_FIELD ANY_OP "x"', 'NAMESERVER_DOMAIN BEGINS_WITH "ex"'):
        assert irisql.problems(irisql.normalize(ok)) == [], ok
    assert irisql.problems(irisql.normalize('NAMESERVER_HOST CONTAINS "ns1"'))
    assert "CIDR" in irisql.problems(irisql.normalize('IP IN ["104.21.59.0/24"]'))[0]
    assert "10,000" in irisql.error_hint("Server error (HTTP 503): Limit Exceeded Maximum 10000 returned")
    assert irisql.error_hint("HTTP 400: [Line 2] Operator \"X\" is not supported for this field")
    assert irisql.error_hint("timeout") == ""


def test_every_example_is_a_valid_query():
    for name, body in irisql.EXAMPLES.items():
        assert irisql.problems(irisql.normalize(body)) == [], name


def test_domain_table_preselects_the_riskiest_and_ip_table_counts_result_domains():
    records = [record("a.com", 40, [("1.2.3.4", 12)]), record("b.top", 99, [("1.2.3.4", 12), ("5.6.7.8", 2)]),
               record("c.com", None), {"no": "domain"}]
    domains = irisql.domain_frame(records, preselect=1)
    assert list(domains["Domain"]) == ["a.com", "b.top", "c.com"]
    assert irisql.selected(domains, "Domain") == ["b.top"]
    row = domains.iloc[1]
    assert row["IPs"] == "1.2.3.4, 5.6.7.8" and row["ASNs"] == "13335" and row["Countries"] == "US"
    assert row["Registrar"] == "NameCheap, Inc." and row["Tags"] == "watch" and row["Name Servers"] == "ns1.example.net"
    ips = irisql.ip_frame(records)
    assert list(ips["IP"]) == ["1.2.3.4", "5.6.7.8"]
    assert ips.iloc[0]["Result Domains"] == 2 and ips.iloc[0]["Domains"] == "a.com, b.top"
    assert ips.iloc[0]["Iris Domains"] == 12 and irisql.selected(ips, "IP") == []
    assert irisql.domain_frame([]).empty and irisql.ip_frame([]).empty


def test_costs_and_commands():
    assert irisql.query_cost(500, 500) == 1 and irisql.query_cost(1200, 500) == 3
    assert irisql.analysis_cost([]) == 0 and irisql.analysis_cost([f"d{i}.com" for i in range(101)]) == 2
    query = irisql.normalize('domain contains "domaintools"')
    cmds = irisql.commands(query, 500, "risk_score")
    assert cmds["DomainTools Python SDK"].startswith("domaintools iris_investigate --irisql '# IrisQL-1.0")
    assert "--sort-by risk_score" in cmds["DomainTools Python SDK"] and "$DT_API_KEY" in cmds["curl"]
    assert "page_size=500&sort_by=risk_score" in cmds["curl"] and "irisql=" in cmds["Python script"]
    assert "Content-Type: application/json" in cmds["curl"] and "text/plain" not in cmds["curl"]


class FakePages:
    """Stands in for irisql_page: one answer (or exception) per call, recording the params."""
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def __call__(self, query, params, api_key):
        self.calls.append({"irisql": query, **params})
        page = self.pages[len(self.calls) - 1]
        if isinstance(page, Exception):
            raise page
        return page


def _with_pages(monkeypatch, pages):
    fake = FakePages(pages)
    monkeypatch.setattr(enrichment, "load_dtapi_credentials", lambda: ("user", "key"))
    monkeypatch.setattr(enrichment, "irisql_page", fake)
    return fake


def test_fetch_irisql_pages_until_the_limit_and_is_cached(monkeypatch):
    api = _with_pages(monkeypatch, [
        {"results": [record("a.com", 1), record("b.com", 2)], "total_count": 9, "has_more_results": True,
         "position": "p2"},
        {"results": [record("c.com", 3)], "total_count": 9, "has_more_results": True, "position": "p3"}])
    query = irisql.normalize('domain contains "x"')
    result = enrichment.fetch_irisql(query, 3, "risk_score", page_size=2)
    assert [r["domain"] for r in result.data] == ["a.com", "b.com", "c.com"]
    assert result.truncated and result.extras["total"] == 9 and result.extras["pages"] == 2
    assert api.calls[0] == {"irisql": query, "page_size": 2, "sort_by": "risk_score"}
    assert api.calls[1] == {"irisql": query, "page_size": 1, "sort_by": "risk_score", "position": "p2"}
    again = enrichment.fetch_irisql(query, 3, "risk_score", page_size=2)
    assert len(api.calls) == 2 and again.cached_at and len(again.data) == 3


def test_fetch_irisql_keeps_pages_fetched_before_an_error(monkeypatch):
    _with_pages(monkeypatch, [{"results": [record("a.com", 1)], "total_count": 5, "has_more_results": True,
                               "position": "p2"},
                              enrichment.IrisQLError("HTTP 400: Invalid IrisQL")])
    result = enrichment.fetch_irisql(irisql.normalize('domain contains "y"'), 10, page_size=1)
    assert result.error == "HTTP 400: Invalid IrisQL" and [r["domain"] for r in result.data] == ["a.com"]


class FakeResponse:
    def __init__(self, status, body):
        self.status_code, self.ok, self._body = status, status < 400, body

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, response):
        self.response, self.sent = response, {}

    def post(self, url, **kwargs):
        self.sent = {"url": url, **kwargs}
        return self.response


def test_irisql_page_sends_the_query_as_json_content_type(monkeypatch):
    session = FakeSession(FakeResponse(200, {"response": {"results": [record("a.com", 1)], "total_count": 1}}))
    monkeypatch.setattr(enrichment, "get_session", lambda: session)
    query = irisql.normalize('domain contains "x"')
    page = enrichment.irisql_page(query, {"page_size": 5}, "secret")
    assert page["total_count"] == 1 and session.sent["data"] == query.encode()
    assert session.sent["headers"]["Content-Type"] == "application/json"
    assert session.sent["headers"]["X-Api-Key"] == "secret" and session.sent["params"] == {"page_size": 5}


def test_irisql_page_raises_the_api_message(monkeypatch):
    monkeypatch.setattr(enrichment, "get_session",
                        lambda: FakeSession(FakeResponse(400, {"error": {"message": "Unknown field FOO"}})))
    try:
        enrichment.irisql_page("# IrisQL-1.0\nFOO MATCHES \"x\"", {}, "secret")
    except enrichment.IrisQLError as exc:
        assert str(exc) == "HTTP 400: Unknown field FOO"
    else:
        raise AssertionError("expected IrisQLError")


def test_irisql_page_is_always_in_the_menu():
    assert "irisql" in SPECS and not SPECS["irisql"].analyst_only


def test_start_irisql_and_certsql_are_plain_links_before_overview():
    from views import navigation
    assert list(navigation.SECTIONS)[:5] == ["Start", "IrisQL", "CertsQL", "Runs", "Overview"]
    assert navigation.SPECS["irisql"].title == "IrisQL"
    assert set(navigation.DIRECT) == {"Start", "IrisQL", "CertsQL", "Runs"}
    sections = list(navigation.SECTIONS)
    assert sections.index("Evidence") == sections.index("Hunt") + 1   # Evidence right after Hunt


def test_an_irisql_search_becomes_its_own_lookup_queries_tool():
    from types import SimpleNamespace

    from core.lookup_queries import TOOLS, build_lookup_queries, request_counts
    from integrations.http import FetchResult
    from views.irisql_view import search_status

    query = irisql.normalize('domain contains "domaintools"')
    result = FetchResult("Iris Investigate", "IrisQL: x", data=[record("a.com", 1)], record_count=1, truncated=True,
                         extras={"total": 712, "pages": 2})
    row = search_status({"query": query, "max_results": 1000, "sort_by": "", "result": result})
    assert row["Source"] == "IrisQL" and row["Status"] == "OK" and row["Detail"].startswith("1 of 712")
    queries = build_lookup_queries(SimpleNamespace(statuses=[row]))
    assert TOOLS[0] == "IrisQL" and list(queries["Tool"]) == ["IrisQL"] and queries.iloc[0]["Query"] == query
    assert "--irisql" in queries.iloc[0]["Command"] and "curl -X POST" in queries.iloc[0]["Command"]
    assert list(request_counts(queries)) == [2]   # one request per page


def test_data_and_settings_groups_follow_evidence_and_merged_pages_are_tabs():
    from views import navigation
    order = list(navigation.SECTIONS)
    assert order[order.index("Evidence") + 1:] == ["Data", "Settings"]
    assert [spec.key for spec in navigation.SECTIONS["Data"]] == ["offline", "export", "sources"]
    assert [spec.key for spec in navigation.SECTIONS["Settings"]] == ["settings", "account", "docs"]
    assert navigation.title("offline") == "Saved datasets" and navigation.title("history") == "Compare runs"
    assert {key: navigation.ALIASES[key][0] for key in ("history", "pivots", "raw", "queries")} == {
        "history": "recent", "pivots": "hunt_tree", "raw": "evidence", "queries": "evidence"}


def test_tor_network_is_its_own_infrastructure_page_not_a_vpndb_tab():
    from views import navigation, vpndb_page
    assert [spec.key for spec in navigation.SECTIONS["Infrastructure"]][:3] == ["dns", "vpndb", "tor"]
    assert navigation.title("tor") == "Tor network" and "Tor network" not in vpndb_page.TABS
    assert set(vpndb_page.HOW_TO_READ) == set(vpndb_page.TABS)


def test_profile_queries_search_an_ip_as_an_ip_not_as_a_name():
    from core import certsql
    assert irisql.similar_query("83.228.209.234") == '# IrisQL-1.0\nip matches "83.228.209.234"'
    assert irisql.similar_query("login.example.com") == '# IrisQL-1.0\nDOMAIN CONTAINS "login"'
    cidr = irisql.similar_query("83.228.209.7/24")
    assert '"83.228.209.0"' in cidr and '"83.228.209.255"' in cidr
    assert certsql.certificates_query("83.228.209.234") == '# CertsQL-1.0\nsan_ip_v4 equals "83.228.209.234"'
    assert "san_ip_v6 equals" in certsql.certificates_query("2001:db8::1")
    assert "san_dns ends_with \".example.com\"" in certsql.certificates_query("example.com")
    for target in ("83.228.209.234", "83.228.209.7/24", "example.com", "2001:db8::1"):
        assert not irisql.problems(irisql.similar_query(target))
        assert not certsql.problems(certsql.certificates_query(target))


def test_reference_alignment():
    from core import irisql
    from core.query_assist import catalog
    # comment lines are not sent; the version line stays first
    assert irisql.normalize("# IrisQL-1.0\n# note\n// note\ndomain contains \"abc\"") == \
        '# IrisQL-1.0\ndomain contains "abc"'
    # host fields take MATCHES / DOES_NOT_MATCH / EXISTS only
    assert irisql.problems(irisql.normalize('MAILSERVER_HOST BEGINS_WITH "mx"'))
    assert not irisql.problems(irisql.normalize('MAILSERVER_HOST MATCHES "mx.example.com"'))
    # WITHIN takes "The last N unit"
    assert not irisql.problems(irisql.normalize('FIRST_SEEN WITHIN "The last 7 months"'))
    assert irisql.problems(irisql.normalize('FIRST_SEEN WITHIN "30 days"'))
    # fields listed without operators: suggested, not checked
    assert not irisql.problems(irisql.normalize('HISTORICAL_FREE_TEXT CONTAINS "acme"'))
    fields = {f["name"]: f for f in catalog("irisql")["fields"]}
    assert {"MISC_EMAIL", "HISTORICAL_EMAIL", "HISTORICAL_FREE_TEXT"} <= set(fields)
    # SSL_DURATION values are strings: the editor inserts quotes
    duration = {op["name"]: op for op in fields["SSL_DURATION"]["operators"]}
    assert duration["GREATER_THAN"]["template"]["text"] == '""'


def test_certsql_sorts_on_every_documented_field():
    from core.certsql import SORT_FIELDS
    assert set(SORT_FIELDS) == {
        "sha256", "validity_not_before", "validity_not_after", "validity_duration_days", "public_key_bits",
        "issuer_common_name", "subject_common_name", "issuer_organization", "subject_organization", "issuer_locality",
        "subject_locality", "issuer_state_or_province", "subject_state_or_province"}

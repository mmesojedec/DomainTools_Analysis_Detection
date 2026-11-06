import json

import pandas as pd

from core.lookup_queries import build_lookup_queries, one_line, request_counts, tool_bundle
from integrations.certificates import events_start_time
from integrations.collector import CollectedData

SHA_A, SHA_B = "aa" * 32, "bb" * 32
CREATED = "2026-10-27T07:31:09+00:00"


def status(source, target, state="OK", records=1):
    return {"Source": source, "Target": target, "Status": state, "Records": records, "Detail": ""}


def collected(statuses, **kwargs):
    data = CollectedData(targets=["example.com", "1.2.3.4"], domain_targets=["example.com", "other.org"], **kwargs)
    data.statuses = statuses
    return data


def by_source(frame, source):
    return frame[frame["Source"] == source].reset_index(drop=True)


def test_dnsdb_lookups_list_names_types_and_curl_requests():
    q = build_lookup_queries(collected([
        status("DNSDB Scout", "example.com", "Partial"), status("DNSDB Scout", "1.2.3.4"), status("DNSDB Scout", "5.6.7.8"),
        status("DNSDB CAA Supplement", "example.com"), status("DNSDB TXT Supplement", "example.com"),
        status("DNSDB Scout", "other.org"),
        status("DNSDB Hostname Gap-Fill", "api.example.com", "Partial"),
        status("TXT Supplement", "1 domain(s)"),   # summary row: no lookup of its own
    ], dnsdb_limit=1000), CREATED)
    main = by_source(q, "DNSDB Scout")
    assert main.loc[0, "Query"] == "*.example.com\nexample.com"   # capped: the apex was looked up on its own too
    params = "?limit=1000&swclient=DT_Analytics&version=2.0.0&aggr=f"
    assert main.loc[0, "Command"].split("\n") == [
        f"curl -s -H \"X-API-Key: $DNSDB_API_KEY\" -H 'Accept: application/x-ndjson' "
        f"'https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/{name}/ANY{params}'" for name in ("*.example.com", "example.com")]
    assert main.loc[1, "Search"] == "Rdata IP"
    assert main.loc[1, "Command"].endswith(f"'https://api.dnsdb.info/dnsdb/v2/lookup/rdata/ip/1.2.3.4{params}'")
    assert "limit=1000&" in main.loc[1, "Command"] and "limit=2000&" in main.loc[2, "Command"]   # 5.6.7.8: IP pivot
    assert main.loc[3, "Query"] == "*.other.org" and main.loc[3, "Command"].count("curl") == 1   # complete: one request
    caa = by_source(q, "DNSDB CAA Supplement").loc[0]
    assert caa["Query"] == "example.com" and "/rrset/name/example.com/CAA?limit=100&" in caa["Command"]   # apex only
    txt = by_source(q, "DNSDB TXT Supplement").loc[0]
    assert (txt["Search"], txt["Query"]) == ("RRset, type TXT", "*.example.com")
    gap = by_source(q, "DNSDB Hostname Gap-Fill").loc[0]
    assert (gap["Query"], gap["Status"]) == ("api.example.com", "Partial")
    assert "TXT Supplement" not in set(q["Source"])


def test_certificate_queries_use_the_run_inputs():
    seeds = pd.DataFrame([{"Seed": "org~:Acme", "Query": '# CertsQL-1.0\nsubject_organization contains "Acme"'}])
    q = build_lookup_queries(collected([
        status("Certificate Search", "org~:Acme"), status("Certificate Search", "example.com"),
        status("Certificate Search (Hostname Gap-Fill)", "example.com"),
        status("Cert Events (Hostname)", "example.com"), status("Cert Events (Hostname Gap-Fill)", "api.example.com"),
        status("Cert Events (IP)", "1.2.3.4"),
    ], seeds=seeds, host_focus={"example.com": ["api.example.com"]}), CREATED)
    search = by_source(q, "Certificate Search")
    assert search.loc[0, "Query"] == '# CertsQL-1.0\nsubject_organization contains "Acme"'
    assert 'san_dns ends_with ".example.com"' in search.loc[1, "Query"]
    assert "x-api-key: $DT_CERT_API_KEY" in search.loc[1, "Command"]
    gap = by_source(q, "Certificate Search (Hostname Gap-Fill)").loc[0, "Query"]
    assert 'san_dns equals "api.example.com"' in gap and 'san_dns equals "*.example.com"' in gap
    events = json.loads(by_source(q, "Cert Events (Hostname)").loc[0, "Query"])
    assert events == {"start_time": events_start_time(now=CREATED), "hostname": "example.com", "include_subdomains": True}
    assert json.loads(by_source(q, "Cert Events (Hostname Gap-Fill)").loc[0, "Query"])["include_subdomains"] is False
    assert json.loads(by_source(q, "Cert Events (IP)").loc[0, "Query"])["ip"] == "1.2.3.4"


def test_event_window_follows_the_run_time():
    assert events_start_time(days=365, now="2026-10-27T07:31:09+00:00") == "2025-10-27T00:00:00"


def test_per_certificate_summaries_expand_to_each_hash():
    ssl = pd.DataFrame({"Source": ["DomainTools Cert API"] * 2 + ["Domain History"], "Hash": [SHA_A, SHA_B, "cc" * 32]})
    q = build_lookup_queries(collected([
        status("Cert Events (SHA256)", SHA_A, "Error", 0),   # listed on its own after a failed retry
        status("Cert Events (SHA256)", "2 certificates", "Partial", 3),
        status("CT Log Events", "2 certificates"), status("CT / Co-occurrence", "5 certificates", "Partial"),
    ], ssl=ssl), CREATED)
    sha = by_source(q, "Cert Events (SHA256)")
    assert list(zip(sha["Target"], sha["Status"])) == [(SHA_A, "Error"), (SHA_B, "Partial")]
    assert list(by_source(q, "CT Log Events")["Target"]) == [SHA_A, SHA_B]
    assert "CT / Co-occurrence" not in set(q["Source"])


def test_domaintools_api_and_iris_rows():
    q = build_lookup_queries(collected([
        status("Domain History", "example.com"), status("Risk Evidence", "example.com"),
        status("Iris Investigate", "example.com, other.org"), status("Iris pDNS", "example.com"),
        status("Iris pDNS TXT Supplement", "example.com"),
    ]), CREATED)
    creds = '-u "$DT_API_USERNAME" -k "$DT_API_KEY"'
    assert by_source(q, "Domain History").loc[0, "Command"] == \
        f"domaintools domain_history --query example.com {creds} --page-size 100"
    assert by_source(q, "Risk Evidence").loc[0, "Command"] == f"domaintools risk_evidence --domain example.com {creds}"
    iris = by_source(q, "Iris Investigate").loc[0]
    assert (iris["Query"], iris["Tool"]) == ("example.com\nother.org", "Iris Investigate")
    assert iris["Command"] == f"domaintools iris_investigate --domains example.com,other.org {creds}"
    pdns = by_source(q, "Iris pDNS").loc[0]
    assert (pdns["Search"], pdns["Query"]) == ("RRName", "*.example.com")
    assert by_source(q, "Iris pDNS TXT Supplement").loc[0, "Search"] == "RRName, type TXT"


def test_tool_bundle_groups_by_search_type():
    q = build_lookup_queries(collected([
        status("DNSDB Scout", "example.com"), status("DNSDB CAA Supplement", "example.com"),
        status("Iris Investigate", "example.com, other.org"),
    ]), CREATED)
    assert tool_bundle(q, "DNSDB Scout") == "# RRset, type ANY\n*.example.com\n\n# RRset, type CAA\nexample.com"
    assert tool_bundle(q, "Iris Investigate") == "example.com\nother.org"


def test_one_line_flattens_queries_for_tables():
    q = build_lookup_queries(collected([
        status("Certificate Search", "example.com"), status("Cert Events (Hostname)", "example.com"),
        status("DNSDB Scout", "example.com", "Partial"), status("Iris pDNS", "example.com"),
    ]), CREATED)
    flat = dict(zip(q["Source"], q["Query"].map(one_line)))
    assert flat["Certificate Search"] == 'san_dns equals "example.com" · san_dns ends_with ".example.com"'
    assert flat["Cert Events (Hostname)"] == ("hostname=example.com, include_subdomains=true, "
                                              f"start_time={events_start_time(now=CREATED)}")
    assert flat["DNSDB Scout"] == "*.example.com · example.com"
    assert flat["Iris pDNS"] == "*.example.com"
    assert "\n" not in "".join(flat.values())


def test_capped_dnsdb_lookups_count_two_requests():
    q = build_lookup_queries(collected([
        status("DNSDB Scout", "24ur.com", "Partial"), status("DNSDB TXT Supplement", "24ur.com"),
        status("DNSDB CAA Supplement", "24ur.com"), status("Certificate Search", "24ur.com"),
        status("Domain History", "24ur.com"),
    ]), CREATED)
    assert dict(zip(q["Source"], request_counts(q))) == {
        "DNSDB Scout": 2, "DNSDB TXT Supplement": 1, "DNSDB CAA Supplement": 1, "Certificate Search": 1,
        "Domain History": 1}
    dnsdb = q[q["Tool"] == "DNSDB Scout"]
    names = [n for n in tool_bundle(dnsdb, "DNSDB Scout").splitlines() if n and not n.startswith("#")]
    assert len(names) == request_counts(dnsdb).sum() == 4


def test_no_statuses_gives_an_empty_table():
    assert build_lookup_queries(CollectedData()).empty


def test_cached_lookups_count_no_request():
    queries = build_lookup_queries(CollectedData(statuses=[
        {"Source": "Domain History", "Target": "a.com", "Status": "OK", "Records": 3, "Detail": "From cache (2 h old)"},
        {"Source": "Domain History", "Target": "b.com", "Status": "OK", "Records": 3, "Detail": ""}]))
    assert list(queries["Cached"]) == [True, False] and list(request_counts(queries)) == [0, 1]

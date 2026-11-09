import json

import pandas as pd

from core.cert_utils import is_weak_public_key
from core.dataset import dedupe_certificates, expand_multiline_rows
from core.pdns_features import add_event_gaps
from core.risk_profile import generate_digital_risk_profile
from integrations import cache
from integrations.cache import cached_fetch
from integrations.certificates import build_search_queries, match_target_against_hit, parse_domaintools_certs
from integrations.dnsdb import parse_dnsdb_to_dataframe, parse_saf_lines
from integrations.domain_history import calculate_lifespans_for_dh, parse_history_to_dataframe
from integrations.http import FetchResult, StatusLog
from integrations.iris import build_pdns_payload, parse_iris_json_to_dataframe


def test_parse_saf_lines_reports_limited_condition():
    lines = [json.dumps({"cond": "begin"}), json.dumps({"obj": {"rrname": "a.com."}}), json.dumps({"cond": "limited", "msg": "Result limit reached"})]
    objects, cond, msg = parse_saf_lines(lines)
    assert len(objects) == 1 and cond == "limited" and msg == "Result limit reached"


def test_parse_dnsdb_frame():
    records = [
        {"rrname": "a.com.", "rrtype": "A", "rdata": ["1.1.1.1", "2.2.2.2"], "count": 5, "time_first": 1704067200, "time_last": 1704153600},
        {"rrname": "www.a.com.", "rrtype": "CNAME", "rdata": "a.com.", "time_first": 1706745600, "time_last": 1706745600},
    ]
    df = parse_dnsdb_to_dataframe(records, "a.com")
    assert list(df.sort_values("Date")["Field"]) == ["A", "CNAME"]
    a_row = df[df["Field"] == "A"].iloc[0]
    assert a_row["Value"] == "1.1.1.1\n2.2.2.2" and a_row["Lifespan Days"] == 1.0
    assert df["Days Since Previous Event"].max() == 31.0


def test_parse_iris_frame_handles_missing_last_seen():
    df = parse_iris_json_to_dataframe([{"rrname": "a.com", "rrtype": "a", "rdata": "1.1.1.1", "first_seen": "2024-01-01T00:00:00Z"}], "a.com")
    assert df.iloc[0]["Lifespan Days"] == 0.1 and df.iloc[0]["Field"] == "A"


def test_iris_payload_shapes():
    assert build_pdns_payload("1.2.3.4")["search_type"] == "rdata"
    assert build_pdns_payload("a.com")["query"] == "*.a.com"


def test_domain_history_parsing_and_lifespans():
    raw = {"response": {"changes": [
        {"field": "ip", "timestamp": "2024-01-01T00:00:00Z", "before": {"ip": "1.1.1.1"}, "after": {"ip": "2.2.2.2"}},
        {"field": "ip", "timestamp": "2024-01-11T00:00:00Z", "before": {"ip": "2.2.2.2"}, "after": {"ip": "3.3.3.3"}},
    ]}}
    df = parse_history_to_dataframe(raw, "a.com")
    assert len(df) == 2 and set(df["Field"]) == {"IP"}
    spans = calculate_lifespans_for_dh(df)
    assert spans.sort_values("Start").iloc[0]["Lifespan Days"] == 10.0


def test_add_event_gaps_is_per_domain():
    df = pd.DataFrame({"Domain": ["a", "b", "a"], "Field": ["A", "A", "A"],
                       "Date": pd.to_datetime(["2024-01-01", "2024-01-05", "2024-01-11"])})
    gaps = add_event_gaps(df).set_index(["Domain", "Date"])["Days Since Previous Event"]
    assert gaps.loc[("a", pd.Timestamp("2024-01-11"))] == 10.0
    assert gaps.loc[("b", pd.Timestamp("2024-01-05"))] == 0.0


def test_certificate_parsing_and_matching():
    hit = {"sha256": "abc", "subject_common_name": "www.a.com", "issuer_common_name": "R3", "san_dns": ["www.a.com", "*.a.com"],
           "san_ip_v4": ["1.2.3.4"], "validity_not_before": "2024-01-01T00:00:00Z", "validity_not_after": "2024-04-01T00:00:00Z"}
    assert match_target_against_hit("a.com", hit)
    assert match_target_against_hit("1.2.3.4", hit)
    assert not match_target_against_hit("b.com", hit)
    df = parse_domaintools_certs([hit], ["a.com", "1.2.3.4", "b.com"])
    assert sorted(df["Domain"]) == ["1.2.3.4", "a.com"]
    assert pd.isna(df.iloc[0]["Has Embedded SCTs"])  # absent field stays unknown instead of False


def test_build_search_queries_one_per_target():
    queries = build_search_queries(["a.com", "b.com", "1.2.3.4", "2001:db8::1"])
    assert [q[0] for q in queries] == ["a.com", "b.com", "1.2.3.4", "2001:db8::1"]
    assert "san_ip_v6" in queries[-1][1]


def test_dedupe_certificates_prefers_cert_api():
    df = pd.DataFrame([
        {"Domain": "a.com", "Hash": "h", "Source": "Domain History"},
        {"Domain": "a.com", "Hash": "h", "Source": "DomainTools Cert API"},
    ])
    assert list(dedupe_certificates(df)["Source"]) == ["DomainTools Cert API"]


def test_expand_multiline_rows():
    df = pd.DataFrame([{"Domain": "a.com", "Before": "x\ny", "After": "z"}, {"Domain": "b.com", "Before": "q", "After": "r"}])
    out = expand_multiline_rows(df, ["Before", "After"], ["Domain"])
    assert out.to_dict("records") == [
        {"Domain": "a.com", "Before": "x", "After": "z"},
        {"Domain": "", "Before": "y", "After": ""},
        {"Domain": "b.com", "Before": "q", "After": "r"},
    ]


def test_cached_fetch_skips_errors():
    calls = []

    @cached_fetch(ttl=60)
    def fetch(x):
        calls.append(x)
        return FetchResult("S", x, error="boom" if x == "bad" else None)

    fetch("ok"), fetch("ok"), fetch("bad"), fetch("bad")
    assert calls == ["ok", "bad", "bad"]


def test_cached_fetch_survives_a_restart_and_honours_the_lifetime():
    calls = []

    def fetch(x):
        calls.append(x)
        return FetchResult("S", x, note="limit")

    first = cache.cached_fetch()(fetch)
    assert first("a.com").note == "limit" and "From cache" in first("a.com").note
    first.cache_clear()                                     # an app restart: memory gone, disk kept
    assert "From cache" in cache.cached_fetch()(fetch)("a.com").note and calls == ["a.com"]
    cache.set_cache_ttl(0)                                  # Cache lifetime: Off
    try:
        cache.cached_fetch()(fetch)("a.com")
    finally:
        cache.set_cache_ttl(cache.FETCH_CACHE_TTL_SECONDS)
    assert calls == ["a.com", "a.com"]
    cache.clear_all_caches()                                # Force refresh empties the disk cache
    assert cache.cache_usage()[0] == 0


def test_status_log_rows():
    log = StatusLog()
    log.record(FetchResult("DNSDB Scout", "a.com", error="Authentication/authorization failed (HTTP 401)"))
    log.record(FetchResult("DNSDB Scout", "b.com", truncated=True, record_count=10, note="limit"))
    assert [r["Status"] for r in log.rows] == ["Error", "Partial"]


def test_weak_key_helper():
    assert is_weak_public_key(1024, "RSA") and not is_weak_public_key(256, "ECDSA")
    assert not is_weak_public_key(float("nan"), "RSA")


def test_risk_profile_handles_nan_flags():
    ssl = pd.DataFrame([{"Domain": "a.com", "Hash": "h", "Is Self Signed": float("nan"), "Public Key Bits": 256, "Public Key Algo": "ECDSA"}])
    profiles = generate_digital_risk_profile(["a.com"], pd.DataFrame(), pd.DataFrame(), ssl, pd.DataFrame(), {})
    assert profiles.iloc[0]["Certificate Trust"] == 0
    assert "_" in profiles.iloc[0]["DIF Fingerprint"]


def test_collector_records_errors(monkeypatch):
    import integrations.collector as collector

    monkeypatch.setattr(collector, "fetch_dnsdb_history", lambda t, limit, *args: FetchResult("DNSDB Scout", t, data=[], error="HTTP 401"))
    log = StatusLog()
    frame, _ = collector.collect_pdns(["a.com"], "DNSDB Scout", 10, log)
    assert frame.empty and log.rows[0]["Status"] == "Error"


def test_cache_summary_counts_cached_lookups_and_their_expiry():
    from views.raw_view import cache_summary
    statuses = [
        {"Source": "DNSDB Scout", "Target": "a.com", "Status": "OK", "Detail": "From cache (2 h old)",
         "Cached At": pd.Timestamp("2026-10-30 08:00")},
        {"Source": "DNSDB Scout", "Target": "b.com", "Status": "OK", "Detail": "", "Cached At": pd.NaT},
        {"Source": "DNSDB TXT Lookup", "Target": "2 domain(s)", "Status": "OK", "Detail": "Not needed"},
    ]
    row = cache_summary(statuses, 86400, "2026-10-30T10:00:00Z").iloc[0]
    assert (row["Lookups"], row["From Cache"], row["Live"]) == (2, 1, 1)     # the summary row is not a lookup
    assert row["Expires At"] == pd.Timestamp("2026-10-31 08:00")             # the cached one expires first
    assert FetchResult("S", "x", cached_at=0).status_row()["Cached At"] == pd.Timestamp("1970-01-01")

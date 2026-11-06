import pandas as pd

import integrations.certificates as certificates
import integrations.collector as collector
from integrations.http import FetchResult, StatusLog


def _rows(log, source):
    return [r for r in log.rows if r["Source"] == source]


def test_error_after_some_records_is_partial_not_error():
    row = FetchResult("Cert Events (SHA256)", "h", data=[{}] * 500, error="Server error (HTTP 503)", record_count=500).status_row()
    assert row["Status"] == "Partial" and "Incomplete" in row["Detail"] and "500" in row["Detail"]
    assert FetchResult("X", "t", error="Server error (HTTP 503)").status_row()["Status"] == "Error"


def test_empty_cert_api_responses_are_no_data_with_explanation(monkeypatch):
    # Shapes taken from real Cert API responses for a certificate/target with no records (HTTP 200, empty list)
    responses = {
        "search": {"hits": [], "total": {"value": 0, "relation": "eq"}, "cursor": None, "explain": None},
        "events/sha256": {"sha256": "0" * 64, "active_events": [], "pagination": {"limit": 5, "has_more": False, "next_cursor": None}},
        "events/ctl": {"sha256": "0" * 64, "ctl_events": []},
    }
    monkeypatch.setattr(certificates, "load_cert_api_key", lambda: "key")
    monkeypatch.setattr(certificates, "_post", lambda endpoint, payload, key: (responses[endpoint], None))
    for fetch in (certificates.search_certificates, certificates.fetch_cert_events_sha256, certificates.fetch_cert_events_ctl):
        fetch.cache_clear()

    search = certificates.search_certificates("designsolu.xyz", "q")
    sha = certificates.fetch_cert_events_sha256("0" * 64)
    ctl = certificates.fetch_cert_events_ctl("0" * 64)
    for result in (search, sha, ctl):
        row = result.status_row()
        assert result.ok and row["Status"] == "No data" and row["Detail"]
    assert "No certificates" in search.note and "not observed" in sha.note and "No CT log" in ctl.note


def test_run_with_retry_recovers_transient_failures(monkeypatch):
    calls = []

    def lookup(job):
        calls.append(job)
        failing_first_time = job == "b" and calls.count("b") == 1
        return FetchResult("S", job, error="Server error (HTTP 503)" if failing_first_time else None, record_count=1)

    results, retried = collector.run_with_retry(["a", "b", "c"], lookup, max_workers=2, pause=0)
    assert all(r.ok for r in results.values()) and retried == {"b"} and calls.count("b") == 2


def _fake_ct(monkeypatch, failing=()):
    def ctl(sha):
        if sha in failing:
            return FetchResult("CT Log Events", sha, error="Server error (HTTP 503)")
        events = [{"log_url": "https://ct.example/log", "event_timestamp": "2026-10-01T00:00:00Z"}] if sha == "with-data" else []
        return FetchResult("CT Log Events", sha, data=events, record_count=len(events))

    def sha256(sha, max_records):
        if sha in failing:
            return FetchResult("Cert Events (SHA256)", sha, error="Connection error")
        events = [{"domain": "a.com", "ip": "1.2.3.4"}] if sha == "with-data" else []
        return FetchResult("Cert Events (SHA256)", sha, data=events, record_count=len(events))

    monkeypatch.setattr(collector, "fetch_cert_events_ctl", ctl)
    monkeypatch.setattr(collector, "fetch_cert_events_sha256", sha256)
    monkeypatch.setattr(collector.time, "sleep", lambda seconds: None)


def _ssl(hashes):
    return pd.DataFrame([{"Source": "DomainTools Cert API", "Hash": h} for h in hashes])


def test_ct_telemetry_separates_empty_from_failed(monkeypatch):
    _fake_ct(monkeypatch, failing={"broken"})
    log = StatusLog()
    ctl, obs = collector.collect_ct_telemetry(_ssl(["with-data", "empty", "broken"]), 200, log)
    assert len(ctl) == 1 and len(obs) == 1

    for source in collector.CT_SOURCES:
        rows = _rows(log, source)
        errors = [r for r in rows if r["Status"] == "Error"]
        summary = rows[-1]
        assert len(errors) == 1 and errors[0]["Target"] == "broken"
        assert summary["Status"] == "Partial"
        assert "1 with data, 1 empty (no records exist), 1 failed" in summary["Detail"]
        assert "1 retried once" in summary["Detail"]


def test_ct_telemetry_all_empty_is_no_data_not_error(monkeypatch):
    _fake_ct(monkeypatch)
    log = StatusLog()
    collector.collect_ct_telemetry(_ssl(["empty", "empty-2"]), 200, log)
    assert {r["Status"] for r in log.rows} == {"No data"}
    assert all("2 empty" in r["Detail"] for r in log.rows)


def test_ct_telemetry_flags_capped_lookups(monkeypatch):
    _fake_ct(monkeypatch)
    monkeypatch.setattr(collector, "fetch_cert_events_sha256", lambda sha, max_records: FetchResult(
        "Cert Events (SHA256)", sha, data=[{"domain": "a.com"}] * 3, record_count=3, truncated=True))
    log = StatusLog()
    collector.collect_ct_telemetry(_ssl(["with-data"]), 200, log)
    summary = _rows(log, "Cert Events (SHA256)")[-1]
    assert summary["Status"] == "Partial" and "1 capped" in summary["Detail"]


def test_ct_telemetry_skipped_when_search_found_no_certificates():
    log = StatusLog()
    ctl, obs = collector.collect_ct_telemetry(pd.DataFrame(), 200, log)
    assert ctl.empty and obs.empty
    assert [(r["Source"], r["Status"]) for r in log.rows] == [("CT Log Events", "No data"), ("Cert Events (SHA256)", "No data")]
    assert all("Skipped" in r["Detail"] for r in log.rows)


def test_ct_hashes_take_the_newest_certificates_in_turns_per_domain():
    ssl = pd.DataFrame({
        "Source": ["DomainTools Cert API"] * 5 + ["Domain History"],
        "Domain": ["big.com", "big.com", "big.com", "small.com", "big.com", "small.com"],
        "Hash": ["b-old", "b-new", "b-mid", "s-only", "b-new", "dh"],   # b-new appears twice (two matched targets)
        "Not Before Date": pd.to_datetime(["2024-01-01", "2026-09-01", "2025-06-01", "2023-01-01", "2026-09-01", "2026-10-01"]),
    })
    assert collector.ct_hashes(ssl) == ["b-new", "s-only", "b-mid", "b-old"]


def test_ct_cap_keeps_every_domains_newest_certificate(monkeypatch):
    looked_up = []
    monkeypatch.setattr(collector, "_ct_lookup", lambda job: looked_up.append(job[1]) or FetchResult(job[0], job[1], data=[]))
    ssl = pd.DataFrame({"Source": "DomainTools Cert API", "Domain": ["big.com"] * 3 + ["small.com"],
                        "Hash": ["b1", "b2", "b3", "s1"],
                        "Not Before Date": pd.to_datetime(["2026-01-01", "2026-02-01", "2026-03-01", "2020-01-01"])})
    log = StatusLog()
    collector.collect_ct_telemetry(ssl, 2, log)
    assert sorted(set(looked_up)) == ["b3", "s1"]
    assert "2 newest certificates" in _rows(log, "CT / Co-occurrence")[0]["Detail"]

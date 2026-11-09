"""API collection: risk from Iris, SDK retries, query counting, per-source cache lifetimes, parallel stages,
skipped products, Domain History period, incremental passive DNS and the Iris fields used in rules."""
import threading
import time

import pandas as pd
import pytest

import integrations.collector as collector
from core.account import unavailable_stages
from core.api_usage import (
    attention_rows,
    cache_group,
    failed_lookups,
    queries_by_product,
    remaining,
    run_overview,
    run_usage,
    source_product,
    source_stats,
    target_stats,
)
from core.threat_detection.context import DomainContext
from core.threat_detection.enrichment_rules import apply_popularity, rule_iris_mail
from core.use_cases import query_plan
from integrations import cache, domain_history, iris
from integrations.enrichment import extract_iris_profile
from integrations.http import FetchResult, StatusLog, count_query, metered, sdk_call
from integrations.progress import CollectionProgress, tracking
from integrations.risk import risk_from_iris

DOMAIN_RISK = {"risk_score": 97, "components": [
    {"name": "proximity", "risk_score": 81},
    {"name": "threat_profile", "risk_score": 97, "threats": ["malware", "phishing"], "evidence": ["ip address"]}]}


class SdkError(Exception):
    def __init__(self, code):
        super().__init__(f"HTTP {code}")
        self.code = code


def test_risk_scores_come_from_the_iris_records():
    risk = risk_from_iris({"bad.cc": {"domain_risk": DOMAIN_RISK}, "unscored.com": {"domain_risk": {}},
                           "none.com": {}})
    assert list(risk["Domain"].unique()) == ["bad.cc"]
    assert risk[["Component", "Score"]].values.tolist() == [["Overall Risk", 97], ["Proximity", 81],
                                                            ["Threat Profile", 97]]
    assert risk.iloc[2][["Threats", "Evidence"]].tolist() == ["malware, phishing", "ip address"]
    assert "risk" not in {row["Key"] for row in query_plan({})}   # no separate Risk Evidence lookup


def test_sdk_calls_are_retried_on_rate_limits_and_server_errors_only():
    waits, calls = [], []

    def flaky():
        calls.append(1)
        if len(calls) < 3:
            raise SdkError(429 if len(calls) == 1 else 503)
        return "ok"

    assert sdk_call(flaky, sleep=waits.append) == "ok" and waits == [2.0, 4.0]
    with pytest.raises(SdkError):
        sdk_call(lambda: (_ for _ in ()).throw(SdkError(404)), sleep=waits.append)
    assert waits == [2.0, 4.0]   # 404 is not retried
    with pytest.raises(SdkError):
        sdk_call(lambda: (_ for _ in ()).throw(SdkError(503)), sleep=waits.append)
    assert waits[2:] == [2.0, 4.0]   # three attempts, then the error


def test_each_lookup_carries_the_queries_it_made_and_cached_ones_none():
    @cache.cached_fetch(group="history")
    def fetch(name):
        count_query(3)
        return FetchResult("Domain History", name, data=[1], record_count=1)

    first, second = fetch("a.com"), fetch("a.com")
    assert first.queries == 3 and first.status_row()["Queries"] == 3
    assert second.queries == 0 and second.status_row()["Queries"] == 0 and second.cached_at is not None
    assert metered(lambda: FetchResult("X", "t"))().queries == 0


def test_sources_keep_cached_results_for_their_own_lifetime(monkeypatch):
    monkeypatch.setattr(cache, "_ttl", [86400])
    monkeypatch.setattr(cache, "_group_ttl", {"history": 604800})
    assert cache.group_ttl("history") == 604800 and cache.group_ttl("pdns") == 86400
    cache.set_group_ttl("pdns", 1800)
    assert cache.group_ttl("pdns") == 1800
    cache.set_group_ttl("pdns", None)
    assert cache.group_ttl("pdns") == 86400
    monkeypatch.setattr(cache, "_ttl", [0])
    assert cache.group_ttl("history") == 0   # the cache off turns every source off

    monkeypatch.setattr(cache, "_ttl", [86400])

    @cache.cached_fetch(group="history")
    def fetch(name):
        return FetchResult("Domain History", name, data=[1], record_count=1)

    assert not fetch.peek("b.com")
    hit = (fetch("b.com"), fetch("b.com"))[1]
    assert fetch.peek("b.com") and hit.cache_lifetime == 604800


def test_domain_history_stops_paging_at_the_period_start(monkeypatch):
    pages = [[{"timestamp": f"2026-10-{day:02d}T00:00:00Z", "field": "ip"} for day in range(30, 0, -1)][i:i + 100]
             for i in (0,)]
    old = [{"timestamp": "2025-01-01T00:00:00Z", "field": "ip"}] * 100
    calls = []

    class Api:
        def domain_history(self, domain, page_size, offset):
            calls.append(offset)
            page = (pages[0] + old)[offset:offset + page_size]
            return type("R", (), {"data": lambda self: {"response": {"changes": page}}})()

    monkeypatch.setattr(domain_history, "get_dt_api", lambda: Api())
    result = domain_history.fetch_domain_history("a.com", 1000, "2026-10-15")
    assert calls == [0] and result.record_count == 16 and "since 2026-10-15" in result.note
    assert collector.history_since(30, "2026-11-06") == "2026-10-07" and collector.history_since(0) is None
    assert collector.history_args("a.com") == ("a.com",)   # no period: the cache key of earlier runs


def test_incremental_passive_dns_looks_up_only_known_targets_since_the_earlier_dataset(monkeypatch):
    calls = []

    def fake(target, limit=5000, rrtype="ANY", include_wildcard=True, since=None):
        calls.append((target, since))
        return FetchResult("DNSDB Scout", target, data=[{"rrname": f"www.{target}.", "rrtype": "A",
                                                          "rdata": ["1.1.1.1"], "time_first": 1_790_000_000,
                                                          "time_last": 1_790_100_000}], record_count=1)

    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake)
    base_rows = [{"Domain": "a.com", "RRName": "www.a.com", "Field": "A", "Value": "1.1.1.1", "Count": 1,
                  "Source": "DNSDB Scout", "Bailiwick": "", "First Seen": pd.Timestamp(1_790_000_000, unit="s"),
                  "Last Seen": pd.Timestamp(1_790_050_000, unit="s")},
                 {"Domain": "a.com", "RRName": "old.a.com", "Field": "A", "Value": "2.2.2.2", "Count": 1,
                  "Source": "DNSDB Scout", "Bailiwick": "", "First Seen": pd.Timestamp("2024-01-01"),
                  "Last Seen": pd.Timestamp("2024-02-01")}]
    from core.pdns_features import build_pdns_frame
    base = {"frame": build_pdns_frame(base_rows), "created": "2026-11-01T10:00:00Z", "name": "monday"}
    log = StatusLog()
    pdns, _ = collector.collect_pdns(["a.com", "b.com"], "DNSDB Scout", 100, log, base=base)
    since = collector.incremental_since("2026-11-01T10:00:00Z")
    assert since == int(pd.Timestamp("2026-10-31", tz="UTC").timestamp())
    assert sorted(calls) == [("a.com", since), ("b.com", None)]
    a = pdns[pdns["Domain"] == "a.com"].sort_values("RRName")
    assert a["RRName"].tolist() == ["old.a.com", "www.a.com"]   # the old record kept, the seen-again one replaced
    assert a.iloc[1]["Last Seen"] == pd.Timestamp(1_790_100_000, unit="s")
    assert any("Incremental" in str(row["Detail"]) for row in log.rows if row["Target"] == "a.com")


def test_stages_run_at_the_same_time_and_missing_products_are_skipped(monkeypatch):
    started, release = [], threading.Event()

    def stage(name, value):
        def run(*args, **kwargs):
            started.append(name)
            release.wait(2)
            return value
        return run

    monkeypatch.setattr(collector, "collect_domain_history", stage("history", (pd.DataFrame(), pd.DataFrame())))
    monkeypatch.setattr(collector, "collect_certificates", stage("certs", pd.DataFrame()))
    monkeypatch.setattr(collector, "collect_cert_events", lambda *a, **k: pd.DataFrame())
    monkeypatch.setattr(collector, "collect_enrichment", stage("iris", {}))

    def pdns(*args, **kwargs):
        deadline = time.time() + 2
        while len(started) < 2 and time.time() < deadline:   # the other stages start while passive DNS runs
            time.sleep(0.01)
        started.append("pdns")
        release.set()
        return pd.DataFrame(), {}

    monkeypatch.setattr(collector, "collect_pdns", pdns)
    data = collector.collect_all(["a.com"], "DNSDB Scout", 100, include_ct=False, unavailable={"iris"})
    assert sorted(started[:2]) == ["certs", "history"] and started[2] == "pdns"   # Iris skipped, the rest in parallel
    assert any(row["Source"] == "Iris Investigate" and "Skipped" in row["Detail"] for row in data.statuses)
    assert unavailable_stages([{"id": "iris-investigate-(api-only)"}, {"id": "domain-history"}]) == {"certs", "events"}
    assert unavailable_stages(None) == set()


def test_progress_draws_only_from_the_thread_that_created_it():
    drawn = []
    progress = CollectionProgress(query_plan({}), render=lambda p: drawn.append(1))
    progress.tick(force=True)
    thread = threading.Thread(target=lambda: progress.tick(force=True))
    thread.start()
    thread.join()
    assert len(drawn) == 1


def test_run_usage_and_what_is_left():
    statuses = [FetchResult("Iris Investigate", "a.com", queries=1).status_row(),
                FetchResult("Domain History", "a.com", queries=3).status_row(),
                FetchResult("Domain History", "b.com", cached_at=1.0, queries=0).status_row(),
                FetchResult("DNSDB TXT Lookup", "a.com", queries=1).status_row(),
                FetchResult("VPNDB", "2 IP(s)", queries=2).status_row(),
                FetchResult("Cert Events (IP)", "1.2.3.4", error="Server error (HTTP 503)").status_row(),
                {"Source": "TXT Lookup", "Target": "1 domain(s)", "Status": "OK", "Detail": ""}]
    usage = run_usage(statuses).set_index("Product")
    assert usage.loc["domain-history"].tolist()[1:] == [2, 1, 3]
    assert queries_by_product(statuses) == {"domain-history": 3, "iris-investigate": 1, "DNSDB": 1, "VPNDB": 2}
    assert failed_lookups(statuses) == 1
    assert source_product("CT Log Events") == ("DomainTools API", "certificate-events")
    assert cache_group("Iris pDNS TXT Lookup") == "pdns" and cache_group("Cert Events (IP)") == "certs"

    products = [{"id": "iris-investigate-(api-only)", "rest": {"month": "5"}},
                {"id": "domain-history", "per_month_limit": "100", "usage": {"month": "95"}, "rest": {"month": ""}}]
    assert remaining(products, "iris-investigate") == 5 and remaining(products, "domain-history") == 5



def test_iris_pdns_uses_the_cache_without_opening_a_browser(monkeypatch):
    seen = []

    def lookup(target, extra=(), capped=()):
        return FetchResult("Iris pDNS", target, data=[], cached_at=1.0)

    lookup.is_cached = lambda *a: True
    monkeypatch.setattr(iris, "iris_pdns_lookup", lookup)
    results = iris.fetch_iris_pdns_many(["a.com", "1.2.3.4"], extra_rrtypes=("TXT",),
                                        on_result=lambda t, r: seen.append(t))
    assert set(results) == {"a.com", "1.2.3.4"} and sorted(seen) == ["1.2.3.4", "a.com"]
    assert iris.lookup_args("1.2.3.4", ("TXT",), ("CNAME",)) == ("1.2.3.4", (), ())


def test_iris_mail_spf_and_popularity_feed_the_rules():
    record = {"popularity_rank": 133, "active": True, "website_response": 200, "spf_info": "v=spf1 +all",
              "mx": [{"host": {"value": "mx.yandex.ru."}}, {"host": {"value": "mx.yandex.ru"}}],
              "email_domain": [{"value": "Example.com"}]}
    profile = extract_iris_profile(record)
    assert (profile["popularity_rank"], profile["mx_hosts"], profile["email_domains"]) == (133, ["mx.yandex.ru"],
                                                                                           ["example.com"])
    assert extract_iris_profile({"popularity_rank": 0})["popularity_rank"] is None
    ctx = DomainContext(domain="a.com", is_ip=False, thresholds={}, profile=profile)
    rule_iris_mail(ctx)
    assert [(a["Threat Type"], a["Confidence"]) for a in ctx.alerts] == [("High-Risk Mail Provider", "Low"),
                                                                       ("Highly Permissive SPF (+all)", "High")]
    ctx.alerts[1]["Confidence"] = "Medium-High"
    apply_popularity(ctx)
    assert [a["Confidence"] for a in ctx.alerts] == ["Low", "Medium"]
    assert "popularity rank 133" in ctx.alerts[0]["Threat Logic"]
    unpopular = DomainContext(domain="b.com", is_ip=False, thresholds={}, profile={"popularity_rank": 50_000})
    unpopular.alerts.append({"Confidence": "Medium", "Threat Logic": "x"})
    apply_popularity(unpopular)
    assert unpopular.alerts[0]["Confidence"] == "Medium"


def test_progress_rows_report_their_own_cache_lifetime():
    progress = CollectionProgress(query_plan({}))
    with tracking(progress):
        progress.start("history", 1)
        progress.advance("history", FetchResult("Domain History", "a.com", note="From cache (1 h old)",
                                                cached_at=1.0, cache_lifetime=604800))
    row = next(r for r in progress.snapshot() if r.key == "history")
    assert row.cache_lifetime == 604800


def test_domain_history_period_follows_the_option_or_the_analysis_window():
    from core.use_cases import BY_KEY, effective_settings, history_limit_text, history_period_days
    assert history_period_days("all", 90, "Last 30 days") == 0
    assert history_period_days("window", 90, "Last 30 days") == 30
    assert history_period_days("window", 90, "All time") == 0
    assert history_period_days("window", 90, "Custom range", "2026-10-01", today="2026-11-06") == 37
    assert history_period_days("days", 400, "Last 30 days") == 400   # more than the window, when needed
    assert history_limit_text({}) == "1,000 changes"
    assert history_limit_text({"opt_history_mode": "window", "analysis_window": "Last 90 days"}) == \
        "Analysis window (90 days), up to 1,000 changes"
    assert history_limit_text({"opt_history_mode": "window", "analysis_window": "All time"}) == \
        "Analysis window (all time), up to 1,000 changes"
    assert history_limit_text({"opt_history_mode": "days", "opt_history_days": 400}) == "400 days, up to 1,000 changes"
    monitor = effective_settings(BY_KEY["monitor"])
    assert (monitor["opt_history_mode"], monitor["opt_history_days"]) == ("days", 90)
    assert "90 days" in next(r["Limit"] for r in query_plan(monitor) if r["Key"] == "history")


def _history_api(total, calls):
    changes = [{"timestamp": "2026-10-01T00:00:00Z", "field": "ip"}] * total

    class Api:
        def domain_history(self, domain, page_size, offset):
            calls.append(offset)
            page = changes[offset:offset + page_size]
            return type("R", (), {"data": lambda self: {"response": {"changes": page}}})()
    return Api()


def test_domain_history_cap_flags_domains_with_more_changes(monkeypatch):
    calls = []
    monkeypatch.setattr(domain_history, "get_dt_api", lambda: _history_api(450, calls))
    capped = domain_history.fetch_domain_history("long.com", 200)
    assert capped.truncated and capped.record_count == 200 and "more changes are available" in capped.note
    assert calls == [0, 100]
    calls.clear()
    full = domain_history.fetch_domain_history("long.com", 0)   # no cap: every page
    assert not full.truncated and full.record_count == 450 and calls == [0, 100, 200, 300, 400]
    from core.api_usage import capped_history
    statuses = [capped.status_row(), full.status_row(),
                FetchResult("Domain History", "x.com", error="boom", record_count=5).status_row(),
                {"Source": "Domain History", "Target": "old.com", "Status": "Partial", "Records": 1000,
                 "Detail": "Stopped at 1000 change events"}]   # a dataset saved before the cap option
    assert capped_history(statuses) == {"long.com": 200, "old.com": 1000}


def test_domain_history_cap_option_reaches_the_cache_key_and_plan():
    from core.use_cases import history_cap, history_limit_text
    assert collector.history_args("a.com", None, 1000) == ("a.com",)
    assert collector.history_args("a.com", None, 0) == ("a.com", 0)
    assert collector.history_args("a.com", "2026-10-01", 2000) == ("a.com", 2000, "2026-10-01")
    assert history_cap("all", 2500) == 2500 and history_cap("unlimited", 2500) == 0 and history_cap("days", None) == 1000
    assert history_limit_text({"opt_history_max": 2500}) == "2,500 changes"
    assert history_limit_text({"opt_history_mode": "unlimited"}).startswith("All time, no limit")


def test_fetch_the_rest_replaces_only_the_capped_domains_history(monkeypatch):
    calls = []

    def fake(domains, log, days=0, max_changes=1000):
        calls.append((list(domains), days, max_changes))
        for d in domains:
            log.record(FetchResult("Domain History", d, data={}, record_count=2500))
        return (pd.DataFrame({"Domain": ["long.com"] * 2, "Field": ["IP", "NS"]}),
                pd.DataFrame({"Domain": ["long.com"], "Source": ["Domain History"], "Hash": ["new"]}))

    monkeypatch.setattr(collector, "collect_domain_history", fake)
    data = collector.CollectedData(
        dh=pd.DataFrame({"Domain": ["long.com", "short.com"], "Field": ["IP", "IP"]}),
        ssl=pd.DataFrame({"Domain": ["long.com", "long.com"], "Source": ["Domain History", "Certificate API"],
                          "Hash": ["old", "cert"]}),
        statuses=[{"Source": "Domain History", "Target": "long.com", "Status": "Partial", "Records": 1000,
                   "Detail": "Stopped at the cap of 1,000 changes; more changes are available"},
                  {"Source": "Domain History", "Target": "short.com", "Status": "OK", "Records": 1, "Detail": ""}])
    rows = collector.fetch_rest_of_history(data, ["long.com"], 0)
    assert calls == [(["long.com"], 0, 0)] and len(rows) == 1
    assert sorted(data.dh["Domain"]) == ["long.com", "long.com", "short.com"]
    assert set(data.ssl["Hash"]) == {"cert", "new"}   # the capped Domain History certificates are replaced
    from core.api_usage import capped_history
    assert capped_history(data.statuses) == {} and len(data.statuses) == 2


def test_data_sources_stats_per_run_source_and_target():
    statuses = [FetchResult("Domain History", "a.com", record_count=1000, truncated=True,
                            note="Stopped at the cap of 1,000 changes; more changes are available", queries=10).status_row(),
                FetchResult("Domain History", "b.com", record_count=4, cached_at=1.0).status_row(),
                FetchResult("DNSDB", "a.com", error="Server error (HTTP 503)", queries=2).status_row(),
                FetchResult("DNSDB", "b.com", queries=1).status_row()]
    overview = run_overview(statuses)
    assert (overview["Lookups"], overview["Targets"], overview["Sources"]) == (4, 2, 2)
    assert (overview["OK"], overview["Partial"], overview["No data"], overview["Errors"]) == (1, 1, 1, 1)
    assert (overview["Records"], overview["Queries"], overview["From cache"], overview["Answered"]) == (1004, 13, 1, 0.75)
    sources = source_stats(statuses).set_index("Source")
    assert sources.index.tolist() == ["DNSDB", "Domain History"]   # errors first
    assert sources.loc["Domain History", ["Product", "Avg records", "Max records", "From cache"]].tolist() == \
        ["domain-history", 502.0, 1000, 1]
    assert sources.loc["DNSDB", "Answered"] == 0.5
    targets = target_stats(statuses).set_index("Target")
    assert targets.loc["a.com", "Needs attention"] == "Domain History (partial), DNSDB (error)"
    assert targets.loc["b.com", "Needs attention"] == "" and targets.loc["b.com", "Sources"] == 2
    assert attention_rows(statuses)["Status"].tolist() == ["Error", "Partial"]
    assert run_overview([])["Lookups"] == 0 and source_stats([]).empty

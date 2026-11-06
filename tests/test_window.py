import pandas as pd

from core.dataset import build_dataset
from core.threat_detection import detect_threat_flags
from core.window import (
    ALL_TIME,
    AnalysisWindow,
    custom_window,
    filter_cert_events,
    filter_certificates,
    filter_pdns,
    filter_point_events,
    preset_window,
    resolve_window,
)
from integrations.collector import CollectedData
from integrations.dnsdb import parse_dnsdb_to_dataframe

NOW = pd.Timestamp("2026-10-18 12:34:56")
WIN30 = preset_window("Last 30 days", now=NOW)


def test_preset_and_custom_windows():
    assert WIN30.start == pd.Timestamp("2026-09-18 12:00:00") and WIN30.end is None  # floored to the hour, open-ended
    assert preset_window(ALL_TIME).is_all_time
    custom = custom_window("2026-10-01", "2026-10-02", "America/New_York")
    assert custom.start == pd.Timestamp("2026-10-01 04:00:00")  # local midnight in UTC
    assert custom.end == pd.Timestamp("2026-10-03 03:59:59")
    assert resolve_window("Custom range", None).is_all_time  # incomplete date selection falls back to all time


def test_filter_pdns_uses_last_seen():
    df = pd.DataFrame({"Domain": ["a", "a", "a"], "Field": ["A"] * 3,
                       "First Seen": pd.to_datetime(["2020-01-01", "2026-10-10", "2020-01-01"]),
                       "Last Seen": pd.to_datetime(["2026-10-15", "2026-10-11", "2021-01-01"])})
    kept = filter_pdns(df, WIN30)
    assert len(kept) == 2  # old-but-still-observed record is kept; record last seen in 2021 is dropped
    assert filter_pdns(df, AnalysisWindow()) is df


def test_certificate_and_point_event_filters():
    certs = pd.DataFrame({"Hash": ["valid", "expired", "no-dates"],
                          "Not Before Date": pd.to_datetime(["2026-01-01", "2024-01-01", None]),
                          "Not After Date": pd.to_datetime(["2027-01-01", "2024-04-01", None]),
                          "Date": pd.to_datetime(["2026-01-01", "2024-01-01", "2026-10-01"])})
    assert list(filter_certificates(certs, WIN30)["Hash"]) == ["valid", "no-dates"]
    events = pd.DataFrame({"Timestamp": ["2026-10-01T00:00:00Z", "2025-01-01T00:00:00Z"]})
    assert len(filter_point_events(events, WIN30, "Timestamp")) == 1
    hosts = pd.DataFrame({"Timestamp": ["2026-10-02T00:00:00Z", "2023-01-01T00:00:00Z"], "First Seen": [None, None], "Last Seen": [None, None]})
    assert len(filter_cert_events(hosts, WIN30)) == 1


def _collected(pdns):
    return CollectedData(targets=["a.com"], domain_targets=["a.com"], pdns_provider="DNSDB Scout", pdns=pdns)


def test_dataset_windowing_keeps_dormancy_context_for_detection():
    now = pd.Timestamp.now(tz="UTC").tz_localize(None)
    epoch = lambda ts: int(ts.tz_localize("UTC").timestamp())  # noqa: E731
    old, burst = now - pd.Timedelta(days=400), now - pd.Timedelta(days=5)
    records = [{"rrname": "a.com.", "rrtype": "NS", "rdata": ["ns1.old.net."], "time_first": epoch(old), "time_last": epoch(old)}]
    records += [{"rrname": "a.com.", "rrtype": rt, "rdata": [val], "time_first": epoch(burst + pd.Timedelta(hours=h)),
                 "time_last": epoch(burst + pd.Timedelta(hours=h))}
                for h, (rt, val) in enumerate([("NS", "ns1.new.net."), ("A", "45.33.12.1"), ("MX", "mx.new.net."), ("TXT", '"v=spf1 -all"')])]
    pdns = parse_dnsdb_to_dataframe(records, "a.com")
    fields = sorted(pdns["Field"].unique())
    ds = build_dataset(_collected(pdns), ["a.com"], [], fields, "UTC", preset_window("Last 30 days"))
    assert ds.window_stats["Passive DNS"] == (4, 5)  # the 400-day-old record is outside the window
    result = detect_threat_flags(ds.events_utc, {"risk_score": 0}, history_gaps=True, window_start=ds.window.start)
    # The dormant period lies before the window, but gaps were computed on full history, so the burst is still detected
    assert "Parked-to-Weaponized" in set(result.alerts["Threat Type"])
    # Without history gaps the windowed slice would have lost the dormancy context
    naive = detect_threat_flags(ds.events_utc, {"risk_score": 0})
    assert "Parked-to-Weaponized" not in set(naive.alerts.get("Threat Type", []))


def test_hops_are_windowed_by_new_domain_first_seen():
    obs = pd.DataFrame([
        {"IP": "45.33.12.9", "RRName": "a-old.com", "First Seen": pd.Timestamp("2025-01-01"), "Last Seen": pd.Timestamp("2025-03-01"), "Related": "t.com"},
        {"IP": "45.33.12.9", "RRName": "b-mid.com", "First Seen": pd.Timestamp("2025-03-05"), "Last Seen": pd.Timestamp("2026-10-01"), "Related": "t.com"},
        {"IP": "45.33.12.9", "RRName": "c-new.com", "First Seen": pd.Timestamp("2026-10-05"), "Last Seen": pd.Timestamp("2026-10-15"), "Related": "t.com"},
    ])
    full = detect_threat_flags(pd.DataFrame(), {}, enrichment_data={"t.com": {}}, ip_observations=obs)
    windowed = detect_threat_flags(pd.DataFrame(), {}, enrichment_data={"t.com": {}}, ip_observations=obs, window_start=WIN30.start)
    assert list(full.hops["To Domain"]) == ["b-mid.com", "c-new.com"]
    assert list(windowed.hops["To Domain"]) == ["c-new.com"]

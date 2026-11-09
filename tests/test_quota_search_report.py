"""Quota and expiry banners, indicator sightings, and the case report."""
import datetime as dt

import pandas as pd
import pytest

from core import persistence, seen
from core.account import account_alerts, dnsdb_alerts, quota_level
from core.case_report import build_case_report, infrastructure_rows, top_alerts
from integrations.collector import CollectedData

TODAY = dt.date(2026, 11, 9)


def product(pid, limit, used, expires=None):
    return {"id": pid, "per_month_limit": str(limit) if limit is not None else None, "usage": {"month": str(used)},
            "expiration_date": expires}


def test_quota_levels_warn_from_95_percent_and_turn_red_when_used_up():
    assert quota_level(949, 1000) is None and quota_level(950, 1000) == "warning"
    assert quota_level(1000, 1000) == "error" and quota_level(1200, 1000) == "error"
    assert quota_level(5, None) is None and quota_level(None, 100) is None


def test_account_alerts_cover_the_apps_products_quota_and_expiry():
    products = [product("domain-history", 10000, 9600), product("certificate-search", 10000, 10000),
                product("iris-investigate", 1000, 10, "2026-11-20"), product("certificate-events", 100, 1, "2026-11-01"),
                product("whois", 100, 100, "2026-11-10"),          # not used by this app: ignored
                product("account-information", 100000, 112, "2027-01-27")]
    alerts = account_alerts(products, TODAY)
    by = {(a["product"], a["level"]): a["text"] for a in alerts}
    assert by[("Domain history", "warning")].startswith("Domain history: 96% of this month's quota used (9,600 of")
    assert "quota is used up (10,000 of 10,000)" in by[("Certificate search", "error")]
    assert by[("Iris investigate", "warning")] == "Iris investigate expires on 2026-11-20 (in 11 days)"
    assert by[("Certificate events", "error")].startswith("Certificate events expired on 2026-11-01")
    assert not any(a["product"] == "Whois" for a in alerts) and len(alerts) == 4
    assert account_alerts(None) == [] and account_alerts([product("domain-history", 10000, 10)], TODAY) == []


def test_dnsdb_alerts_from_the_rate_limit_check():
    now = pd.Timestamp("2026-11-09", tz="UTC")
    expires = int(pd.Timestamp("2026-11-30", tz="UTC").timestamp())
    alerts = dnsdb_alerts({"limit": 1000, "remaining": 30, "expires": expires}, now)
    assert [a["level"] for a in alerts] == ["warning", "warning"] and "97% of the key's quota" in alerts[0]["text"]
    assert dnsdb_alerts({"limit": 1000, "remaining": 0}, now)[0]["level"] == "error"
    assert dnsdb_alerts({"limit": "unlimited", "remaining": "n/a", "expires": "n/a"}, now) == []
    assert dnsdb_alerts(None) == []


def test_normalize_and_match_indicators():
    assert seen.normalize("  hxxps://Evil[.]Example[.]com/login?x=1 ") == "evil.example.com"
    assert seen.normalize("ns1.example.net.") == "ns1.example.net" and seen.normalize("a[@]b[.]com") == "a@b.com"
    assert seen.matches("GA4: G-ABC123", "g-abc123") and seen.matches("1.2.3.4", "1.2.3.4")
    assert not seen.matches("ns1.dynect.net", "dynect.net") and seen.matches("ns1.dynect.net", "dynect.net", True)
    assert not seen.matches("10.0.0.1", "1", partial=True)   # too short for a partial search


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(persistence, "SETTINGS_FILE", tmp_path / "settings.json")
    persistence._ALL_RUNS_CACHE.update(signature=None, runs=[])
    return tmp_path


def test_search_finds_an_indicator_in_runs_and_datasets(store, monkeypatch):
    alerts = pd.DataFrame([{"Domain": "a.com", "Threat Type": "X", "Severity": "High"}])
    empty = pd.DataFrame(columns=["Domain", "Threat Type", "Severity"])
    key_a, key_b = persistence.target_set_key(["a.com"]), persistence.target_set_key(["b.com"])
    first = persistence.save_snapshot(key_a, ["a.com"], {"a.com": {"IP": ["1.2.3.4"], "Web Tracker": ["GA4: G-X1"]}},
                                      alerts, "Last 30 days")
    persistence.save_snapshot(key_b, ["b.com"], {"b.com": {"IP": ["1.2.3.4", "5.6.7.8"]}}, empty, "All time")
    manifests = [{"id": "d1", "created": "2026-11-01T00:00:00Z", "name": "case", "targets": ["c.com"],
                  "run_key": "k", "size_bytes": 1}]
    monkeypatch.setattr(seen, "list_offline_datasets", lambda: manifests)
    monkeypatch.setattr(seen, "dataset_artifacts", lambda m: {"c.com": {"Email": ["x@c.com"], "IP": ["1.2.3.4"]}})

    found = seen.search("1.2.3.4")
    assert list(found["Found in"]) == ["Run", "Run", "Offline dataset"] and set(found["Domain"]) == {"a.com", "b.com", "c.com"}
    stats = seen.summary(found)
    assert (stats["runs"], stats["datasets"], stats["target_lists"], stats["domains"]) == (2, 1, 3, 3)
    run_a = found[found["Domain"] == "a.com"].iloc[0]
    assert run_a["Alerts on domain"] == 1 and run_a["id"] == first["id"] and run_a["key"] == key_a
    assert list(seen.search("g-x1")["Kind"]) == ["Web Tracker"]
    assert list(seen.search("X@C.COM")["Kind"]) == ["Email"] and seen.search("x@c.com", include_datasets=False).empty
    assert list(seen.search("b.com")["Kind"]) == ["Target"] and seen.search("9.9.9.9").empty and seen.search("").empty


def test_runs_record_registration_and_soa_emails():
    enrichment = {"a.com": {"registrant_contact": {"email": [{"value": "Owner@A.com", "count": 3}]},
                            "admin_contact": {"email": [{"value": "select request email form at https://x", "count": 1}]},
                            "soa_email": [{"value": "hostmaster@a.com", "count": 9}], "ssl_email": []}}
    artifacts = persistence.collect_run_artifacts(CollectedData(targets=["a.com"], enrichment=enrichment))
    assert artifacts["a.com"]["Email"] == ["hostmaster@a.com", "owner@a.com"]


def _alerts():
    return pd.DataFrame([
        {"Domain": "low.com", "Threat Type": "Low thing", "Severity": "Low", "Confidence": "High",
         "Threat Logic": "minor", "Triggering IOCs": ""},
        {"Domain": "<script>alert(1)</script>.com", "Threat Type": "Phish", "Severity": "Critical",
         "Confidence": "Medium", "Threat Logic": "login <form> posts to evil", "Triggering IOCs": "1.2.3.4",
         "Status": "Malicious"},
        {"Domain": "b.com", "Threat Type": "C2", "Severity": "Critical", "Confidence": "High",
         "Threat Logic": "beacon", "Triggering IOCs": ""}])


def test_top_alerts_are_ordered_by_severity_then_confidence():
    assert list(top_alerts(_alerts(), 2)["Domain"]) == ["b.com", "<script>alert(1)</script>.com"]
    assert top_alerts(pd.DataFrame(), 5).empty


def test_case_report_has_every_section_and_escapes_values():
    alerts = _alerts()
    profiles = pd.DataFrame([{"Domain": "b.com", "Unified Risk": 91.0, "Base Domain Risk Score": 80,
                              "DIF Breakdown": "2 IPs"}])
    enrichment = {"b.com": {"registrar": {"value": "Reg Inc"}, "create_date": {"value": "2026-10-01"},
                            "ip": [{"address": {"value": "1.2.3.4"}, "asn": [{"value": 13335}],
                                    "country_code": {"value": "us"}}],
                            "name_server": [{"host": {"value": "ns1.b.com"}}]}}
    infra = infrastructure_rows(enrichment, ["b.com", "missing.com"])
    assert infra[0]["Registrar"] == "Reg Inc" and infra[0]["Name servers"] == ["ns1.b.com"] and len(infra) == 1
    iocs = pd.DataFrame([{"Type": "ipv4-addr", "Value": "1.2.3.4", "Domain": "b.com", "First Seen": "2026-10-01",
                          "Last Seen": "2026-11-01"}])
    page = build_case_report({"title": "Case <1>", "analyst": "SOC", "notes": "Takedown <now>",
                              "targets": ["b.com", "low.com"], "created": "2026-11-09T10:00:00Z", "window": "Last 30 days",
                              "origin": "live lookups"}, alerts, profiles, infra, iocs,
                             {"Lookups": 10, "Answered": 0.9}, top=2)
    for section in ("At a glance", "Summary", "Top alerts (2 of 3)", "Risk by domain", "Infrastructure snapshot",
                    "Indicators (1)"):
        assert section in page
    assert "<script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;.com" in page
    assert "Case &lt;1&gt;" in page and "Takedown &lt;now&gt;" in page and "login &lt;form&gt;" in page
    assert "Marked malicious" in page and "90% of 10" in page and "Low thing" not in page   # top 2 only
    bare = build_case_report({"targets": []}, None, None, [], None)
    assert "No alerts in this run" in bare and "<h1>Case report</h1>" in bare

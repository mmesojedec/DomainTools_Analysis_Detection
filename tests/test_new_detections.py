"""New lifecycle, certificate-timing, compound and cross-domain rules, and the tuning of noisy rules."""
import pandas as pd

from core.cert_utils import issuer_family
from core.correlation import collect_artifacts, correlate, link_strength
from core.threat_detection.compound_rules import (
    bulk_registration_alerts,
    campaign_wave_alerts,
    rule_lure_subdomain,
    rule_phishing_kit_staging,
)
from core.threat_detection.context import DomainContext
from core.threat_detection.engine import detect_threat_flags
from core.threat_detection.lifecycle_rules import rule_disposable_registrant, rule_ns_churn, rule_reregistered

NOW = pd.Timestamp("2026-06-01")


def ctx(domain="a.com", **kwargs):
    kwargs.setdefault("thresholds", {})
    return DomainContext(domain=domain, is_ip=False, now=NOW, **kwargs)


def events(rows):
    frame = pd.DataFrame(rows)
    frame["Date"] = pd.to_datetime(frame["Date"], format="mixed")
    return frame


def types(result):
    alerts = result.alerts if hasattr(result, "alerts") and isinstance(result.alerts, pd.DataFrame) else None
    if alerts is not None:
        return set(alerts["Threat Type"]) if not alerts.empty else set()
    return {alert["Threat Type"] for alert in result.alerts}


def test_link_strength_uses_iris_counts():
    assert link_strength("IP", 12) == "strong"
    assert link_strength("IP", 400) == "weak" and link_strength("IP", None) == "weak"
    assert link_strength("IP", 50_000) is None
    assert link_strength("Web Tracker", None) == "strong" and link_strength("Web Tracker", 5_000) == "weak"


def test_rare_shared_ip_links_two_domains():
    enrichment = {d: {"ip": [{"address": {"value": "45.1.2.3", "count": 3}}]} for d in ("a.com", "b.com")}
    result = correlate(collect_artifacts(pd.DataFrame(), pd.DataFrame(), enrichment, {}))
    assert result.domain_cluster.get("a.com") == result.domain_cluster.get("b.com") is not None
    common = {d: {"ip": [{"address": {"value": "45.1.2.3", "count": 400}}]} for d in ("a.com", "b.com")}
    assert not correlate(collect_artifacts(pd.DataFrame(), pd.DataFrame(), common, {})).clusters


def test_reregistered_and_disposable_email():
    c = ctx(profile={"create_date": pd.Timestamp("2026-05-01"), "first_seen": pd.Timestamp("2019-01-01"),
                     "email_domains": ["mailinator.com"]})
    rule_reregistered(c)
    rule_disposable_registrant(c)
    assert types(c) == {"Re-Registered Domain", "Disposable Registrant Email"}


def test_ns_churn_counts_providers_not_hosts():
    rows = [{"Domain": "a.com", "Date": f"2026-05-0{i + 1}", "Field": "NS", "Value": f"ns{i}.{p}"}
            for i, p in enumerate(["one.net", "one.net", "two.org", "three.io"])]
    c = ctx(events=events(rows))
    rule_ns_churn(c)
    assert types(c) == {"Name Server Churn"}
    same = ctx(events=events([dict(r, Value=f"ns{i}.one.net") for i, r in enumerate(rows)]))
    rule_ns_churn(same)
    assert not same.alerts


def _cert(**extra):
    base = {"Domain": "a.com", "Hash": "h1", "Source": "DomainTools Cert API", "Common Name": "www.a.com",
            "Issuer": "R11", "Issuer Org": "Let's Encrypt", "Alt Names List": ["www.a.com"],
            "Not Before Date": pd.Timestamp("2026-05-01"), "Not After Date": pd.Timestamp("2026-07-30"),
            "Has Embedded SCTs": True, "Is Precertificate": False}
    return {**base, **extra}


def test_certificate_staged_before_dns_and_backdated():
    ev = events([{"Domain": "a.com", "RRName": "www.a.com.", "Date": "2026-05-05", "Field": "A", "Value": "45.1.1.1"}])
    ssl = pd.DataFrame([_cert(**{"Signed Certificate Timestamps": [{"timestamp": "2026-05-04T00:00:00Z"}]})])
    found = types(detect_threat_flags(ev, {"risk_score": 0}, ssl_df=ssl))
    assert {"Certificate Staged Before DNS", "Backdated Certificate"} <= found


def test_rapid_weaponization_compares_the_hostname_it_names():
    # an unrelated subdomain resolving the same hour as the certificate no longer counts
    ev = events([{"Domain": "a.com", "RRName": "mail.a.com.", "Date": "2026-05-01 01:00", "Field": "A",
                  "Value": "45.1.1.1"},
                 {"Domain": "a.com", "RRName": "www.a.com.", "Date": "2026-03-01", "Field": "A", "Value": "45.1.1.2"}])
    found = types(detect_threat_flags(ev, {"risk_score": 0}, ssl_df=pd.DataFrame([_cert()])))
    assert "Rapid Weaponization (Cert-to-DNS Gap)" not in found


def test_unusual_fields_and_graded_self_signed():
    odd = _cert(**{"Serial Number": "01", "Extended Key Usage": ["Client Authentication"]})
    assert "Unusual Certificate Fields" in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0},
                                                                     ssl_df=pd.DataFrame([odd])))
    c2 = _cert(Issuer="Major Cobalt Strike", **{"Common Name": "Major Cobalt Strike", "Issuer Org": "",
                                                 "Is Self Signed": True})
    alerts = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=pd.DataFrame([c2])).alerts
    row = alerts[alerts["Threat Type"] == "Self-Signed Certificate Detected"].iloc[0]
    assert row["Severity"] == "Critical"


def test_phishing_kit_staging_needs_three_signals():
    c = ctx()
    c.flags |= {"lookalike", "nrd"}
    rule_phishing_kit_staging(c)
    assert not c.alerts
    c.flags.add("cert_staging")
    rule_phishing_kit_staging(c)
    assert types(c) == {"Phishing Kit Staging"}


def test_lure_subdomain():
    c = ctx("example.net", events=events([{"Domain": "example.net", "RRName": "paypal-login.secure.example.net.",
                                           "Date": "2026-05-01", "Field": "A", "Value": "45.1.1.1"}]))
    rule_lure_subdomain(c)
    assert types(c) == {"Lure Subdomain"}


def test_bulk_registration_cohort_and_campaign_wave():
    contexts = {}
    for i, d in enumerate(["a.com", "b.com", "c.com"]):
        created = pd.Timestamp("2026-05-01") + pd.Timedelta(hours=5 * i)
        contexts[d] = ctx(d, profile={"create_date": created, "registrar": "NameCheap", "email_domains": [],
                                      "name_servers": ["ns1.evilhost.ru"], "ips": []},
                          ssl=pd.DataFrame([_cert(Domain=d, **{"Not Before Date": created + pd.Timedelta(hours=2)})]))
    bulk_registration_alerts(contexts)
    campaign_wave_alerts(contexts)
    for c in contexts.values():
        assert types(c) == {"Bulk Registration Cohort", "Campaign Wave (Same-Day Setup)"}


def test_noisy_rules_tuned():
    rows = [
        {"Domain": "a.com", "RRName": "sel._domainkey.mail.x.a.com.", "Date": "2026-05-01", "Field": "TXT",
         "Value": "v=DKIM1; k=rsa; p=" + "A" * 300},
        {"Domain": "a.com", "RRName": "live.a.com.", "Date": "2026-05-01", "Field": "A", "Value": "45.1.1.1"},
    ] + [{"Domain": "a.com", "RRName": "_acme-challenge.www.a.com.", "Date": f"2026-05-{d:02d}", "Field": "TXT",
          "Value": "token"} for d in range(1, 20)]
    found = types(detect_threat_flags(events(rows), {"risk_score": 0}))
    assert not found & {"Anomalous TXT Payload", "Deeply Nested Subdomains", "ACME Certificate Sprawl",
                        "IPTV / Stream Distribution Endpoint"}


def test_sha1_before_2017_is_history():
    old = _cert(**{"Signature Algo": "sha1WithRSAEncryption", "Not Before Date": pd.Timestamp("2015-01-01"),
                   "Not After Date": pd.Timestamp("2016-01-01")})
    alerts = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=pd.DataFrame([old])).alerts
    row = alerts[alerts["Threat Type"] == "Deprecated Signature Algorithm"].iloc[0]
    assert (row["Severity"], row["Confidence"]) == ("Medium", "Low")


def test_issuer_family_is_shared():
    assert issuer_family({"Issuer": "R11"})[0] == "letsencrypt"
    assert issuer_family({"Issuer": "WE1"})[0] == "google"
    assert issuer_family({"Issuer": "Corp CA"}) == ("other", "Corp CA")


def test_allowlist_parsing_and_matching():
    from core.allowlist import parse_allowlist
    allow = parse_allowlist("203.0.113.0/24, AS64500\nns:corp-dns.example\norg:Example Corp\ntracker:G-ABC\n# note")
    assert allow.ip("203.0.113.9") and allow.ip("8.8.8.8", asn=64500) and not allow.ip("8.8.8.8")
    assert allow.name_server("ns1.corp-dns.example") and allow.artifact("Web Tracker", "GA4: g-abc")
    assert allow.in_text("Certificate org Example Corp issued") == "example corp"


def test_allowlisted_ip_does_not_link_and_lowers_alerts():
    enrichment = {d: {"ip": [{"address": {"value": "45.1.2.3", "count": 3}}]} for d in ("a.com", "b.com")}
    from core.allowlist import parse_allowlist
    artifacts = collect_artifacts(pd.DataFrame(), pd.DataFrame(), enrichment, {}, parse_allowlist("45.1.2.0/24"))
    assert artifacts.empty
    ev = events([{"Domain": "a.com", "Date": "2026-05-01", "Field": "MX", "Value": "mx.cock.li"}])
    alerts = detect_threat_flags(ev, {"risk_score": 0}, allowlist="ns:cock.li").alerts
    assert set(alerts["Confidence"]) == {"Low"}


def test_verdict_feedback_and_malicious_link():
    from core.triage import calibrate_alerts, rule_feedback
    entries = {f"d{i}.com|R": {"domain": f"d{i}.com", "threat_type": "R", "status": "Benign"} for i in range(5)}
    alerts = pd.DataFrame([{"Domain": "x.com", "Threat Type": "R", "Confidence": "High", "Threat Logic": "why"}])
    out = calibrate_alerts(alerts, rule_feedback(entries))
    assert out.iloc[0]["Confidence"] == "Medium" and "your verdicts" in out.iloc[0]["Threat Logic"]
    ssl = pd.DataFrame([_cert(Domain=d, Hash="shared") for d in ("a.com", "b.com")])
    found = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl, verdicts={"a.com": "Malicious"}).alerts
    linked = found[found["Threat Type"] == "Linked to Confirmed-Malicious Domain"]
    assert list(linked["Domain"]) == ["b.com"]


def test_stix_bundle_has_attack_patterns_and_confidence():
    import json

    from core.export import to_stix_bundle
    iocs = pd.DataFrame([{"Type": "domain-name", "Value": "a.com", "Domain": "a.com", "Source": "x", "Note": ""}])
    alerts = pd.DataFrame([{"Domain": "a.com", "Threat Type": "Typosquatting Lookalike", "Severity": "High",
                            "Confidence": "Medium", "MITRE ATT&CK": "T1583.001 (Acquire Infrastructure: Domains)"}])
    objects = json.loads(to_stix_bundle(iocs, alerts))["objects"]
    kinds = [o["type"] for o in objects]
    assert "attack-pattern" in kinds and "relationship" in kinds
    indicator = next(o for o in objects if o["type"] == "indicator")
    assert indicator["indicator_types"] == ["malicious-activity"] and indicator["confidence"] == 60
    low = alerts.assign(Severity="Low")
    indicator = next(o for o in json.loads(to_stix_bundle(iocs, low))["objects"] if o["type"] == "indicator")
    assert indicator["indicator_types"] == ["anomalous-activity"]


def test_lookalike_candidates_and_query():
    from core.lookalike import lookalike_candidates, lookalike_query
    names = lookalike_candidates(["paypal"], ["paypal.com"])
    assert "paypal.com" not in names and {"paypal.net", "paypal-login.com", "paypa1.com", "paypl.com"} <= set(names)
    assert lookalike_query(names[:2]).endswith(f'DOMAIN EXACTLY_IN ["{names[0]}", "{names[1]}"]')


def test_query_watch_reports_only_new_domains(monkeypatch):
    import core.query_watch as qw
    store = {}
    monkeypatch.setattr(qw, "load_settings", lambda: dict(store))
    monkeypatch.setattr(qw, "save_setting", lambda key, value: store.__setitem__(key, value))
    qw.add_watch("actor", "# IrisQL-1.0\nDOMAIN CONTAINS \"x\"", 100, "", ["a.com", "b.com"])
    new, previous = qw.check_watch("actor", ["a.com", "b.com", "c.com"])
    assert new == ["c.com"] and previous
    assert qw.check_watch("actor", ["c.com"])[0] == []
    qw.remove_watch("actor")
    assert qw.list_watches() == []

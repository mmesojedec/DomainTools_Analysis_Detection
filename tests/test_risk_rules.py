"""DomainTools risk score rules: high Proximity with a low threat profile (neighbourhood, possible hijack)."""
import pandas as pd

from config import DEFAULT_THRESHOLDS
from core.threat_detection.context import DomainContext
from core.threat_detection.engine import detect_threat_flags
from core.threat_detection.risk_rules import recent_changes, risk_pattern, rule_risk_neighbourhood
from integrations.risk import risk_components, risk_response_to_rows, risk_rows_to_dataframe

NOW = pd.Timestamp("2026-06-01")
OLD = pd.Timestamp("2018-03-01")


def components(proximity=100, malware=2, phishing=10, spam=20):
    response = {"risk_score": max(proximity, malware, phishing, spam), "components": [
        {"name": "proximity", "risk_score": proximity, "evidence": ["registrant", "name server"]},
        {"name": "threat_profile", "risk_score": max(malware, phishing, spam)},
        {"name": "threat_profile_malware", "risk_score": malware},
        {"name": "threat_profile_phishing", "risk_score": phishing},
        {"name": "threat_profile_spam", "risk_score": spam, "threats": ["spam"]}]}
    return risk_rows_to_dataframe(risk_response_to_rows("a.com", response))


def ctx(risk=None, events=None, created=OLD, ips=()):
    return DomainContext(domain="a.com", is_ip=False, thresholds=dict(DEFAULT_THRESHOLDS), now=NOW,
                         risk_components=risk_components(risk if risk is not None else components())["a.com"],
                         events=events if events is not None else pd.DataFrame(),
                         profile={"create_date": created, "ips": list(ips)})


def pdns(rows):
    frame = pd.DataFrame(rows, columns=["Date", "Field", "Value", "RRName"])
    frame["Date"] = pd.to_datetime(frame["Date"])
    return frame


def dh(rows):
    frame = pd.DataFrame(rows, columns=["Date", "Field", "Before", "Value"]).assign(**{"Change Event": "changed"})
    frame["Date"] = pd.to_datetime(frame["Date"])
    return frame


def test_components_are_named_and_the_pattern_needs_every_threat_score_low():
    named = risk_components(components())["a.com"]
    assert list(named) == ["Overall", "Proximity", "Threat profile", "Malware", "Phishing", "Spam"]
    assert named["Proximity"]["Evidence"] == "registrant, name server" and named["Spam"]["Threats"] == "spam"
    assert risk_pattern(named, 90, 30) == (100, {"Malware": 2, "Phishing": 10, "Spam": 20})
    assert risk_pattern(risk_components(components(spam=45))["a.com"], 90, 30) is None
    assert risk_pattern(risk_components(components(proximity=80))["a.com"], 90, 30) is None
    unknown = {k: v for k, v in named.items() if k != "Malware"}
    assert risk_pattern(unknown, 90, 30) is None   # an unknown score is not a low one


def test_old_domain_moved_to_a_new_network_is_a_possible_hijack():
    moved = pdns([("2025-01-01", "A", "198.51.100.7", "a.com"), ("2026-05-10", "A", "203.0.113.9", "a.com"),
                  ("2026-05-12", "A", "192.0.2.5", "shop.a.com")])   # other subdomains do not count
    c = ctx(events=moved)
    assert [(kind, value) for _, kind, value in recent_changes(c, 90)] == [("IP", "203.0.113.9")]
    rule_risk_neighbourhood(c)
    (alert,) = c.alerts
    assert alert["Threat Type"] == "Possible Domain Hijack" and alert["Severity"] == "High"
    assert "Proximity 100" in alert["Triggering IOCs"] and "203.0.113.9" in alert["Triggering IOCs"]
    assert "hijack" in c.flags


def test_domain_history_changes_compare_before_and_after():
    history = dh([("2026-05-01", "REGISTRAR", None, "NameSilo, LLC"),          # first capture: not a change
                  ("2026-05-02", "NAME_SERVER", "host: ns1.oldhost.com", "host: ns1.newdns.net, ip: 192.0.2.1"),
                  ("2026-05-03", "REGISTRANT_ORG", "Acme Ltd", "Acme Ltd")])  # unchanged value
    assert [(kind, value) for _, kind, value in recent_changes(ctx(events=history), 90)] == \
        [("Name servers", "ns1.newdns.net")]


def test_without_age_or_change_it_is_only_a_neighbourhood_alert():
    same = pdns([("2025-01-01", "A", "198.51.100.7", "a.com"), ("2026-05-10", "A", "198.51.100.8", "a.com")])
    for c, reason in ((ctx(events=same), "No move"), (ctx(created=pd.Timestamp("2026-04-01")), "days old")):
        rule_risk_neighbourhood(c)
        (alert,) = c.alerts
        assert alert["Threat Type"] == "Benign-Looking Domain in Malicious Neighborhood", reason
        assert reason in alert["Threat Logic"] and alert["Confidence"] == "Medium"


def test_shared_hosting_lowers_confidence_and_low_proximity_is_quiet():
    c = ctx(ips=[{"ip": "198.51.100.7", "count": 25_000}])
    rule_risk_neighbourhood(c)
    assert c.alerts[0]["Confidence"] == "Low" and "shared hosting" in c.alerts[0]["Threat Logic"]
    quiet = ctx(risk=components(proximity=60))
    rule_risk_neighbourhood(quiet)
    assert not quiet.alerts


def test_engine_runs_the_rule_even_below_the_min_risk_score():
    risk = components(proximity=92)
    enrichment = {"a.com": {"domain": "a.com", "create_date": {"value": "2018-03-01"}}}
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 95}, risk_df=risk, enrichment_data=enrichment)
    assert "Benign-Looking Domain in Malicious Neighborhood" in set(result.alerts["Threat Type"])

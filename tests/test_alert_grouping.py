import pandas as pd

from core.alert_grouping import alert_evidence, group_alerts, merge_duplicate_alerts, primary_technique
from core.correlation import Correlation
from core.threat_detection import detect_threat_flags
from core.threat_detection.context import ALERT_COLUMNS, evidence_from_iocs, evidence_record


def alert(domain, threat_type, severity="High", confidence="Medium", mitre="T1583.001 (Acquire Infrastructure)",
          logic="logic", iocs="ioc", evidence=None):
    row = dict.fromkeys(ALERT_COLUMNS, "")
    row.update({"Domain": domain, "Threat Type": threat_type, "Severity": severity, "Confidence": confidence,
                "MITRE ATT&CK": mitre, "Threat Logic": logic, "Triggering IOCs": iocs,
                "Evidence": evidence if evidence is not None else [], "Occurrences": 1})
    return row


def frame(*rows):
    return pd.DataFrame(list(rows), columns=ALERT_COLUMNS)


def self_signed_cert(domain, hash_value, issued):
    return {"Domain": domain, "Hash": hash_value, "Common Name": domain, "Issuer": domain, "Is Self Signed": True,
            "Alt Names List": [domain], "Not Before Date": pd.Timestamp(issued), "Not After Date": pd.Timestamp(issued) + pd.Timedelta(days=90)}


def test_evidence_from_iocs_parses_event_and_key_value_lines():
    records = evidence_from_iocs("[2024-03-01 10:00] NS ➔ ns1.duckdns.org\nCert Issued: 2024-03-02 08:00\nRegistrar: Foo\n"
                                 "free text line\n... 3 more observations")
    assert [r["Field"] for r in records] == ["NS", "Cert Issued", "Registrar", ""]
    assert records[0]["Time"] == pd.Timestamp("2024-03-01 10:00") and records[0]["Value"] == "ns1.duckdns.org"
    assert records[1]["Time"] == pd.Timestamp("2024-03-02 08:00")
    assert pd.isna(records[2]["Time"]) and records[3]["Value"] == "free text line"


def test_evidence_record_normalizes_tz_aware_times_to_naive_utc():
    record = evidence_record(pd.Timestamp("2024-01-01 12:00", tz="Europe/Ljubljana"), "A", "1.2.3.4")
    assert record["Time"] == pd.Timestamp("2024-01-01 11:00")


def test_dns_rule_emits_structured_evidence():
    ev = pd.DataFrame([{"Domain": "a.com", "Date": pd.Timestamp("2024-01-01 09:30"), "Field": "MX", "Value": "mx.yandex.ru"}])
    result = detect_threat_flags(ev, {"risk_score": 0})
    row = result.alerts[result.alerts["Threat Type"] == "High-Risk Mail Provider"].iloc[0]
    assert row["Evidence"] == [{"Time": pd.Timestamp("2024-01-01 09:30"), "Field": "MX", "Value": "mx.yandex.ru", "Artifact": None}]


def test_per_certificate_alerts_merge_into_one_with_all_evidence():
    ssl = pd.DataFrame([self_signed_cert("a.com", "h1", "2024-01-01"), self_signed_cert("a.com", "h2", "2024-02-01")])
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl)
    self_signed = result.alerts[result.alerts["Threat Type"] == "Self-Signed Certificate Detected"]
    assert len(self_signed) == 1
    row = self_signed.iloc[0]
    assert row["Occurrences"] == 2
    assert sorted(r["Artifact"] for r in row["Evidence"]) == ["h1", "h2"]
    assert "h1" in row["Triggering IOCs"] and "h2" in row["Triggering IOCs"]
    assert not result.alerts.duplicated(subset=["Domain", "Threat Type"]).any()


def test_merge_keeps_worst_severity_logic_and_best_confidence():
    merged = merge_duplicate_alerts(frame(
        alert("a.com", "Burner", severity="High", confidence="Low", logic="45 days", iocs="x",
              evidence=[evidence_record("2024-01-01", "Certificate", "c1", "h1")]),
        alert("a.com", "Burner", severity="Critical", confidence="High", logic="5 days", iocs="y",
              evidence=[evidence_record("2024-01-01", "Certificate", "c1", "h1"), evidence_record("2024-02-01", "Certificate", "c2", "h2")]),
        alert("b.com", "Burner"),
    ))
    assert len(merged) == 2
    row = merged[merged["Domain"] == "a.com"].iloc[0]
    assert (row["Severity"], row["Confidence"], row["Occurrences"]) == ("Critical", "High", 2)
    assert row["Threat Logic"].startswith("5 days") and "+1 similar" in row["Threat Logic"]
    assert [r["Artifact"] for r in row["Evidence"]] == ["h1", "h2"]  # duplicates across merged alerts dropped


def test_merge_drops_exact_duplicates_without_marking_them_merged():
    merged = merge_duplicate_alerts(frame(alert("a.com", "X"), alert("a.com", "X")))
    assert len(merged) == 1 and merged.iloc[0]["Threat Logic"] == "logic" and merged.iloc[0]["Occurrences"] == 1


def test_group_by_finding_spans_domains_and_sorts_by_severity():
    alerts = frame(
        alert("a.com", "Fast-Flux", severity="High", evidence=[evidence_record("2024-01-05", "A", "1.1.1.1")]),
        alert("b.com", "Fast-Flux", severity="Medium", evidence=[evidence_record("2024-03-01", "A", "2.2.2.2")]),
        alert("a.com", "Burner", severity="Critical"),
    )
    groups = group_alerts(alerts, "Finding")
    assert list(groups["Group"]) == ["Burner", "Fast-Flux"]
    flux = groups.iloc[1]
    assert (flux["Worst Severity"], flux["Domains"], flux["Alerts"]) == ("High", 2, 2)
    assert flux["Domain List"] == ["a.com", "b.com"]
    assert (flux["First Seen"], flux["Last Seen"]) == (pd.Timestamp("2024-01-05"), pd.Timestamp("2024-03-01"))
    assert sorted(alerts.loc[flux["Members"], "Domain"]) == ["a.com", "b.com"]


def test_group_by_campaign_cluster_uses_correlation_and_falls_back_to_domain():
    correlation = Correlation(clusters=[{"Cluster": "C1", "Domains": ["a.com", "b.com"], "Size": 2, "Strength": "Strong",
                                         "Shared Artifacts": {}}],
                              domain_cluster={"a.com": "C1", "b.com": "C1"})
    alerts = frame(alert("a.com", "X"), alert("b.com", "Y"), alert("c.com", "Z", severity="Low"))
    groups = group_alerts(alerts, "Campaign Cluster", correlation)
    assert list(groups["Label"]) == ["Cluster C1 · Strong · 2 domains", "c.com (no shared infrastructure)"]
    assert groups.iloc[0]["Threat Types"] == ["X", "Y"]


def test_group_by_technique_and_domain():
    alerts = frame(alert("a.com", "X", mitre="T1568.001 (Fast Flux DNS)"), alert("b.com", "Y", mitre="T1568.001 (Fast Flux)"),
                   alert("a.com", "Z", mitre="n/a"))
    by_technique = group_alerts(alerts, "ATT&CK Technique")
    assert set(by_technique["Label"]) == {"T1568.001 · Command and Control", "No technique"}
    assert group_alerts(alerts, "Domain").set_index("Group")["Alerts"].to_dict() == {"a.com": 2, "b.com": 1}
    assert primary_technique("T1583.001 (Acquire Infrastructure), T1588") == "T1583.001"


def test_group_alerts_empty():
    assert group_alerts(frame(), "Finding").empty


def test_alert_evidence_is_time_ordered_with_undated_last_and_ioc_fallback():
    alerts = frame(
        alert("a.com", "X", evidence=[evidence_record(None, "IP", "1.1.1.1"), evidence_record("2024-02-01", "A", "2.2.2.2")]),
        alert("b.com", "Y", evidence=[evidence_record("2024-01-01", "NS", "ns.example")]),
        alert("c.com", "Z", iocs="raw ioc text"),
    )
    evidence = alert_evidence(alerts)
    assert list(evidence["Value"][:2]) == ["ns.example", "2.2.2.2"]
    assert evidence["Time"].iloc[2:].isna().all()
    assert "raw ioc text" in set(evidence["Value"])
    assert list(evidence.columns) == ["Time", "Domain", "Threat Type", "Severity", "Field", "Value", "Artifact"]

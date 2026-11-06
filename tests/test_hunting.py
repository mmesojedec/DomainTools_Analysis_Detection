import json
from types import SimpleNamespace

import pandas as pd

import core.persistence as persistence
from core.dataset import Dataset
from core.export import IOC_COLUMNS, confirmed_indicators, ioc_type, to_misp_event
from core.hunt_stats import (
    alerts_by_category,
    cluster_callouts,
    data_health,
    glance_stats,
    lifecycle_stats,
    shared_infrastructure,
    weekly_activity,
)
from core.hunt_tree import hunt_trail, hunt_tree, trail_text
from core.pivots import iris_queries, top_leads
from core.risk_profile import drivers_text, score_drivers
from core.run_history import diff_artifacts
from core.triage import attach_status, domain_verdicts, load_triage, open_alerts, set_status, status_of, triage_counts
from views.hunt_actions import certificate_target

NOW = pd.Timestamp("2026-11-01")


def iris(create, expire, ips=(), ns=(), registrar="Reg Inc"):
    return {"create_date": {"value": create}, "expiration_date": {"value": expire}, "registrar": {"value": registrar},
            "ip": [{"address": {"value": ip}, "asn": [{"value": asn}], "isp": {"value": isp}} for ip, asn, isp in ips],
            "name_server": [{"host": {"value": host}} for host in ns]}


def dataset():
    pdns = pd.DataFrame({
        "Domain": ["a.com", "a.com", "a.com", "b.com"],
        "RRName": ["a.com", "a.com", "www.a.com", "b.com"],
        "Field": ["A", "NS", "A", "NS"],
        "Value": ["1.1.1.1\n2.2.2.2", "ns1.shared.net.", "3.3.3.3", "ns1.shared.net."],
        "First Seen": pd.to_datetime(["2026-10-01", "2026-10-02", "2026-10-20", "2026-10-03"]),
        "Date": pd.to_datetime(["2026-10-01", "2026-10-02", "2026-10-20", "2026-10-03"]),
    })
    ssl = pd.DataFrame({
        "Domain": ["a.com", "b.com"], "Hash": ["a" * 64, "b" * 64], "Common Name": ["a.com", "b.com"],
        "Issuer": ["R3", "b.com"], "Issuer Org": ["Let's Encrypt", ""], "Is Self Signed": [False, True],
        "Not Before Date": pd.to_datetime(["2026-10-05", "2026-01-01"]),
        "Not After Date": pd.to_datetime(["2026-11-20", "2027-01-01"]),
        "Source": ["DomainTools Cert API", "DomainTools Cert API"],
    })
    ds = Dataset(selected_domains=["a.com", "b.com"], timezone="UTC", pdns_provider="DNSDB Scout")
    ds.pdns_utc, ds.ssl_utc, ds.events_utc = pdns, ssl, pdns
    ds.enrichment = {"a.com": iris("2026-10-15", "2026-11-10", [("1.1.1.1", 13335, "Cloudflare")], ["ns1.shared.net"]),
                     "b.com": iris("2001-01-01", "2030-01-01", [("9.9.9.9", 13335, "Cloudflare")], ["ns1.shared.net"])}
    return ds


def alert_frame(rows):
    return pd.DataFrame(rows, columns=["Domain", "Threat Type", "Severity", "Category", "MITRE ATT&CK"])


def test_triage_status_is_kept_attached_and_counted(tmp_path):
    path = tmp_path / "triage.json"
    alerts = alert_frame([("a.com", "X", "High", "Email", ""), ("b.com", "Y", "Low", "DNS", "")])
    set_status([("a.com", "X")], "Malicious", "phishing kit", path=path)
    set_status([("b.com", "*")], "Benign", path=path)
    found = attach_status(alerts, load_triage(path))
    assert list(found["Status"]) == ["Malicious", "New"] and found["Triage Note"][0] == "phishing kit"
    assert triage_counts(found) == {"New": 1, "Investigating": 0, "Benign": 0, "Malicious": 1}
    assert list(open_alerts(found)["Domain"]) == ["b.com"]
    assert domain_verdicts(load_triage(path)) == {"b.com": "Benign"}
    assert status_of(load_triage(path), "b.com") == ("Benign", "")
    set_status([("a.com", "X")], "New", path=path)   # back to New without a note: forgotten
    assert "a.com|X" not in load_triage(path)


def test_score_drivers_name_the_alert_behind_each_vector_and_the_floor():
    alerts = alert_frame([("a.com", "Self-Signed Certificate Detected", "High", "Certificates", "T1588.004")])
    profile = {"Domain": "a.com", "Domain Risk Score": 20, "Certificate Trust": 100, "DNS Volatility": 10}
    drivers = score_drivers(profile, alerts)
    assert drivers[0] == (30, "Certificate Trust: Self-Signed Certificate Detected (High)")
    assert (8, "DomainTools risk score 20") in drivers and drivers_text(drivers).startswith("+30 Certificate Trust")
    floor = score_drivers({"Domain": "a.com", "Domain Risk Score": 90, "DNS Volatility": 10}, alerts)
    assert len(floor) == 1 and "sets the score" in floor[0][1]


def test_glance_stats_count_the_run():
    alerts = alert_frame([("a.com", "X", "High", "Email", ""), ("b.com", "Y", "High", "DNS", "")])
    stats = glance_stats(dataset(), alerts)
    assert stats["Alerts"]["High"] == 2 and stats["Domains"] == 2
    assert stats["IPs"] == 4 and stats["ASNs"] == 1 and stats["Name servers"] == 1
    assert stats["Certificates"] == 2 and stats["Self-signed"] == 1 and stats["Hostnames"] == 3
    assert stats["First event"] == pd.Timestamp("2026-10-01")
    by_category = alerts_by_category(alerts)
    assert set(by_category["Category"]) == {"Email", "DNS"} and by_category["Alerts"].sum() == 2


def test_shared_infrastructure_marks_values_two_domains_use():
    shared = shared_infrastructure(dataset()).set_index(["Type", "Value"])
    assert shared.loc[("Name server", "ns1.shared.net"), "Domains"] == 2
    assert shared.loc[("Hosting network", "AS13335 Cloudflare"), "Shared"]
    assert not shared.loc[("Certificate issuer", "Let's Encrypt"), "Shared"]


def test_weekly_activity_and_lifecycle():
    activity = weekly_activity(dataset())
    assert {"Registration", "IP change", "Name server change", "New certificate", "New hostname"} <= set(activity["Activity"])
    assert activity["Week"].min() >= pd.Timestamp("2025-10-01")   # the 2001 registration is outside the 52 weeks
    life = lifecycle_stats(dataset(), now=NOW)
    assert life["Newest domain"][0] == "a.com"
    assert [d for d, _ in life["Registered recently"]] == ["a.com"]
    assert [d for d, _ in life["Domains expiring"]] == ["a.com"]
    assert [cn for cn, _ in life["Certificates expiring"]] == ["a.com"]


def test_data_health_and_cluster_callouts():
    statuses = [{"Status": "OK", "Detail": "From cache (1 h old)"}, {"Status": "Error", "Detail": "HTTP 503"},
                {"Status": "Partial", "Detail": ""}]
    rows = [SimpleNamespace(cache_hits=[("a.com", 100.0), ("b.com", 50.0)])]
    assert data_health(statuses, rows) == {"Lookups": 3, "OK": 1, "Partial": 1, "No data": 0, "Failed": 1,
                                           "Cached": 1, "Oldest cached": 50.0}
    correlation = SimpleNamespace(clusters=[
        {"Cluster": "C2", "Strength": "Moderate", "Size": 2, "Domains": ["c.com", "d.com"],
         "Shared Artifacts": {"IP": ["1.1.1.1"]}},
        {"Cluster": "C1", "Strength": "Strong", "Size": 2, "Domains": ["a.com", "b.com"],
         "Shared Artifacts": {"Certificate": ["h1", "h2", "h3"]}}])
    callouts = cluster_callouts(correlation)
    assert callouts[0]["Cluster"] == "C1" and callouts[0]["Text"] == "a.com, b.com share Certificate h1, h2 (+1)"


def test_hunt_tree_follows_parent_links():
    runs = [("k1", {"id": "r1", "created": "1", "targets": ["a.com"]}),
            ("k2", {"id": "r2", "created": "2", "targets": ["1.1.1.1"], "parent": {"id": "r1", "via": "IP 1.1.1.1"}}),
            ("k3", {"id": "r3", "created": "3", "targets": ["c.com"], "parent": {"id": "r2", "via": "Iris search"}}),
            ("k4", {"id": "r4", "created": "4", "targets": ["lonely.com"]})]
    assert [s["id"] for s in hunt_trail(runs, "r3")] == ["r1", "r2", "r3"]
    assert trail_text(hunt_trail(runs, "r2")) == "**a.com** *via IP 1.1.1.1* → **1.1.1.1**"
    tree = hunt_tree(runs)
    assert [(row["Run"], row["Depth"], row["Parent"]) for row in tree] == [("r1", 0, None), ("r2", 1, "r1"),
                                                                           ("r3", 2, "r2")]


def test_snapshot_records_its_parent_and_hostnames(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path / "runs")
    key = persistence.target_set_key(["a.com"])
    snapshot = persistence.save_snapshot(key, ["a.com"], {}, pd.DataFrame(), parent={"id": "r1", "via": "IP 1.1.1.1"})
    assert persistence.load_run(key, snapshot["id"])["parent"] == {"id": "r1", "via": "IP 1.1.1.1"}
    collected = SimpleNamespace(pdns=dataset().pdns_utc, dh=pd.DataFrame(), enrichment={}, ssl=pd.DataFrame(),
                                ssl_active=pd.DataFrame())
    assert persistence.collect_run_artifacts(collected)["a.com"]["Hostname"] == ["www.a.com"]


def test_diff_leaves_out_hostnames_an_older_snapshot_never_recorded():
    current = {"a.com": {"IP": ["1.1.1.1"], "Hostname": ["www.a.com"]}}
    assert set(diff_artifacts({"a.com": {"IP": []}}, current)["Artifact"]) == {"IP"}
    assert set(diff_artifacts({"a.com": {"Hostname": []}}, current)["Artifact"]) == {"IP", "Hostname"}


def test_watches_are_saved_once_per_target_list(tmp_path):
    path = tmp_path / "settings.json"
    persistence.save_watch("Shop", ["b.com", "a.com"], path=path)
    persistence.save_watch("Shop again", ["a.com", "b.com"], path=path)
    assert [w["name"] for w in persistence.load_watches(path)] == ["Shop again"]
    assert persistence.find_watch(["b.com", "a.com"], path=path)["name"] == "Shop again"
    persistence.remove_watch(["a.com", "b.com"], path=path)
    assert persistence.load_watches(path) == []


def test_leads_and_iris_queries():
    ranking = pd.DataFrame({"Signal": ["Strong", "Strong", "Weak"], "Type": ["IP address", "Contact email", "IP address"],
                            "Value": ["1.1.1.1", "x@y.com", "8.8.8.8"], "Iris Domains": [3, 10, 900000],
                            "Run Domains": [2, 1, 1], "Shared With": ["a.com, b.com", "c.com", "a.com"],
                            "Iris Search": ["ip=1.1.1.1", "email=x@y.com", "ip=8.8.8.8"],
                            "Analyze As": ["1.1.1.1", "", "8.8.8.8"]})
    assert list(top_leads(ranking)["Value"]) == ["1.1.1.1", "x@y.com"]
    assert top_leads(ranking[ranking["Signal"] == "Weak"]).empty
    assert iris_queries(ranking, {"c.com"}) == ["email=x@y.com"]


def test_confirmed_indicators_and_misp_event():
    iocs = pd.DataFrame([{"Type": "ipv4-addr", "Value": "1.1.1.1", "Domain": "a.com, b.com", "Source": "Iris"},
                         {"Type": "domain-name", "Value": "c.com", "Domain": "c.com", "Source": "Target"}],
                        columns=IOC_COLUMNS)
    alerts = alert_frame([("a.com", "X", "High", "Email", "")]).assign(
        Status=["Malicious"], Evidence=[[{"Artifact": "a" * 40, "Field": "Certificate"}, {"Artifact": "not one"}]])
    found = confirmed_indicators(iocs, alerts, {"c.com": "Benign"})
    assert list(zip(found["Type"], found["Value"])) == [("ipv4-addr", "1.1.1.1"), ("x509-sha1", "a" * 40)]
    assert confirmed_indicators(iocs, alerts.assign(Status="Benign"), {}).empty
    event = json.loads(to_misp_event(found))["Event"]
    assert [a["type"] for a in event["Attribute"]] == ["ip-dst", "x509-fingerprint-sha1"]
    assert ioc_type("2001:db8::1") == "ipv6-addr" and ioc_type("evil.example") == "domain-name"


def test_certificate_target_prefers_sha256():
    assert certificate_target("A" * 64, "b" * 40) == "sha256:" + "a" * 64
    assert certificate_target("", "b" * 40) == "sha1:" + "b" * 40
    assert certificate_target("c" * 40) == "sha1:" + "c" * 40 and certificate_target("short") == ""

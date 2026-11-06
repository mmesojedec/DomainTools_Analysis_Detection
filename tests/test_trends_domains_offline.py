import json
import re

import pandas as pd
import pytest

import core.offline as offline
import core.persistence as persistence
from core.run_history import artifact_trend, domain_history, domain_lifecycle, risk_trend, severity_trend, snapshot_domains
from integrations.collector import CollectedData


def snap(run_id, created, targets, alerts=(), profiles=(), artifacts=None, schema=2):
    return {"schema": schema, "id": run_id, "created": created, "targets": targets, "artifacts": artifacts or {},
            "alerts": [dict(zip(["Domain", "Threat Type", "Severity"], a)) for a in alerts],
            "profiles": [dict(zip(["Domain", "Unified Risk", "Base Domain Risk Score", "DIF Fingerprint"], p)) for p in profiles]}


RUNS = [
    snap("r1", "2026-10-01T00:00:00Z", ["a.com"], [("a.com", "X", "High")], [("a.com", 40, 30, "DIF1")], {"a.com": {"IP": ["1.1.1.1"]}}),
    snap("r2", "2026-10-05T00:00:00Z", ["a.com", "b.com"], [("a.com", "X", "High"), ("b.com", "Y", "Low")],
         [("a.com", 70, 30, "DIF2"), ("b.com", 10, 10, "DIFB")], {"a.com": {"IP": ["1.1.1.1", "2.2.2.2"]}}),
    snap("r3", "2026-10-09T00:00:00Z", ["a.com"], [("a.com", "Z", "Critical")], [("a.com", 90, 30, "DIF2")], {"a.com": {"IP": ["2.2.2.2"]}}),
]


def test_trends():
    sev = severity_trend(RUNS)
    assert sev.groupby("Run")["Alerts"].sum().to_dict() == {"r1": 1, "r2": 2, "r3": 1}
    risk = risk_trend(RUNS)
    a = risk[risk["Domain"] == "a.com"]
    assert list(a["Unified Risk"]) == [40, 70, 90] and list(a["DIF Changed"]) == [False, True, False]
    arts = artifact_trend(RUNS)
    assert list(arts[(arts["Domain"] == "a.com") & (arts["Artifact"] == "IP")]["Count"]) == [1, 2, 1]


def test_domain_history_across_target_lists():
    runs = [("k1", RUNS[0]), ("k2", RUNS[1]), ("k1", RUNS[2])]
    history = domain_history(runs, "b.com")
    assert [s["id"] for _, s in history] == ["r2"]
    a_hist = domain_history(runs, "a.com")
    assert [k for k, _ in a_hist] == ["k1", "k2", "k1"]
    assert all(set(snapshot_domains(s)) >= {"a.com"} for _, s in a_hist)
    assert all(alert["Domain"] == "a.com" for _, s in a_hist for alert in s["alerts"])
    life = domain_lifecycle(a_hist).set_index("Threat Type")
    assert life.loc["X", "Runs Seen"] == 2 and not life.loc["X", "Active in Latest Run"]
    assert life.loc["Z", "Active in Latest Run"]


@pytest.fixture
def stores(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(persistence, "SETTINGS_FILE", tmp_path / "settings.json")
    monkeypatch.setattr(offline, "OFFLINE_DIR", tmp_path / "offline")
    persistence._ALL_RUNS_CACHE.update(signature=None, runs=[])
    return tmp_path


def test_runs_before_spans_target_lists(stores):
    for key, s in (("aaaaaaaaaaaaaaaa", RUNS[0]), ("bbbbbbbbbbbbbbbb", RUNS[1]), ("aaaaaaaaaaaaaaaa", RUNS[2])):
        path = stores / "runs" / key
        path.mkdir(parents=True, exist_ok=True)
        (path / f"2026100{s['id'][-1]}T000000Z.json").write_text(json.dumps(s))
    assert [s["id"] for s in persistence.runs_before("2026-10-06T00:00:00Z", domains=["a.com"])] == ["r1", "r2"]
    assert [s["id"] for s in persistence.runs_before("2026-12-01T00:00:00Z", domains=["b.com"])] == ["r2"]
    assert len(persistence.load_all_runs()) == 3


def test_offline_roundtrip_and_management(stores):
    collected = CollectedData(
        targets=["a.com"], domain_targets=["a.com"], pdns_provider="DNSDB Scout",
        pdns=pd.DataFrame({"Domain": ["a.com"], "Field": ["A"], "Value": ["1.1.1.1"], "First Seen": pd.to_datetime(["2026-10-01"])}),
        ssl=pd.DataFrame({"Domain": ["a.com"], "Hash": ["h"], "Alt Names List": [["a.com", "*.a.com"]], "Basic Constraints": [{"is_ca": False}]}),
        enrichment={"a.com": {"ip": [{"address": {"value": "1.1.1.1"}}]}}, pdns_coverage={"a.com": {"truncated": True, "caa_checked": True}},
        statuses=[{"Source": "DNSDB Scout", "Target": "a.com", "Status": "OK", "Records": 1, "Detail": ""}],
    )
    manifest = offline.save_offline_dataset(collected, {"dnsdb_limit": 2000}, run_key="aaaaaaaaaaaaaaaa")
    assert manifest["frames"]["pdns"] == 1 and manifest["size_bytes"] > 0
    loaded, meta = offline.load_offline_dataset(manifest["id"])
    assert loaded.targets == ["a.com"] and loaded.enrichment == collected.enrichment and loaded.pdns_coverage == collected.pdns_coverage
    assert loaded.pdns["First Seen"].iloc[0] == pd.Timestamp("2026-10-01")
    assert loaded.ssl["Alt Names List"].iloc[0] == ["a.com", "*.a.com"] and loaded.ssl["Basic Constraints"].iloc[0] == {"is_ca": False}
    assert meta["settings"]["dnsdb_limit"] == 2000

    offline.update_offline_manifest(manifest["id"], name="baseline", run_id="20261019T000000Z", targets=["evil"])
    listed = offline.list_offline_datasets()[0]
    assert listed["name"] == "baseline" and listed["run_id"] == "20261019T000000Z" and listed["targets"] == ["a.com"]  # targets not editable

    offline.set_offline_retention(1)
    offline.save_offline_dataset(collected)
    assert len(offline.list_offline_datasets()) == 1
    offline.delete_offline_dataset(offline.list_offline_datasets()[0]["id"])
    assert offline.list_offline_datasets() == []
    with pytest.raises(ValueError):
        offline.load_offline_dataset("../../etc/passwd")


def test_domain_lifecycle_without_detections():
    quiet = [("k", snap("q1", "2026-10-01T00:00:00Z", ["quiet.com"], artifacts={"quiet.com": {"IP": ["1.1.1.1"]}}))]
    life = domain_lifecycle(quiet)
    assert life.empty and "Active in Latest Run" in life.columns


def test_saved_datasets_are_named_and_broken_down_part_by_part(stores):
    collected = CollectedData(
        targets=["a.com"], domain_targets=["a.com"], pdns_provider="DNSDB Scout",
        pdns=pd.DataFrame({"Domain": ["a.com", "a.com"], "Field": ["A", "NS"], "Value": ["1.1.1.1", "ns1.x.net"]}),
        enrichment={"a.com": {"domain": "a.com"}}, tor_overview={"counts": {"relays": 9}, "networks": []},
        statuses=[{"Source": "DNSDB Scout", "Target": "a.com", "Status": "Partial", "Records": 2,
                   "Detail": "Limit of 2 records reached"},
                  {"Source": "Domain History", "Target": "a.com", "Status": "OK", "Records": 0, "Detail": ""}])
    manifest = offline.save_offline_dataset(collected, {"pdns_provider": "DNSDB Scout", "dnsdb_limit": 2000,
                                                        "txt_records": 0, "vpndb_check": False})
    assert re.fullmatch(r"dt_analysis \d{4}-\d\d-\d\d \d\d:\d\d UTC", manifest["name"])
    assert offline.save_offline_dataset(collected, name=" case 7 ")["name"] == "case 7"
    parts, capped = offline.dataset_breakdown(manifest["id"])
    by = parts.set_index("Data")
    assert by.loc["Passive DNS", "Records"] == 2 and "2,000 records per domain" in by.loc["Passive DNS", "Limit applied"]
    assert "TXT" not in by.loc["Passive DNS", "Limit applied"] and by.loc["VPNDB verdicts", "Limit applied"] == "Off"
    assert by.loc["Tor network overview", "Records"] == 1 and by.loc["Iris Investigate records", "Records"] == 1
    assert parts["Bytes"].sum() <= offline.list_offline_datasets()[-1]["size_bytes"]
    assert list(capped["Source"]) == ["DNSDB Scout"]

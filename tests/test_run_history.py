import json

import pandas as pd
import pytest

import core.persistence as persistence
from core.run_history import (
    alert_lifecycle,
    compare_runs,
    first_detected_mask,
    resolved_since,
    run_summary,
    snapshot_alerts,
)

LEGACY = {"created": "2026-10-01T00:00:00Z", "targets": ["a.com"], "artifacts": {"a.com": {"IP": ["1.1.1.1"]}},
          "alerts": [["a.com", "High-Risk Mail Provider", "old logic"], ["a.com", "DGA / High Entropy Domain", "x"]]}


def v2(created, alerts, profiles=(), artifacts=None, window="Last 30 days"):
    return {"schema": 2, "created": created, "window": window, "artifacts": artifacts or {},
            "alerts": [dict(zip(["Domain", "Threat Type", "Severity", "Confidence"], a)) for a in alerts],
            "profiles": [dict(zip(["Domain", "Unified Risk", "Base Domain Risk Score", "DIF Fingerprint"], p)) for p in profiles]}


def alerts_df(rows):
    return pd.DataFrame(rows, columns=["Domain", "Threat Type", "Severity"])


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path / "runs")
    monkeypatch.setattr(persistence, "SETTINGS_FILE", tmp_path / "settings.json")
    return tmp_path


def test_legacy_snapshot_is_readable():
    alerts = snapshot_alerts(LEGACY)
    assert list(alerts["Threat Type"]) == ["High-Risk Mail Provider", "DGA / High Entropy Domain"]
    assert alerts["Severity"].isna().all()
    assert run_summary(LEGACY)["alerts"] == 2


def test_compare_runs_new_resolved_persisting_and_risk():
    base = v2("2026-10-01T00:00:00Z", [("a.com", "X", "High"), ("a.com", "Y", "Low")], [("a.com", 40, 30, "S-UN_x_NO_aaaaaa")],
              {"a.com": {"IP": ["1.1.1.1"]}})
    target = v2("2026-10-08T00:00:00Z", [("a.com", "Y", "Low"), ("b.com", "Z", "Critical")], [("a.com", 75, 30, "F-CF_y_EM_bbbbbb")],
                {"a.com": {"IP": ["2.2.2.2"]}}, window="Last 7 days")
    result = compare_runs(base, target)
    assert list(result.new["Threat Type"]) == ["Z"]
    assert list(result.resolved["Threat Type"]) == ["X"]
    assert list(result.persisting["Threat Type"]) == ["Y"]
    assert set(zip(result.artifact_diff["Value"], result.artifact_diff["Change"])) == {("2.2.2.2", "Added"), ("1.1.1.1", "Removed")}
    row = result.risk_changes.set_index("Domain").loc["a.com"]
    assert row["Risk Change"] == 35 and bool(row["DIF Changed"])
    assert result.window_mismatch and not result.legacy
    assert compare_runs(LEGACY, target).legacy


def test_alert_lifecycle_and_first_detected():
    history = [v2("2026-10-01T00:00:00Z", [("a.com", "X", "High")]), v2("2026-10-05T00:00:00Z", [("a.com", "X", "High")]), LEGACY]
    current = alerts_df([("a.com", "X", "High"), ("a.com", "NEW", "Low"), ("a.com", "High-Risk Mail Provider", "Low")])
    lifecycle = alert_lifecycle(history, current, "2026-10-19T00:00:00Z")
    assert lifecycle.loc[("a.com", "X"), "Runs Seen"] == 3
    assert lifecycle.loc[("a.com", "X"), "First Detected"] == pd.Timestamp("2026-10-01", tz="UTC")
    assert lifecycle.loc[("a.com", "NEW"), "Runs Seen"] == 1
    assert list(first_detected_mask(current, lifecycle)) == [False, True, False]


def test_resolved_since():
    previous = v2("2026-10-01T00:00:00Z", [("a.com", "X", "High"), ("a.com", "GONE", "Critical")])
    resolved = resolved_since(previous, alerts_df([("a.com", "X", "High")]))
    assert list(resolved["Threat Type"]) == ["GONE"] and resolved_since(None, alerts_df([])).empty


def test_store_save_list_meta_export_delete(store):
    key = persistence.target_set_key(["a.com", "b.com"])
    alerts = pd.DataFrame([{"Domain": "a.com", "Threat Type": "X", "Severity": "High", "Confidence": "Medium",
                            "Category": "Email", "MITRE ATT&CK": "T1", "Threat Logic": "l", "Triggering IOCs": "ignored"}])
    profiles = pd.DataFrame([{"Domain": "a.com", "Unified Risk": pd.Series([88]).iloc[0], "Base Domain Risk Score": 70, "DIF Fingerprint": "d"}])
    first = persistence.save_snapshot(key, ["b.com", "a.com"], {"a.com": {"IP": ["1.1.1.1"]}}, alerts, "Last 30 days", profiles)
    persistence.save_snapshot(key, ["a.com", "b.com"], {}, alerts.iloc[0:0], "All time", profiles.iloc[0:0])

    saved = json.loads((store / "runs" / key / f"{first['id']}.json").read_text())
    assert saved["schema"] == 2 and saved["profiles"][0]["Unified Risk"] == 88 and isinstance(saved["profiles"][0]["Unified Risk"], int)
    assert "Triggering IOCs" not in saved["alerts"][0] and saved["summary"]["by_severity"] == {"High": 1}

    sets = persistence.list_target_sets()
    assert sets[0]["key"] == key and sets[0]["runs"] == 2 and sets[0]["targets"] == ["a.com", "b.com"]
    runs = persistence.list_runs(key)
    assert [r["alerts"] for r in runs] == [0, 1]  # newest first

    persistence.update_run_meta(key, first["id"], name="Baseline", note="before takedown")
    assert persistence.load_run(key, first["id"])["name"] == "Baseline"
    assert json.loads(persistence.export_run_json(key, first["id"]))["note"] == "before takedown"

    persistence.delete_run(key, first["id"])
    assert len(persistence.list_runs(key)) == 1
    persistence.delete_target_set(key)
    assert persistence.list_target_sets() == []


def test_retention(store):
    key = persistence.target_set_key(["a.com"])
    persistence.set_run_retention(2)
    for _ in range(4):
        persistence.save_snapshot(key, ["a.com"], {}, pd.DataFrame(), None, None)
    assert persistence.run_retention() == 2 and len(persistence.list_runs(key)) == 2
    persistence.set_run_retention(5)
    persistence.save_snapshot(key, ["a.com"], {}, pd.DataFrame(), None, None)
    assert persistence.apply_retention(key, keep=1) == 2 and len(persistence.list_runs(key)) == 1


def test_invalid_identifiers_are_rejected(store):
    with pytest.raises(ValueError):
        persistence.load_run("../../etc", "20261019T000000Z")
    with pytest.raises(ValueError):
        persistence.delete_run(persistence.target_set_key(["a.com"]), "../settings")

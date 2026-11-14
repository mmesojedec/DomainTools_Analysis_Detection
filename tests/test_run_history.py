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
    assert sets[0]["summary"]["alerts"] == 0 and sets[0]["name"] == ""   # the latest run (no alerts)
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


def test_recent_runs_alert_text():
    from views.history_view import _severity_text
    assert _severity_text({"alerts": 3, "by_severity": {"Critical": 1, "High": 2, "Low": 0}}) == \
        "3 alerts (1 critical, 2 high)"
    assert _severity_text({"alerts": 1, "by_severity": {"Medium": 1}}) == "1 alert"
    assert _severity_text({}) == ""   # legacy runs keep no summary


def test_recent_runs_are_the_newest_across_target_lists_with_their_options(store):
    empty = pd.DataFrame(columns=["Domain", "Threat Type", "Severity"])
    a, b = persistence.target_set_key(["a.com"]), persistence.target_set_key(["b.com"])
    first = persistence.save_snapshot(a, ["a.com"], {}, empty, "Last 30 days")
    second = persistence.save_snapshot(b, ["b.com"], {}, empty, "All time",
                                       options={"use_case": "triage", "opt_dnsdb_limit": 500})
    third = persistence.save_snapshot(a, ["a.com"], {}, empty, "Last 7 days", name="again")
    runs = persistence.recent_runs(2)
    assert [r["id"] for r in runs] == [third["id"], second["id"]] and runs[0]["key"] == a and runs[0]["name"] == "again"
    assert runs[1]["options"] == {"use_case": "triage", "opt_dnsdb_limit": 500} and runs[0]["options"] == {}
    assert [r["id"] for r in persistence.recent_runs(10)][-1] == first["id"]


def test_offline_copy_of_a_run_is_its_newest_linked_dataset():
    from views.history_view import _offline_by_run
    datasets = [{"id": "old", "run_id": "r1", "created": "2026-11-01T00:00:00Z"},
                {"id": "new", "run_id": "r1", "created": "2026-11-02T00:00:00Z"},
                {"id": "loose", "run_id": None, "created": "2026-11-03T00:00:00Z"}]
    assert _offline_by_run(datasets) == {"r1": "new"}


def test_run_again_restores_the_runs_options_and_starts_a_run(monkeypatch):
    from views import sidebar
    state = {"opt_dnsdb_limit": 5000, "use_case": "triage", "analysis_window": "Last 30 days"}
    monkeypatch.setattr(sidebar.st, "session_state", state)
    options = {"opt_dnsdb_limit": 500, "opt_force_refresh": True, "use_case": "monitoring",
               "analysis_window": "Custom range", "analysis_window_range": ["2026-10-01", "2026-10-31"]}
    sidebar.run_again(["a.com", "b.com"], options)
    assert state["opt_dnsdb_limit"] == 500 and state["use_case"] == "monitoring" and "opt_force_refresh" not in state
    assert state["analysis_window"] == "Custom range" and str(state["analysis_window_range"][1]) == "2026-10-31"
    assert state[sidebar.TARGETS_KEY] == "a.com\nb.com" and state[sidebar.DATA_MODE_KEY] == sidebar.LIVE_MODE
    sidebar.run_again(["c.com"], {})   # a run saved before options were recorded: the current ones stay
    assert state["opt_dnsdb_limit"] == 500 and state[sidebar.TARGETS_KEY] == "c.com"


def test_run_options_records_the_window_range_only_for_a_custom_range(monkeypatch):
    import datetime as dt

    from views import sidebar
    state = {"opt_dnsdb_limit": 700, "opt_force_refresh": True, "use_case": None, "analysis_window": "Last 7 days",
             "analysis_window_range": (dt.date(2026, 1, 1), dt.date(2026, 1, 2))}
    monkeypatch.setattr(sidebar.st, "session_state", state)
    options = sidebar.run_options()
    assert options["opt_dnsdb_limit"] == 700 and "opt_force_refresh" not in options
    assert "analysis_window_range" not in options and options["analysis_window"] == "Last 7 days"
    state["analysis_window"] = "Custom range"
    assert sidebar.run_options()["analysis_window_range"] == ["2026-01-01", "2026-01-02"]


def test_recent_run_row_names_a_built_in_use_case_or_a_saved_profile():
    from core.use_cases import USE_CASES, profile_key
    from views.history_view import _recent_row
    profiles = [{"name": "My hunt", "description": "", "settings": {}}]
    base = {"created": "2026-11-09T10:00:00Z", "targets": ["a.com"], "seeds": [], "window": "Last 30 days",
            "summary": {"alerts": 0, "by_severity": {}}}
    case = USE_CASES[0]
    assert _recent_row({**base, "options": {"use_case": case.key}}, "UTC", None, profiles)["Use case"] == case.title
    assert _recent_row({**base, "options": {"use_case": profile_key("My hunt")}}, "UTC", "d1", profiles)["Use case"] \
        == "My hunt"
    assert _recent_row({**base, "options": {"use_case": None}}, "UTC", None, None)["Use case"] == "—"
    assert _recent_row({**base, "options": {}}, "UTC", None, profiles)["Use case"] == "not recorded"


def test_recent_runs_section_renders_runs_with_a_use_case_and_a_profile(store, monkeypatch):
    from streamlit.testing.v1 import AppTest

    from core.use_cases import PROFILES_SETTING, profile_key
    from views import recent_view
    empty = pd.DataFrame(columns=["Domain", "Threat Type", "Severity"])
    persistence.save_setting(PROFILES_SETTING, [{"name": "My hunt", "description": "", "settings": {}}])
    persistence.save_snapshot(persistence.target_set_key(["a.com"]), ["a.com"], {}, empty, "Last 30 days",
                              options={"use_case": "triage"})
    persistence.save_snapshot(persistence.target_set_key(["b.com"]), ["b.com"], {}, empty, "All time",
                              options={"use_case": profile_key("My hunt")})
    monkeypatch.setattr(recent_view, "list_offline_datasets", lambda: [])

    def page():
        from views import recent_view
        recent_view.render_recent_page("UTC")

    at = AppTest.from_function(page).run(timeout=30)   # Timeline is the default view
    assert not at.exception and len(at.get("plotly_chart")) == 2   # timeline + runs per day
    at.session_state["recent_view"] = "Cards"
    at.run(timeout=30)
    assert not at.exception and [b.label for b in at.button][:2] == ["Select", "Select"]
    assert any("first run" in m.value for m in at.markdown)
    at.session_state["recent_view"] = "Table"
    at.run(timeout=30)
    assert not at.exception
    assert list(at.dataframe[0].value["Use case"]) == ["My hunt", "Triage a suspicious domain"]
    at.text_input(key="recent_filter").input("a.com").run(timeout=30)
    assert list(at.dataframe[0].value["Targets"]) == ["a.com"]

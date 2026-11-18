"""Results toolbar: filters read from session state, applied to the loaded run without new lookups."""

import pandas as pd

from core.intel_data import SEVERITY_ORDER


def collected():
    from core.pdns_features import build_pdns_frame
    from integrations.collector import CollectedData
    now = pd.Timestamp("2026-11-01")
    pdns = build_pdns_frame([
        {"Domain": d, "RRName": f"www.{d}", "Field": f, "Value": v, "Count": 1, "Source": "DNSDB", "Bailiwick": d,
         "First Seen": now, "Last Seen": now}
        for d in ("a.com", "b.com") for f, v in (("A", "45.1.2.3"), ("MX", "mx.a.com"))])
    return CollectedData(targets=["a.com", "b.com"], domain_targets=["a.com", "b.com"], pdns=pdns)


def test_filter_alerts_keeps_the_picked_severities_and_their_masks():
    from views.results_toolbar import ViewFilters, filter_alerts
    active = pd.DataFrame({"Severity": ["High", "Low", "Critical"], "Confidence": ["High", "High", "Low"]})
    import dataclasses

    @dataclasses.dataclass
    class View:
        active: pd.DataFrame
        new_mask: pd.Series
        first_detected_mask: object = None

    view = View(active, pd.Series([True, False, True]))
    kept = filter_alerts(view, ViewFilters(severities=["High", "Critical"], confidences=["High"]))
    assert list(kept.active["Severity"]) == ["High"] and list(kept.new_mask) == [True]
    assert filter_alerts(view, ViewFilters()) is view   # every severity and confidence: unchanged


def test_toolbar_filters_change_the_run_view_and_reset(monkeypatch):
    from streamlit.testing.v1 import AppTest

    from views import navigation
    monkeypatch.setattr(navigation, "link", lambda *args, **kwargs: None)   # no page menu in a test app
    data = collected()

    def page():
        import streamlit as st

        from views.results_toolbar import filter_state, render_results_toolbar
        filters = filter_state(st.session_state["data"])
        render_results_toolbar(st.session_state["data"], filters)
        st.session_state["seen"] = (filters.domains, filters.pdns_types, filters.severities)

    at = AppTest.from_function(page)
    at.session_state["data"] = data
    at.session_state["analyst_mode"] = True
    at.run(timeout=30)
    assert not at.exception
    assert at.session_state["seen"] == (["a.com", "b.com"], ["A", "MX"], list(SEVERITY_ORDER))
    assert [p.proto.popover.label for p in at.get("popover")] == ["Domains · all", "Hostnames · all", "Record types · all", "Alerts · all", "Detection · defaults"]
    at.multiselect(key="view_domains::run").set_value(["b.com"]).run(timeout=30)
    at.multiselect(key="view_pdns_types::run").set_value(["MX"]).run(timeout=30)
    at.multiselect(key="flt_severity").set_value(["Critical"]).run(timeout=30)
    assert at.session_state["seen"] == (["b.com"], ["MX"], ["Critical"])
    assert at.get("popover")[0].proto.popover.label == "Domains · 1 of 2"
    at.button(key="toolbar_reset").click().run(timeout=30)
    assert at.session_state["seen"] == (["a.com", "b.com"], ["A", "MX"], list(SEVERITY_ORDER))


def test_window_coverage_offers_a_run_again_when_the_window_reaches_past_the_fetched_history():
    from streamlit.testing.v1 import AppTest
    data = collected()

    def page():
        import streamlit as st

        from core.window import preset_window
        from views.results_toolbar import render_window_coverage
        render_window_coverage(st.session_state["data"], preset_window(st.session_state["window"]),
                               {"opt_history_mode": "days", "opt_history_days": 30}, "2026-11-17T10:00:00Z")

    at = AppTest.from_function(page)
    at.session_state["data"] = data
    at.session_state["window"] = "Last 90 days"
    at.run(timeout=30)
    assert at.button(key="toolbar_rerun_window") and "last 30 days only" in at.caption[0].value
    at.session_state["window"] = "Last 7 days"
    at.run(timeout=30)
    assert not at.button

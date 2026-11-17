import pandas as pd

from core import run_views


def snap(run_id, targets, artifacts=None, alerts=(), parent=None, risk=None):
    """A saved run as load_all_runs returns it; ids are UTC timestamps, so they sort in time order."""
    rows = [{"Domain": d, "Threat Type": t, "Severity": s} for d, t, s in alerts]
    by_severity = {}
    for _, _, severity in alerts:
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {"id": run_id, "created": f"{run_id[:4]}-{run_id[4:6]}-{run_id[6:8]}T{run_id[9:11]}:00:00Z",
            "targets": list(targets), "artifacts": artifacts or {}, "alerts": rows,
            "summary": {"alerts": len(rows), "by_severity": by_severity, "max_unified_risk": risk},
            **({"parent": parent} if parent else {})}


def runs():
    shared_ip = {"IP": ["45.13.20.7"], "Name Server": ["ns1.cloudflare.com"], "JA4X": ["aaa"]}
    return [
        ("A", snap("20261101T100000000000Z", ["a.com"], {"a.com": {"IP": ["45.13.20.7", "104.16.1.1"]}},
                   alerts=[("a.com", "Self-Signed", "High")], risk=40)),
        ("A", snap("20261102T100000000000Z", ["a.com"], {"a.com": {"IP": ["45.13.20.7"]}},
                   alerts=[("a.com", "Fast Flux", "Critical"), ("a.com", "DGA", "Medium")], risk=55)),
        ("B", snap("20261103T100000000000Z", ["b.com"], {"b.com": shared_ip},
                   parent={"id": "20261102T100000000000Z", "via": "IP 45.13.20.7"}, risk=20)),
        ("C", snap("20261104T100000000000Z", ["a.com", "c.com"], {"a.com": {"IP": ["45.13.20.7"]}})),
    ]


def test_overview_has_the_change_trend_and_shared_lists():
    rows = run_views.recent_overview(runs(), limit=3)
    assert [row["key"] for row in rows] == ["C", "B", "A"]   # newest first
    a = rows[2]
    assert a["change"] == {"new": 2, "resolved": 1, "previous": "2026-11-01T10:00:00Z"}
    assert a["top_severity"] == "Critical" and a["risk_trend"] == [40.0, 55.0] and a["runs_of_list"] == 2
    # A and B share 45.13.20.7 on different domains; C also analyzed a.com, so a.com's IP links nothing to A
    assert set(a["shared"]) == {"B"} and a["shared"]["B"] == [("IP", "45.13.20.7")]
    assert set(rows[0]["shared"]) == {"B"}   # C's IP is on a.com, which B doesn't have
    assert rows[1]["change"] is None and rows[1]["top_severity"] == "None"


def test_cdn_ips_large_dns_providers_and_common_values_link_nothing():
    common = [(f"K{i}", snap(f"2026110{i}T100000000000Z", [f"d{i}.com"],
                             {f"d{i}.com": {"IP": ["185.220.101.5", "104.16.1.1"], "Name Server": ["ns1.cloudflare.com"]}}))
              for i in range(run_views.COMMON_LISTS + 1)]
    assert run_views.shared_index(common) == {}
    two = common[:2]
    assert set(run_views.shared_index(two)) == {("IP", "185.220.101.5")}   # the CDN IP and Cloudflare NS are left out
    assert not run_views._significant("IP", "108.138.26.56")             # Amazon CloudFront edge
    assert not run_views._significant("IP", "2.16.10.75")                # Akamai edge
    assert run_views._significant("IP", "139.162.1.1")                   # Linode (Akamai Cloud) hosts customers
    assert not run_views._significant("Name Server", "162.159.10.150")   # Cloudflare DNS recorded as an IP
    assert run_views._significant("Name Server", "ns1.example-host.net")
    assert not run_views._significant("IP", "127.0.0.1") and not run_views._significant("IP", "10.1.2.3")


def test_hunting_graph_draws_leads_and_shared_links_between_newest_runs():
    nodes, edges = run_views.hunting_graph(runs())
    assert [node["key"] for node in nodes] == ["A", "A", "B", "C"]
    lead = [edge for edge in edges if edge["kind"] == "lead"]
    assert lead == [{"source": "20261102T100000000000Z", "target": "20261103T100000000000Z", "kind": "lead",
                     "via": "IP 45.13.20.7"}]
    shared = [edge for edge in edges if edge["kind"] == "shared"]
    pairs = {frozenset((edge["source"], edge["target"])) for edge in shared}
    assert frozenset(("20261102T100000000000Z", "20261103T100000000000Z")) in pairs   # newest run of A and of B
    assert all("20261101T100000000000Z" not in pair for pair in pairs)
    nodes, edges = run_views.hunting_graph(runs(), max_runs=2)
    assert {node["key"] for node in nodes} == {"B", "C"} and not [e for e in edges if e["kind"] == "lead"]


def test_activity_counts_runs_hunt_runs_and_new_detections_per_day():
    frame = run_views.activity_frame(runs(), days=7, today=pd.Timestamp("2026-11-05"))
    assert len(frame) == 7 and frame["Date"].iloc[-1] == pd.Timestamp("2026-11-05")
    day = frame.set_index("Date")
    assert day.loc["2026-11-03", "Runs"] == 1 and day.loc["2026-11-03", "Hunt runs"] == 1   # B came from A's lead
    assert day.loc["2026-11-01", "High"] == 1 and day.loc["2026-11-01", "New High"] == 1
    assert day.loc["2026-11-02", "Critical"] == 1 and day.loc["2026-11-02", "New Critical"] == 1
    assert frame["Runs"].sum() == 4 and day.loc["2026-11-01", "Week"] == 44 and day.loc["2026-11-02", "Week"] == 45


def test_activity_figure_labels_days_with_week_numbers():
    from views.run_visuals import activity_figure
    frame = run_views.activity_frame(runs(), days=14, today=pd.Timestamp("2026-11-05"))
    fig = activity_figure(frame)
    ticks = fig.layout.xaxis2.ticktext
    assert len(ticks) == 14 and ticks[-1] == "Thu 05 Nov<br>W45"
    assert {trace.name for trace in fig.data} >= {"Hunt run (from a lead)", "Critical", "High"}


def test_shared_text_counts_kinds():
    assert run_views.shared_text([("IP", "1.1.1.1"), ("IP", "2.2.2.2"), ("JA4X", "x")], limit=2) == \
        "2 IPs, 1 JA4X: 1.1.1.1, 2.2.2.2, +1 more"


def test_hunting_graph_page_renders_and_shows_a_runs_links(monkeypatch):
    from streamlit.testing.v1 import AppTest

    import core.persistence as persistence
    from views import hunting_graph_view  # imported before the patch, so it keeps the real one afterwards
    monkeypatch.setattr(persistence, "load_all_runs", runs)
    monkeypatch.setattr(hunting_graph_view, "load_all_runs", runs)
    monkeypatch.setattr(hunting_graph_view, "list_offline_datasets", lambda: [])

    def page():
        from views import hunting_graph_view
        hunting_graph_view.render_hunting_graph("UTC")

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception and len(at.get("plotly_chart")) == 1
    links = at.dataframe[0].value
    assert set(links["Link"]) >= {"Shares artifacts"}   # the newest run (C) shares with B
    at.session_state["hunt_graph_selected"] = "20261103T100000000000Z"
    at.run(timeout=30)
    assert set(at.dataframe[0].value["Link"]) >= {"Led to this run", "Shares artifacts"}


def test_sparkline_scales_to_the_range():
    from views.run_visuals import sparkline
    assert sparkline([10, None, 20, 15]) == "▁█▅" and sparkline([5, 5]) == "▄▄" and sparkline([7]) == ""


def test_shared_indicators_and_top_shared_follow_the_shared_links():
    rows = run_views.recent_overview(runs(), limit=4)
    a = next(row for row in rows if row["key"] == "A")
    assert run_views.shared_indicators(a, {"B": "b.com"}) == [
        {"Kind": "IP", "Indicator": "45.13.20.7", "Lists": 1, "Also in": "b.com"}]
    top = run_views.top_shared(runs(), {"A": "a.com", "B": "b.com", "C": "a.com, c.com"})
    assert top == [{"Kind": "IP", "Indicator": "45.13.20.7", "Lists": 3, "Target lists": "a.com; a.com, c.com; b.com"}]


def test_run_indicators_and_filters():
    snapshot = runs()[2][1]
    assert run_views.run_indicators(snapshot) == [("IP", "45.13.20.7"), ("JA4X", "aaa"),
                                                  ("Name Server", "ns1.cloudflare.com"), ("Target", "b.com")]
    rows = run_views.recent_overview(runs(), limit=4)
    assert [r["key"] for r in run_views.filter_overview(rows, text="C.COM")] == ["C"]
    assert [r["key"] for r in run_views.filter_overview(rows, only_alerts=True)] == ["A", "A"]
    assert [r["id"] for r in run_views.filter_overview(rows, only_new=True)] == ["20261102T100000000000Z",
                                                                                "20261101T100000000000Z"]


def test_recent_page_links_a_shared_indicator_to_its_sightings(monkeypatch):
    from streamlit.testing.v1 import AppTest

    import core.persistence as persistence
    import core.seen as seen
    from views import recent_view, seen_view  # imported before the patch, so they keep the real one afterwards
    monkeypatch.setattr(persistence, "load_all_runs", runs)
    monkeypatch.setattr(seen, "load_all_runs", runs)
    for module in (recent_view, seen_view):
        monkeypatch.setattr(module, "load_all_runs", runs)
    monkeypatch.setattr(recent_view, "list_offline_datasets", lambda: [])

    def page():
        from views import recent_view
        recent_view.render_recent_page("UTC")

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception
    assert at.session_state["recent_selected"] == "20261104T100000000000Z"   # the newest run, C
    find = next(b for b in at.button if b.key == "recent_shared_find")
    assert "45.13.20.7" in find.label
    find.click().run(timeout=30)
    assert not at.exception and at.session_state["seen_query"] == "45.13.20.7"
    assert at.session_state["recent_tab"] == "Indicator Sightings"
    pick = next(b for b in at.button if b.key == "seen_pick")
    pick.click().run(timeout=30)
    assert at.session_state["recent_tab"] == "Recent runs"
    assert at.session_state["recent_selected"] == "20261104T100000000000Z"   # the newest sighting: run C


def test_runs_table_shows_one_row_per_list_until_show_all_runs(monkeypatch):
    from streamlit.testing.v1 import AppTest

    import core.persistence as persistence
    from views import recent_view
    monkeypatch.setattr(persistence, "load_all_runs", runs)
    monkeypatch.setattr(recent_view, "load_all_runs", runs)
    monkeypatch.setattr(recent_view, "list_offline_datasets", lambda: [])

    def page():
        import streamlit as st

        from views import recent_view
        st.session_state.setdefault("recent_view", "Table")
        recent_view.render_recent_page("UTC")

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception
    assert len(at.dataframe[0].value) == 3 and "Newest run" in at.dataframe[0].value.columns   # lists A, B, C
    at.toggle(key="recent_all_runs").set_value(True).run(timeout=30)
    assert len(at.dataframe[0].value) == 4 and "Run" in at.dataframe[0].value.columns   # every run
    key = next(row["key"] for row in run_views.recent_overview(runs(), 4) if row["runs_of_list"] == 2)
    at.session_state["recent_list"] = key   # a card's Show all runs
    at.run(timeout=30)
    assert len(at.dataframe[0].value) == 2
    at.toggle(key="recent_all_runs").set_value(False).run(timeout=30)
    assert "recent_list" not in at.session_state and len(at.dataframe[0].value) == 3


def test_hunt_map_page_shows_the_hunts_and_the_timeline_of_all_investigations(monkeypatch):
    from streamlit.testing.v1 import AppTest

    import core.persistence as persistence
    from views import hunt_map_view, hunting_graph_view  # imported before the patch: they keep the real ones after
    monkeypatch.setattr(persistence, "load_all_runs", lambda: runs()[:1])
    monkeypatch.setattr(hunt_map_view, "load_all_runs", lambda: runs()[:1])
    monkeypatch.setattr(hunt_map_view, "list_offline_datasets", lambda: [])
    monkeypatch.setattr(hunting_graph_view, "load_all_runs", runs)
    monkeypatch.setattr(hunting_graph_view, "list_offline_datasets", lambda: [])

    def page():
        from views import hunt_map_view
        hunt_map_view.render_hunt_map("UTC")

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception and "No hunt yet" in at.info[0].value
    monkeypatch.setattr(hunt_map_view, "load_all_runs", runs)
    at.run(timeout=30)
    assert not at.exception and "a.com · 2 run(s)" in at.selectbox(key="hunt_map_hunt").format_func(
        at.selectbox(key="hunt_map_hunt").value)
    assert len(at.get("graphviz_chart")) == 1 and "Load a run of this hunt" in at.info[-1].value
    assert "Hunt status: Done" in at.info[0].value   # the runs kept no suggested steps: nothing open
    assert any("Hunt result" in e.label for e in at.expander)
    at.session_state["hunt_map_tab"] = "All investigations"
    at.run(timeout=30)
    assert not at.exception and len(at.get("plotly_chart")) == 1



def test_cards_show_each_target_list_once_with_all_its_runs():
    rows = [{"id": "a3", "key": "A"}, {"id": "b2", "key": "B"}, {"id": "a2", "key": "A"}, {"id": "b1", "key": "B"},
            {"id": "a1", "key": "A"}, {"id": "c1", "key": "C"}]
    cards = run_views.group_by_list(rows)
    assert [(c["id"], [r["id"] for r in c["repeats"]]) for c in cards] == [
        ("a3", ["a3", "a2", "a1"]), ("b2", ["b2", "b1"]), ("c1", ["c1"])]

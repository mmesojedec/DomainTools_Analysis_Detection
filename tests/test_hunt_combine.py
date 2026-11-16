import pandas as pd

import core.persistence as persistence
from core import hunt_combine
from core.hunt_tree import hunt_members


def snap(run_id, targets, artifacts=None, parent=None, alerts=()):
    return {"id": run_id, "created": run_id, "targets": list(targets), "artifacts": artifacts or {},
            "alerts": [{"Domain": d, "Threat Type": t, "Severity": s} for d, t, s in alerts],
            **({"parent": parent} if parent else {})}


def runs():
    cert = {"Certificate": ["abc123"]}
    return [
        ("K1", snap("2026-11-15T01", ["a.cc", "b.cc"], {"a.cc": cert, "b.cc": {"IP": ["45.13.20.7"]}})),
        ("K2", snap("2026-11-15T02", ["c.cc"], {"c.cc": {"IP": ["45.13.20.7"]}}, parent={"id": "2026-11-15T01"})),
        ("K3", snap("2026-11-16T01", ["d.cc", "c.cc"], {"d.cc": cert})),            # shares the cert and c.cc
        ("K4", snap("2026-11-16T02", ["z.cc"], {"z.cc": {"IP": ["8.8.4.4"]}})),     # unrelated
    ]


def test_related_hunts_and_cross_links():
    data = runs()
    assert hunt_combine.hunt_roots(data) == ["2026-11-16T02", "2026-11-16T01", "2026-11-15T01"]
    related = hunt_combine.related_hunts(data, "2026-11-15T01")
    assert [root for root, _ in related] == ["2026-11-16T01"]
    assert related[0][1] == {"Certificate": 1, "Domain": 1}
    hunts = {root: hunt_members(data, root) for root in ("2026-11-15T01", "2026-11-16T01")}
    links = hunt_combine.cross_links(hunts)
    assert {(link["source"], link["target"]) for link in links} == {("2026-11-15T01", "2026-11-16T01"),
                                                                    ("2026-11-15T02", "2026-11-16T01")}
    assert hunt_combine.best_anchor(hunts["2026-11-15T01"], data[2][1]) in {"2026-11-15T01", "2026-11-15T02"}
    result = hunt_combine.combined_result(hunts)
    assert {"a.cc", "b.cc", "d.cc", "c.cc"} <= {row["Domain"] for row in result["cluster"]}


def test_combined_dot_frames_each_hunt_and_links_them():
    from views.hunt_combine_view import combined_dot
    data = runs()
    hunts = {root: hunt_members(data, root) for root in ("2026-11-15T01", "2026-11-16T01")}
    dot = combined_dot(hunts, {root: root for root in hunts}, links=hunt_combine.cross_links(hunts))
    assert dot.count("subgraph") == 2 and "style=dashed" in dot and "1 Cert" in dot


def test_join_and_detach_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path / "runs")
    first = persistence.save_snapshot("aaaa1111aaaa1111", ["a.cc"], {}, pd.DataFrame())
    other = persistence.save_snapshot("bbbb2222bbbb2222", ["d.cc"], {}, pd.DataFrame(),
                                      parent={"id": None, "via": "CertsQL: sha1 equals x"})
    persistence.join_run("bbbb2222bbbb2222", other["id"], first["id"], "Joined: shares 1 Certificate")
    joined = persistence.load_run("bbbb2222bbbb2222", other["id"])
    assert joined["parent"] == {"id": first["id"], "via": "Joined: shares 1 Certificate"} and "joined" in joined
    persistence.detach_run("bbbb2222bbbb2222", other["id"])
    back = persistence.load_run("bbbb2222bbbb2222", other["id"])
    assert back["parent"] == {"id": None, "via": "CertsQL: sha1 equals x"} and "joined" not in back


def test_same_targets_again_continues_the_hunt(monkeypatch, tmp_path):
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path / "runs")
    first = persistence.save_snapshot("aaaa1111aaaa1111", ["a.cc"], {}, pd.DataFrame(), continue_list=True)
    assert "parent" not in first
    again = persistence.save_snapshot("aaaa1111aaaa1111", ["a.cc"], {}, pd.DataFrame(),
                                      parent={"id": None, "via": "Run again"}, continue_list=True)
    assert again["parent"] == {"id": first["id"], "via": "Run again"}
    plain = persistence.save_snapshot("aaaa1111aaaa1111", ["a.cc"], {}, pd.DataFrame(), continue_list=True)
    assert plain["parent"] == {"id": again["id"], "via": persistence.SAME_TARGETS}
    step = persistence.save_snapshot("aaaa1111aaaa1111", ["a.cc"], {}, pd.DataFrame(),
                                     parent={"id": "elsewhere", "via": "Suggested hunt"}, continue_list=True)
    assert step["parent"]["id"] == "elsewhere"


def test_analyze_selection_links_the_loaded_run(monkeypatch):
    import streamlit as st

    from views import analyze_selection
    monkeypatch.setattr(st, "session_state", {"current_run_id": "r1"})
    assert analyze_selection.hunt_parent("certsql") == "r1"
    st.session_state["certsql_link_hunt"] = False
    assert analyze_selection.hunt_parent("certsql") is None

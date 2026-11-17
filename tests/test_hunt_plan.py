from types import SimpleNamespace

import pandas as pd

from core import hunt_plan

SHA1 = "ab" * 20
JA4X = "2166164053c1_2166164053c1_30d204a01551"


def pivots():
    def row(signal, kind, value, count, run_domains=1, analyze=""):
        return {"Signal": signal, "Type": kind, "Value": value, "Iris Domains": count, "Run Domains": run_domains,
                "Shared With": "a.com", "Iris Search": f"x={value}", "Analyze As": analyze}
    return pd.DataFrame([
        row("Strong", "IP address", "45.13.20.7", 6, analyze="45.13.20.7"),
        row("Strong", "SSL certificate (SHA-1)", SHA1, 3, 2, f"sha1:{SHA1}"),
        row("Weak", "IP address", "104.16.1.1", 90000, analyze="104.16.1.1"),           # Cloudflare edge
        row("Strong", "Name server", "ns1.cloudflare.com", 300),                         # large DNS provider
        row("Useful", "Registrant org", "Privacy Ltd", 4000),                            # too widely shared
        row("Strong", "Redirect domain", "a.com", 12, analyze="a.com"),                  # already analyzed
        row("This domain only", "GA4", "G-XYZ", 1),                                      # nothing to follow
        row("Strong", "GA4", "G-ABC", 40),
        row("Count unknown", "Contact phone", "tel:+1.555", None),                      # no count, no alert
        row("Strong", "Mail server IP", "45.13.20.9", 2, 2, "45.13.20.9"),               # both already in the run
    ])


def alerts():
    return pd.DataFrame([
        {"Domain": "a.com", "Severity": "High", "Threat Type": "Known C2 Certificate Fingerprint (JA4X)",
         "Triggering IOCs": f"JA4X: {JA4X}\nIP: 45.13.20.7", "Evidence": []},
        {"Domain": "a.com", "Severity": "Medium", "Threat Type": "Self-Signed Certificate", "Triggering IOCs": "",
         "Evidence": [{"Field": "Certificate", "Value": "CN=a.com", "Artifact": SHA1}]},
    ])


def test_leads_are_scored_from_rarity_alerts_kind_and_sightings_and_set_aside_with_a_reason():
    index = {"g-abc": {"other": {"domains": {"x.com": 3}, "label": "x.com"}},
             "45.13.20.7": {"same": {"domains": {"a.com": 5}, "label": "a.com"}}}   # an earlier run of a.com itself
    leads = hunt_plan.score_leads(pivots(), alerts(), analyzed=["a.com"], index=index)
    assert "G-XYZ" not in [lead["Value"] for lead in leads]                    # unique to this domain: no lead
    open_ = [lead for lead in leads if not lead["Stop"]]
    assert [lead["Value"] for lead in open_] == ["45.13.20.7", SHA1, "G-ABC"]
    ip = open_[0]
    assert any("High" in reason for reason in ip["Reasons"]) and ip["Alerts"] == 1 and ip["Seen"] == []
    assert any("seen in 1 other investigation(s) with 3 alert(s)" in r for r in open_[2]["Reasons"])
    stops = {lead["Value"]: lead["Stop"] for lead in leads if lead["Stop"]}
    assert stops["104.16.1.1"].startswith("Cloudflare edge")
    assert stops["ns1.cloudflare.com"].startswith("Large DNS provider")
    assert stops["Privacy Ltd"].startswith("Shared by 4,000 domains")
    assert stops["a.com"] == "Already analyzed in this hunt"
    assert stops["tel:+1.555"].startswith("Iris gave no count")
    assert stops["45.13.20.9"] == "Every domain that has it is already in this run"
    assert all(lead["Stop"] for lead in leads[len(open_):])   # set-aside leads come last


def test_lookahead_uses_the_iris_count_saved_runs_and_an_iris_search_already_made():
    lead = {"Iris Domains": 6, "Run Domains": 1, "Iris Search": "ip=45.13.20.7",
            "Seen": [{"label": "b.com", "domains": {"b.com": 2, "c.com": 0}, "alerts": 2}]}
    result = SimpleNamespace(ok=True, data=[{"domain": "evil.com", "domain_risk": {"risk_score": 99}},
                                            {"domain": "b.com", "domain_risk": {"risk_score": 40}}])
    index = {"b.com": {"k": {"domains": {"b.com": 2}, "label": "b.com"}}}
    lines = hunt_plan.lookahead(lead, {"ip=45.13.20.7": result}, index)
    assert lines[0] == "about 5 domain(s) not in this run (Iris count)"
    assert "seen before in *b.com* with b.com, c.com (2 alert(s) there)" == lines[1]
    assert lines[2] == "Iris search already made: 2 domain(s), riskiest evil.com (99), b.com (40); 1 flagged in " \
                       "earlier investigations"


def test_start_order_confirms_the_operators_fingerprint_first_then_its_ip_and_shared_domains():
    leads = hunt_plan.score_leads(pivots(), alerts(), analyzed=["a.com"])
    steps = hunt_plan.start_order(alerts(), leads)
    assert [(s["kind"], s["value"]) for s in steps] == [("JA4X", JA4X), ("IP", "45.13.20.7"), ("Lead", "45.13.20.7"),
                                                       ("Certificate", SHA1), ("Lead", SHA1)]
    assert [s["step"] for s in steps] == [1, 2, 3, 4, 5] and steps[0]["page"] == "certs"
    assert steps[2]["why"] == "then the 6 domains in Iris that share it"
    assert hunt_plan.start_order(pd.DataFrame(), leads) == []


def test_sightings_index_and_followed_branches():
    runs = [("k1", {"id": "1", "targets": ["a.com"], "artifacts": {"a.com": {"IP": ["45.13.20.7"]}},
                    "alerts": [{"Domain": "a.com"}]}),
            ("k2", {"id": "2", "targets": ["b.com"], "artifacts": {"b.com": {"IP": ["45.13.20.7"]}}, "alerts": []})]
    index = hunt_plan.sightings_index(runs, exclude_keys={"k2"})
    assert index["45.13.20.7"] == {"k1": {"domains": {"a.com": 1}, "label": "a.com"}}
    child = {"targets": ["45.13.20.7"], "parent": {"id": "2", "via": "IP address 45.13.20.7"}}
    assert hunt_plan.followed({"Value": "45.13.20.7", "Analyze As": "45.13.20.7"}, [child]) is child
    assert hunt_plan.followed({"Value": "9.9.9.9", "Analyze As": ""}, [child]) is None


def test_plan_items_merge_start_steps_and_branches_into_one_ordered_list_to_run():
    leads = hunt_plan.score_leads(pivots(), alerts(), analyzed=["a.com"])
    steps = hunt_plan.start_order(alerts(), leads)
    child = {"id": "c1", "targets": ["45.13.20.7"], "alerts": [{}], "parent": {"id": "p", "via": "IP 45.13.20.7"}}
    items = hunt_plan.plan_items(steps, leads, [child])
    assert [(i["step"], i["source"], i["value"], i["action"]) for i in items] == [
        (1, "Start", JA4X, "CertsQL"), (2, "Start", "45.13.20.7", "Analyze"),
        (3, "Start", SHA1, "Analyze"), (4, "Branch", "G-ABC", "Iris")]
    assert items[1]["done"] and items[1]["score"] is not None and items[2]["target"] == f"sha1:{SHA1}"
    assert [i["step"] for i in hunt_plan.runnable(items)] == [3, 4]          # followed and by-hand steps left out
    targets, searches, over = hunt_plan.run_parts(items, max_targets=1)
    assert targets == ["45.13.20.7"] and searches == ["x=G-ABC"] and over == [f"sha1:{SHA1}"]
    assert hunt_plan.via_text(items[1:3]) == "Suggested hunt: IP 45.13.20.7, Certificate abababababababababababa…"


def test_hunt_map_marks_followed_steps_done_and_keeps_open_ones_with_their_facts():
    from views.hunt_map_view import hunt_map_dot
    leads = hunt_plan.score_leads(pivots(), alerts(), analyzed=["a.com"])
    plan = hunt_plan.saved_plan(hunt_plan.plan_items(hunt_plan.start_order(alerts(), leads), leads))
    assert plan[1]["alerts"] == 1 and plan[1]["worst"] == "High" and plan[3]["iris"] == 40
    assert plan[0]["types"] == ["Known C2 Certificate Fingerprint (JA4X)"]
    root = {"id": "r1", "targets": ["a.com"], "created": "2026-11-02T09:10:00Z", "plan": plan,
            "summary": {"by_severity": {"High": 1, "Medium": 1}},
            "alerts": [{"Domain": "a.com", "Threat Type": "Known C2 Certificate Fingerprint (JA4X)", "Severity": "High"}],
            "artifacts": {"a.com": {"IP": ["45.13.20.7"]}}}
    child = {"id": "r2", "targets": ["45.13.20.7", "b.com"], "created": "2026-11-02T09:25:00Z", "alerts": [],
             "parent": {"id": "r1", "via": "IP address 45.13.20.7"},
             "artifacts": {"b.com": {"IP": ["45.13.20.7"]}}}
    dot = hunt_map_dot([("k1", root, 0), ("k2", child, 1)], loaded_id="r2", live_items=[])
    assert '"run::r1" -> "done::r1::r2::0"' in dot and '"done::r1::r2::0" -> "run::r2"' in dot   # ✓ step 2, on
    assert "✓ #2 IP" in dot and "2 alerts: " in dot and "1 High" in dot and "starting point" in dot
    assert '"open::r1::g-abc"' in dot and "Iris 40" in dot and "start here" in dot      # still open, with facts
    assert "+2 new domain(s) · +0 new alert(s)" in dot and "linked to start: 1 IP" in dot and "● loaded" in dot
    assert dot.count('"run::r1" -> "open::r1::') == 3 and "more open" not in dot         # JA4X, certificate, GA4
    lit = hunt_map_dot([("k1", root, 0), ("k2", child, 1)], highlight=("type", "Known C2 Certificate Fingerprint (JA4X)"))
    assert '"run::r1" [label=' in lit and 'color="#ff5252", penwidth=2.5' in lit and 'fontcolor="#777777"' in lit
    orphan = {**child, "id": "r3", "parent": {"id": "r1", "via": "Certificate abc"}, "targets": ["z.com"],
              "artifacts": {"z.com": {"IP": ["9.9.9.9"]}}}
    other = hunt_map_dot([("k1", root, 0), ("k3", orphan, 1)])
    assert '"run::r1" -> "run::r3" [color="#43a047", label="✓ Certificate abc"]' in other
    assert "no link to start: drifted" in other


def test_a_step_followed_anywhere_in_the_hunt_is_never_open_again_and_repeats_collapse():
    from views.hunt_map_view import hunt_map_dot, run_items
    cert = "ab" * 32
    step = {"step": 1, "source": "Start", "kind": "Certificate", "value": cert, "action": "Analyze",
            "target": f"sha256:{cert}", "search": "", "score": None, "why": "", "iris": None, "alerts": 1,
            "worst": "High", "domains": 1, "types": []}
    r1 = {"id": "r1", "created": "1", "targets": ["a.com"], "plan": [step]}
    r2 = {"id": "r2", "created": "2", "targets": ["a.com", "b.com"], "seeds": [f"sha256:{cert}"], "plan": [step],
          "parent": {"id": "r1", "via": "Suggested hunt: Certificate ab"}}
    assert run_items([("k", r1, 0), ("k", r2, 1)])["r2"] == []          # followed by r1's child: not open in r2
    r3 = {**r2, "id": "r3", "created": "3", "parent": {"id": "r2", "via": "Suggested hunt: Certificate ab"}}
    dot = hunt_map_dot([("k", r1, 0), ("k", r2, 1), ("k", r3, 2)])
    assert "✓ 1 step(s) repeated from before" in dot                    # r2 → r3 followed it again
    steps = hunt_plan.start_order(alerts(), exclude={"45.13.20.7"})
    assert "45.13.20.7" not in [s["value"] for s in steps]


def test_hunt_status_yield_links_and_result():
    from core import hunt_result as hr
    root = {"id": "r1", "created": "1", "targets": ["a.com", "b.com"],
            "alerts": [{"Domain": "a.com", "Threat Type": "C2", "Severity": "High"}],
            "artifacts": {"a.com": {"IP": ["45.13.20.7"], "Email": ["abuse@namesilo.com"]},
                          "b.com": {"IP": ["45.13.20.7"], "Certificate": ["cc" * 20]}}}
    linked = {"id": "r2", "created": "2", "targets": ["c.com"], "parent": {"id": "r1"},
              "alerts": [{"Domain": "c.com", "Threat Type": "C2", "Severity": "High"},
                         {"Domain": "c.com", "Threat Type": "Phish", "Severity": "Medium"}],
              "artifacts": {"c.com": {"Certificate": ["CC" * 20], "Email": ["abuse@namesilo.com"]}}}
    drifted = {"id": "r3", "created": "3", "targets": ["z.com"], "parent": {"id": "r1"}, "alerts": [],
               "artifacts": {"z.com": {"IP": ["9.9.9.9"]}}}
    runs = [root, linked, drifted]
    assert hr.run_yield(runs)["r2"] == {"new_domains": 1, "new_alerts": 2, "new_high": 1, "new_types": 1}
    links = hr.start_links(runs, root)
    assert links["r2"] == {"Certificate": 1} and not links["r3"]          # a role mailbox links nothing
    assert hr.hunt_status(runs, [0, 1, 1], ["x"]) == ("converging", "the newest run added 1 new domain(s) and no new "
                                                      "kind of alert: following more steps is unlikely to find much")
    assert hr.hunt_status(runs, [0, 1, 3], ["x"])[0] == "done" and hr.hunt_status(runs, [0], [], closed={
        "verdict": "Benign"}) == ("closed", "closed as Benign")
    result = hr.hunt_result(runs, root)
    assert [row["Domain"] for row in result["cluster"]] == ["a.com", "b.com", "c.com"] and result["drifted"] == ["r3"]
    assert {(row["Kind"], row["Domains"]) for row in result["core"]} == {("IP", 2), ("Certificate", 2)}
    assert result["alerts"][0] == {"Threat Type": "C2", "Domains": 2, "Worst": "High"}
    page = hr.hunt_report_html("Hunt: a.com", result, [], ("converging", "x"), "Malicious cluster", "note <b>")
    assert "Malicious cluster" in page and "note &lt;b&gt;" in page and "c.com" in page


def test_indicator_kinds_and_certificate_records():
    from views.indicator_view import _cert_rows, _pdns_rows, kind_of
    assert kind_of("Certificate", SHA1) == "Certificate" and kind_of("SSL subject", "CN=x") == "Value"
    assert kind_of("Lead", JA4X) == "JA4X" and kind_of("Mail server IP", "1.2.3.4") == "IP"
    assert kind_of("Name server", "ns1.x.net") == "Host"
    ds = SimpleNamespace(
        ssl=pd.DataFrame([{"Domain": "a.com", "Hash": "f" * 64, "SHA1": SHA1, "JA4X": JA4X, "Common Name": "a.com"},
                          {"Domain": "b.com", "Hash": "e" * 64, "SHA1": "c" * 40, "JA4X": "", "Common Name": "b.com"}]),
        pdns=pd.DataFrame([{"Domain": "a.com", "RRName": "www.a.com", "Field": "A", "Value": "45.13.20.7"},
                           {"Domain": "a.com", "RRName": "a.com", "Field": "NS", "Value": "ns1.x.net."}]))
    assert list(_cert_rows(ds, SHA1.upper())["Domain"]) == ["a.com"] and list(_cert_rows(ds, JA4X)["Domain"]) == ["a.com"]
    assert len(_pdns_rows(ds, "45.13.20.7")) == 1 and len(_pdns_rows(ds, "ns1.x.net", host=True)) == 1


def test_certificates_page_narrows_to_the_focused_certificate():
    from streamlit.testing.v1 import AppTest

    def page():
        import pandas as pd
        import streamlit as st

        from views.ssl_view import _focused
        ds = type("DS", (), {})()
        ds.ssl = pd.DataFrame([{"Domain": "a.com", "Hash": "f" * 64, "SHA1": "ab" * 20, "JA4X": ""},
                               {"Domain": "b.com", "Hash": "e" * 64, "SHA1": "c" * 40, "JA4X": ""}])
        ds.derived = {"x": 1}
        st.session_state["cert_focus"] = "ab" * 20
        focused = _focused(ds)
        st.write(f"rows={len(focused.ssl)} derived={len(focused.derived)} full={len(ds.ssl)}")

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception and any("rows=1 derived=0 full=2" in m.value for m in at.markdown)
    assert "Showing only" in at.info[0].value


def test_guided_hunt_banner_skips_and_stops_and_picked_steps_offer_one_run():
    from streamlit.testing.v1 import AppTest

    def page():
        import streamlit as st

        from views.hunt_run_view import GUIDE_KEY, render_guide, render_picked
        item = {"id": "1.2.3.4", "step": 1, "source": "Start", "kind": "IP", "value": "1.2.3.4", "action": "Analyze",
                "target": "1.2.3.4", "search": "ip=1.2.3.4", "score": 40, "why": "1 alert", "done": False}
        other = {**item, "id": "g-1", "step": 2, "source": "Branch", "kind": "GA4", "value": "G-1", "action": "Iris",
                 "target": "", "search": "ga4=G-1"}
        if "started" not in st.session_state:
            st.session_state["started"] = True
            st.session_state[GUIDE_KEY] = {"parent": "p", "label": "a.com", "items": [item, other], "position": 0}
        render_guide()
        render_picked(None, None, [item, other], "p", key="t")

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception and "step 1 of 2" in at.markdown[0].value
    assert any(b.label == "Run 2 picked steps" for b in at.button)
    at.button(key="hunt_guide_skip").click().run()
    assert "step 2 of 2" in at.markdown[0].value
    at.button(key="hunt_guide_stop").click().run()
    assert "hunt_guide" not in at.session_state


def test_analyze_on_a_picked_step_starts_the_run(monkeypatch):
    from streamlit.testing.v1 import AppTest

    def page():

        from views.hunt_run_view import render_picked
        item = {"id": "c", "step": 1, "source": "Start", "kind": "Certificate", "value": "ab" * 32,
                "action": "Analyze", "target": "sha256:" + "ab" * 32, "search": "", "score": 50, "why": "1 alert",
                "done": False}
        render_picked(None, None, [item], "parent-run", key="t")

    at = AppTest.from_function(page).run(timeout=30)
    at.button(key="t::analyze").click().run(timeout=30)
    assert not at.exception
    assert at.session_state["targets_input"] == "sha256:" + "ab" * 32
    assert at.session_state["hunt_request"]["direct"] is True and at.session_state["hunt_request"]["id"] == "parent-run"


def test_more_leads_leaves_out_what_the_suggested_hunt_lists(monkeypatch):
    import pandas as pd

    from views import hunt_next_view
    leads = pd.DataFrame({"Value": ["SHA256:AB", "1.2.3.4", "x@y.com"], "Type": ["Certificate", "IP", "Email"]})
    monkeypatch.setattr(hunt_next_view, "dataset_pivots", lambda ds: None)
    monkeypatch.setattr(hunt_next_view, "top_leads", lambda pivots: leads)
    assert hunt_next_view.more_leads(None, {"ab", "1.2.3.4"})["Value"].tolist() == ["x@y.com"]


def test_map_options_choose_the_details_layout_and_open_steps():
    from views.hunt_map_view import hunt_map_dot, lookup_lines, map_direction
    step = {"id": "s1", "step": 1, "source": "Branch", "kind": "IP", "value": "45.13.20.7", "target": "45.13.20.7",
            "search": "", "score": 50, "why": "", "done": False, "types": ["Fast-Flux DNS"]}
    root = {"id": "r1", "created": "2026-11-02T09:10:00Z", "targets": ["a.com"], "window": "Last 30 days",
            "options": {"use_case": "triage", "opt_dnsdb_limit": 5000, "opt_ct": True, "opt_ct_max": 10},
            "queries": {"Iris Investigate": 1, "DNSDB": 4},
            "alerts": [{"Domain": "a.com", "Threat Type": "Fast-Flux DNS", "Severity": "High"}], "plan": [step]}
    child = {"id": "r2", "created": "2026-11-02T09:25:00Z", "targets": ["b.com"], "alerts": [],
             "parent": {"id": "r1", "via": "Analyze now: c.com"}}
    assert lookup_lines(root) == ["Triage a suspicious domain · Last 30 days", "DNSDB 5,000 · CT 10",
                                  "5 API queries: DNSDB 4, Iris Investigate 1"]
    assert lookup_lines(child) == ["via Analyze now: c.com"]
    members = [("k", root, 0), ("k", child, 1)]
    compact = hunt_map_dot(members, details=("gain",), direction="TB", open_limit=0)
    assert "rankdir=TB" in compact and "Fast-Flux" not in compact and "DNSDB 5,000" not in compact
    assert "linked to start" not in compact and "no link to start" not in compact and "open::" not in compact
    full = hunt_map_dot(members, details=("gain", "types", "link", "lookup", "done"))
    assert "rankdir=LR" in full and "DNSDB 5,000 · CT 10" in full and "via Analyze now" in full
    assert '"run::r1" -> "open::r1::45.13.20.7"' in full
    assert map_direction("Auto", 3) == "LR" and map_direction("Auto", 4) == "TB" and map_direction("Top to bottom", 1) == "TB"


def test_reruns_of_the_same_targets_are_one_box_on_the_map():
    from core.hunt_tree import collapse_repeats
    from views.hunt_map_view import hunt_map_dot
    targets = ["7h1r0.cc", "spr7tsc.cc"]
    r1 = {"id": "r1", "created": "2026-11-17T08:00:00Z", "targets": targets, "alerts": []}
    r2 = {"id": "r2", "created": "2026-11-17T09:00:00Z", "targets": targets, "alerts": [],
          "parent": {"id": "r1", "via": "Run again"}}
    r3 = {"id": "r3", "created": "2026-11-17T10:00:00Z", "targets": list(reversed(targets)),
          "alerts": [{"Domain": "7h1r0.cc", "Threat Type": "Fast-Flux DNS", "Severity": "High"}],
          "parent": {"id": "r2", "via": "Same targets again"}}
    r4 = {"id": "r4", "created": "2026-11-17T11:00:00Z", "targets": ["other.cc"], "alerts": [],
          "parent": {"id": "r3", "via": "Analyze now: other.cc"}}
    members, repeats, alias = collapse_repeats([("k", r1, 0), ("k", r2, 1), ("k", r3, 2), ("k", r4, 3)])
    assert [(s["id"], d) for _, s, d in members] == [("r1", 0), ("r4", 1)]
    assert [s["id"] for s in repeats["r1"]] == ["r1", "r2", "r3"] and alias["r3"] == "r1"
    assert members[0][1]["alerts"] == r3["alerts"] and members[1][1]["parent"]["id"] == "r1"   # newest results
    dot = hunt_map_dot([("k", r1, 0), ("k", r2, 1), ("k", r3, 2), ("k", r4, 3)], loaded_id="r3")
    assert dot.count('[label=<<TABLE') == 2 and "3 runs of these targets" in dot and "● loaded" in dot
    assert '"run::r1" -> "run::r4"' in dot and "run::r2" not in dot

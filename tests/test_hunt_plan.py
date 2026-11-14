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


def test_suggested_and_hunts_graphs_draw_branches_followed_runs_and_start_steps():
    from views.hunt_tree_view import hunts_dot, suggested_dot
    leads = hunt_plan.score_leads(pivots(), alerts(), analyzed=["a.com"])
    steps = hunt_plan.start_order(alerts(), leads)
    child = {"id": "c1", "targets": ["45.13.20.7"], "alerts": [{}], "parent": {"id": "p", "via": "IP 45.13.20.7"}}
    dot = suggested_dot(["a.com"], leads, steps, [child])
    assert '"run" -> "lead::0" [label="followed"' in dot and '"lead::0" -> "child::c1"' in dot
    assert '"run" -> "lead::1" [style=dashed, label="suggested"' in dot
    assert '"run" -> "step::1" [style=dotted' in dot and "confirm JA4X" in dot
    assert "104.16.1.1" not in dot   # set-aside leads are not drawn
    rows = [{"Run": "r1", "Parent": None, "Depth": 0, "Targets": "a.com", "Created": "2026-11-02T09:10:00Z",
             "Alerts": 4, "Via": ""},
            {"Run": "r2", "Parent": "r1", "Depth": 1, "Targets": "45.13.20.7", "Created": "2026-11-02T09:25:00Z",
             "Alerts": 2, "Via": "IP 45.13.20.7"}]
    assert '"run::r1" -> "run::r2" [label="IP 45.13.20.7"' in hunts_dot(rows)


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

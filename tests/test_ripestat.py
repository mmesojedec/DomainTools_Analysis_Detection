"""RIPEstat: answers (trimmed copies of real ones) → BGP tables and registration; the stage, settings and queries."""
import pandas as pd
import pytest

from core import bgp
from core import ripestat as rs
from integrations import collector, ripestat, ripestat_stage
from integrations.http import FetchResult

HISTORY = {"query_endtime": "2026-11-27T00:00:00", "by_origin": [
    {"origin": 3333, "prefixes": [{"prefix": "193.0.0.0/21", "timelines": [
        {"starttime": "2000-10-26T00:00:00", "endtime": "2000-11-06T23:59:59", "full_peers_seeing": 28.0},
        {"starttime": "2026-11-03T00:00:00", "endtime": "2026-11-26T23:59:59", "full_peers_seeing": 321.56}]}]},
    {"origin": 64500, "prefixes": [{"prefix": "193.0.0.0/22", "timelines": [
        {"starttime": "2026-11-20T00:00:00", "endtime": "2026-11-26T23:59:59", "full_peers_seeing": 40.0}]}]},
    {"origin": 15962, "prefixes": [{"prefix": "192.0.0.0/3", "timelines": [   # 2020, gone since: not current
        {"starttime": "2020-08-06T00:00:00", "endtime": "2020-08-17T23:59:59", "full_peers_seeing": 96.0}]}]}]}
STATUS = {"first_seen": {"prefix": "193.0.0.0/21", "origin": "3333", "time": "2000-10-31T00:00:00"},
          "visibility": {"v4": {"ris_peers_seeing": 322, "total_ris_peers": 322}},
          "origins": [{"origin": 3333, "route_objects": ["RIPE"]}], "less_specifics": [],
          "more_specifics": [{"prefix": "193.0.4.0/24", "origin": "3333"}]}
VALID = {"status": "valid", "validating_roas": [{"origin": "3333", "prefix": "193.0.0.0/21", "max_length": 21}]}
INVALID = {"status": "invalid_asn", "validating_roas": [{"origin": "3333", "prefix": "193.0.0.0/21"}]}
GLASS = {"latest_time": "2026-11-27T13:01:33", "rrcs": [
    {"rrc": "RRC00", "peers": [
        {"as_path": "15692 2914 12859 3333", "prefix": "193.0.0.0/21", "last_updated": "2026-11-25T19:39:33",
         "latest_time": "2026-11-27T13:01:33"},
        {"as_path": "6939 12859 12859 3333", "prefix": "193.0.0.0/21", "last_updated": "2026-10-01T00:00:00",
         "latest_time": "2026-11-27T13:01:33"}]},
    {"rrc": "RRC01", "peers": [{"as_path": "1299 1103 3333", "prefix": "193.0.0.0/21",
                                "last_updated": "2026-11-01T00:00:00", "latest_time": "2026-11-27T13:01:33"}]}]}
OVERVIEW = {"holder": "RIPE-NCC-AS Reseaux IP Europeens Network Coordination Centre (RIPE NCC)", "announced": True}
NEIGHBOURS = {"neighbour_counts": {"left": 46, "right": 2, "unique": 910, "uncertain": 863}, "neighbours": []}
RIR = {"rirs": [{"rir": "RIPE NCC", "first_time": "2003-11-20T00:00:00", "last_time": "2026-11-25T00:00:00"}]}
COUNTRY = {"located_resources": [{"resource": "3333", "location": "NL"}]}


def _kv(*pairs):
    return [{"key": k, "value": v} for k, v in pairs]


WHOIS_RIPE = {"authorities": ["ripe"], "records": [_kv(
    ("inetnum", "193.0.0.0/21"), ("netname", "RIPE-NCC"), ("descr", "RIPE Network Coordination Centre"),
    ("org", "ORG-RIEN1-RIPE"), ("country", "NL"), ("admin-c", "MDIR-RIPE"), ("status", "ASSIGNED PA"),
    ("created", "2003-03-17T12:15:57Z"))]}
WHOIS_ARIN_AS = {"authorities": ["arin"], "records": [_kv(("ASNumber", "13335"), ("ASName", "CLOUDFLARENET"),
                                                          ("RegDate", "2010-07-14"))]}
WHOIS_ARIN = {"authorities": ["arin"], "records": [
    _kv(("NetRange", "8.0.0.0 - 8.255.255.255"), ("CIDR", "8.0.0.0/8"), ("NetName", "LVLT-ORG-8-8"),
        ("NetType", "Direct Allocation"), ("RegDate", "1992-12-01")),
    _kv(("NetRange", "8.8.8.0 - 8.8.8.255"), ("CIDR", "8.8.8.0/24"), ("NetName", "GOGL"),
        ("NetType", "Direct Allocation"), ("Organization", "Google LLC (GOGL)"), ("RegDate", "2023-12-28")),
    _kv(("OrgAbuseEmail", "network-abuse@google.com"), ("OrgAbusePhone", "+1-650-253-0000")),
    _kv(("OrgName", "Google LLC"), ("Address", "1600 Amphitheatre Parkway"), ("Country", "US"))]}


def test_history_keeps_current_origins_with_their_real_age():
    records = rs.history_records(HISTORY)
    assert [(r["prefix"], r["origin"]) for r in records] == [("193.0.0.0/21", "AS3333"), ("193.0.0.0/22", "AS64500")]
    assert records[0]["first"].startswith("2000-10-26") and records[0]["collectors"] == 322 and records[0]["count"] == 2


def test_validity_flags_follow_rpki_and_irr():
    record = {"prefix": "193.0.0.0/21", "origin": "AS3333"}
    assert rs.add_validity(record, STATUS, VALID) == {**record, "rpki_valid": True, "irr_valid": True}
    hijack = rs.add_validity({"prefix": "193.0.0.0/22", "origin": "AS64500"}, STATUS, INVALID)
    assert hijack["rpki_invalid_origin"] and hijack["irr_invalid_origin"]
    rows = bgp.origin_rows("193.0.6.139", {"ripe.net"}, [rs.add_validity(r, STATUS, VALID if r["origin"] == "AS3333"
                                                                         else INVALID) for r in rs.history_records(HISTORY)])
    assert [r["Status"] for r in rows] == [bgp.VALID, bgp.UNAUTHORIZED]
    assert rows[0]["First Seen"] == pd.Timestamp("2000-10-26")


def test_networks_paths_and_more_specifics():
    assert rs.rir_text(RIR, COUNTRY) == "RIPE 2003-11-20 NL" and rs.rir_text({}, COUNTRY) == ""
    assert rs.whois_rir_text(WHOIS_ARIN) == "ARIN 2023-12-28"   # the /24's date, not its parent /8's
    assert rs.whois_rir_text(WHOIS_ARIN_AS) == "ARIN 2010-07-14" and rs.whois_rir_text({}, COUNTRY) == ""
    old = {"authorities": ["ripe"], "records": [_kv(("aut-num", "AS1"), ("created", "1970-01-01T00:00:00Z"))]}
    assert rs.whois_rir_text(old) == ""   # RIPE's placeholder date for objects older than its dates
    row = bgp.asn_row(rs.asn_record("3333", OVERVIEW, NEIGHBOURS, WHOIS_RIPE, COUNTRY), "origin")
    assert row["ASN"] == "AS3333" and row["RIR"] == "RIPE" and row["RIR Country"] == "NL"
    assert row["Registered"] == pd.Timestamp("2003-03-17") and row["Upstreams"] == 46 and row["Downstreams"] == 2
    routes = bgp.route_rows("193.0.0.0/21", rs.route_records("193.0.0.0/21", GLASS))
    by_upstream = {r["Upstream"]: r for r in routes}
    assert set(by_upstream) == {"AS12859", "AS1103"}   # last two hops, prepending dropped
    assert by_upstream["AS12859"]["Peers"] == 2 and by_upstream["AS12859"]["Collectors"] == 1
    assert by_upstream["AS12859"]["First Seen"] == pd.Timestamp("2026-10-01")
    assert rs.more_specific_records(STATUS) == [{"prefix": "193.0.4.0/24", "origin": "AS3333"}]


def test_registration_takes_the_most_specific_network_and_no_personal_details():
    row = rs.registration_row("8.8.8.8", {"dns.google"}, WHOIS_ARIN, {"abuse_contacts": ["network-abuse@google.com"]})
    assert (row["Range"], row["Net Name"], row["Organisation"], row["Country"], row["RIR"]) == \
        ("8.8.8.0/24", "GOGL", "Google LLC (GOGL)", "US", "ARIN")
    assert row["Registered"] == pd.Timestamp("2023-12-28") and row["Abuse Contact"] == "network-abuse@google.com"
    assert "1600" not in str(row) and "650" not in str(row)
    ripe = rs.registration_row("193.0.6.139", {"ripe.net"}, WHOIS_RIPE, None)
    assert (ripe["Net Name"], ripe["Type"], ripe["Country"], ripe["Organisation"]) == \
        ("RIPE-NCC", "ASSIGNED PA", "NL", "ORG-RIEN1-RIPE")
    assert "MDIR" not in str(ripe)


def test_request_urls_targets_and_curl():
    assert ripestat.request_url("routing-history", "193.0.6.139") == \
        "https://stat.ripe.net/data/routing-history/data.json?resource=193.0.6.139&sourceapp=dt-analytics"
    target = ripestat.target_of("rpki-validation", "AS3333", prefix="193.0.0.0/21")
    assert target == "rpki-validation AS3333 193.0.0.0/21"
    assert ripestat.parse_target(target) == ("rpki-validation", "AS3333", {"prefix": "193.0.0.0/21"})
    assert ripestat.parse_target("rir AS3333") == ("rir", "AS3333", {"starttime": ripestat.HISTORY_START})
    assert ripestat.parse_target("ip 1.1.1.0/24") is None
    assert ripestat.curl_command("whois", "8.8.8.8").startswith("curl -s 'https://stat.ripe.net/data/whois/")


@pytest.mark.parametrize("choice, host, expected", [("auto", "bgpdb.example", "bgpdb"), ("auto", None, "ripestat"),
                                                    ("ripestat", "bgpdb.example", "ripestat"),
                                                    ("bgpdb", None, "bgpdb"), ("nonsense", None, "ripestat")])
def test_routing_source(monkeypatch, choice, host, expected):
    monkeypatch.setattr(ripestat_stage, "load_bgpdb_host", lambda: host)
    assert ripestat_stage.routing_source({"bgp_source": choice}) == expected


def _mock_ripestat(monkeypatch, calls):
    answers = {"routing_history": HISTORY, "routing_status": STATUS, "looking_glass": GLASS, "as_overview": OVERVIEW,
               "asn_neighbours": NEIGHBOURS, "rir": RIR, "rir_country": COUNTRY, "whois": WHOIS_RIPE,
               "abuse_contact": {"abuse_contacts": ["abuse@ripe.net"]}}
    for name, data in answers.items():
        def fetch(*args, _name=name, _data=data):
            calls.append((_name, args))
            return FetchResult(ripestat.SOURCE, f"{_name} {args[0]}", data=_data, record_count=1,
                               extras={"url": f"https://stat.ripe.net/data/{_name}", "raw": "{}"})
        monkeypatch.setattr(ripestat, name, fetch)

    def rpki(asn, prefix):
        calls.append(("rpki_validation", (asn, prefix)))
        return FetchResult(ripestat.SOURCE, f"rpki-validation {asn} {prefix}", data=VALID if asn == "AS3333" else INVALID,
                           record_count=1, extras={"url": "https://stat.ripe.net/data/rpki-validation", "raw": "{}"})
    monkeypatch.setattr(ripestat, "rpki_validation", rpki)


def test_collect_ripestat_builds_the_bgp_tables_and_registration(monkeypatch):
    calls = []
    _mock_ripestat(monkeypatch, calls)
    log = collector.StatusLog()
    origins, asns, routes, neighbours, raw, reg = collector.collect_ripestat(
        ["ripe.net"], ["193.0.6.139"], pd.DataFrame(), {}, log)
    assert set(origins["Origin"]) == {"AS3333", "AS64500"} and "AS3333" in set(asns["ASN"])
    assert origins.loc[origins["Origin"] == "AS3333", "AS Name"].iloc[0].startswith("RIPE-NCC-AS")
    assert set(origins["RIR"]) == {"RIPE"} and set(origins["RIR Country"]) == {"NL"}   # whois + rir-stats-country
    assert {name for name, args in calls if name == "asn_neighbours"} and \
        all(args[0] in set(origins["Origin"]) for name, args in calls if name == "asn_neighbours")   # origins only
    assert set(routes["Upstream"]) == {"AS12859", "AS1103"} and "193.0.4.0/24" in set(neighbours["Prefix"])
    assert reg.iloc[0]["Net Name"] == "RIPE-NCC" and reg.iloc[0]["Abuse Contact"] == "abuse@ripe.net"
    assert bgp.data_source(raw) == "RIPEstat" and len(raw) == len(log.rows) == len(calls)
    found = bgp.findings(origins, asns, routes)
    assert bgp.UNAUTHORIZED_ORIGIN in set(found["Finding"]) or bgp.CONFLICT in set(found["Finding"])


def test_collect_registration_only_skips_routing(monkeypatch):
    calls = []
    _mock_ripestat(monkeypatch, calls)
    raw, reg = ripestat_stage.collect_registration_only(["ripe.net"], ["193.0.6.139"], pd.DataFrame(), {},
                                                        collector.StatusLog())
    assert {name for name, _ in calls} == {"whois", "abuse_contact"} and len(reg) == 1
    assert bgp.data_source(raw) == "BGPDB"   # registration alone does not make RIPEstat the routing source


def test_stops_after_unanswered_calls(monkeypatch):
    monkeypatch.setattr(ripestat, "routing_history", lambda ip: FetchResult(
        ripestat.SOURCE, f"routing-history {ip}", error="Connection refused", extras={ripestat.UNREACHABLE: True}))
    log = collector.StatusLog()
    origins, *_, reg = collector.collect_ripestat(["a.example"], [f"193.0.6.{i}" for i in range(1, 17)], pd.DataFrame(), {}, log)
    assert origins.empty and reg.empty   # registration is skipped too once RIPEstat stopped answering
    assert sum(row["Target"].startswith("routing-history") for row in log.rows) < 16   # parallel calls in flight finish
    assert any("RIPEstat stopped" in str(row.get("Detail") or row.get("Error") or "") for row in log.rows)


def test_lookup_queries_list_ripestat_curl(monkeypatch):
    from core.lookup_queries import build_lookup_queries
    status = FetchResult(ripestat.SOURCE, "rpki-validation AS3333 193.0.0.0/21", data={"status": "valid"},
                         record_count=1).status_row()

    class Run:
        statuses = [status]
    queries = build_lookup_queries(Run())
    assert queries.iloc[0]["Tool"] == "RIPEstat"
    assert "rpki-validation/data.json?resource=AS3333&prefix=193.0.0.0/21" in queries.iloc[0]["Command"]


def test_query_plan_names_ripestat(monkeypatch):
    from core.use_cases import query_plan
    monkeypatch.setattr(ripestat_stage, "_settings", lambda: {"bgp_source": "ripestat"})
    keys = {row["Key"] for row in query_plan({"opt_bgpdb": True})}
    assert "ripestat" in keys and "bgpdb" not in keys
    monkeypatch.setattr(ripestat_stage, "_settings", lambda: {"bgp_source": "bgpdb", "ripestat_registration": True})
    keys = {row["Key"] for row in query_plan({"opt_bgpdb": True})}
    assert {"ripestat", "bgpdb"} <= keys


@pytest.mark.parametrize("choice, host, plan", [
    ("both", "bgpdb.example", (True, "always")), ("both", None, (False, "always")),
    ("auto", "bgpdb.example", (True, "fallback")), ("auto", None, (False, "always")),
    ("bgpdb", "bgpdb.example", (True, "never")), ("bgpdb", None, (False, "never")),
    ("ripestat", "bgpdb.example", (False, "always")), (None, None, (False, "always"))])
def test_routing_plan(monkeypatch, choice, host, plan):
    monkeypatch.setattr(ripestat_stage, "load_bgpdb_host", lambda: host)
    assert ripestat_stage.routing_plan({"bgp_source": choice} if choice else {}) == plan


def _mock_bgpdb(monkeypatch, answers=True):
    from integrations import bgpdb
    record = {"prefix": "193.0.0.0/21", "origin": "AS3333", "first": "2026-11-01", "last": "2026-11-26",
              "count": 5, "collectors": 60, "rpki_valid": True}

    def fetch(target, *rest):
        if not answers:
            return FetchResult("BGPDB", f"ip {target}", error="Connection refused", extras={bgpdb.UNREACHABLE: True})
        return FetchResult("BGPDB", f"x {target}", data=[record], record_count=1)
    monkeypatch.setattr(bgpdb, "load_bgpdb_host", lambda: "bgpdb.example")
    monkeypatch.setattr(ripestat_stage, "load_bgpdb_host", lambda: "bgpdb.example")
    for command in ("ip", "route", "asn", "prefix"):
        monkeypatch.setattr(bgpdb, f"lookup_{command}", fetch)


def test_both_sources_bgpdb_first(monkeypatch):
    _mock_ripestat(monkeypatch, [])
    _mock_bgpdb(monkeypatch)
    out = ripestat_stage.collect_routing(["ripe.net"], ["193.0.6.139"], pd.DataFrame(), {}, collector.StatusLog(), 50,
                                         settings={"bgp_source": "both"})
    assert (out["bgp_source"], out["alt_bgp_source"]) == ("BGPDB", "RIPEstat")
    assert out["bgp_origins"]["Updates"].tolist() == [5]   # BGPDB's
    assert set(out["alt_bgp_origins"]["Origin"]) == {"AS3333", "AS64500"} and len(out["bgp_registration"]) == 1
    assert {"ip", "routing-history"} <= set(out["bgp_raw"]["Command"])


def test_ripestat_takes_over_when_bgpdb_does_not_answer(monkeypatch):
    _mock_ripestat(monkeypatch, [])
    _mock_bgpdb(monkeypatch, answers=False)
    for choice in ("both", "auto"):
        out = ripestat_stage.collect_routing(["ripe.net"], ["193.0.6.139"], pd.DataFrame(), {}, collector.StatusLog(),
                                             50, settings={"bgp_source": choice})
        assert out["bgp_source"] == "RIPEstat" and out["alt_bgp_source"] == "" and not out["bgp_origins"].empty


def test_auto_skips_ripestat_routing_when_bgpdb_answers(monkeypatch):
    calls = []
    _mock_ripestat(monkeypatch, calls)
    _mock_bgpdb(monkeypatch)
    out = ripestat_stage.collect_routing(["ripe.net"], ["193.0.6.139"], pd.DataFrame(), {}, collector.StatusLog(), 50,
                                         settings={"bgp_source": "auto", "ripestat_registration": True})
    assert out["bgp_source"] == "BGPDB" and out["alt_bgp_origins"].empty
    assert {name for name, _ in calls} == {"whois", "abuse_contact"}   # registration only


def test_the_switch_shows_the_other_source(monkeypatch):
    from streamlit.testing.v1 import AppTest

    def page():
        import pandas as pd
        import streamlit as st

        from views.bgp_page import source_view
        main = pd.DataFrame({"Origin": ["AS1"]})
        other = pd.DataFrame({"Origin": ["AS2"]})
        ds = type("DS", (), {})()
        ds.bgp_source, ds.alt_bgp_source, ds.bgp_raw = "BGPDB", "RIPEstat", pd.DataFrame()
        ds.bgp_origins, ds.alt_bgp_origins = main, other
        for name in ("bgp_asns", "bgp_routes", "bgp_neighbours"):
            setattr(ds, name, pd.DataFrame())
            setattr(ds, f"alt_{name}", pd.DataFrame())
        view, source = source_view(ds, "test_switch")
        st.write(f"{source}:{view.bgp_origins['Origin'].iloc[0]}:{ds.bgp_origins['Origin'].iloc[0]}")

    at = AppTest.from_function(page).run()
    assert at.markdown[-1].value == "BGPDB:AS1:AS1"
    at.button_group(key="test_switch").set_value("RIPEstat").run()
    assert at.markdown[-1].value == "RIPEstat:AS2:AS1"   # the dataset itself is untouched
    assert at.session_state["bgp_view_source"] == "RIPEstat"

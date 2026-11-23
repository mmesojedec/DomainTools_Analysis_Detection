"""BGPDB: NDJSON parsing, BGP tables, routing findings, the rules, the VPNDB match and the collection stage."""
import pandas as pd

from core import bgp
from core.threat_detection import detect_threat_flags
from integrations import bgp_stage, bgpdb, collector
from integrations.http import FetchResult

NOW = pd.Timestamp("2026-11-20 12:00")
CLOUDFLARE = {"prefix": "1.1.1.0/24", "origin": "AS13335", "first": "2026-10-21 00:06:54",
              "last": "2026-11-20 10:37:48", "count": 35482, "collectors": 65, "core": 13, "irr_valid": True,
              "rpki_valid": True, "rir_prefix": ["APNIC 2011-08-11 AU 266e3933"], "score": 39}
LEAK = {"prefix": "1.1.1.0/24", "origin": "AS577", "first": "2026-11-13 23:03:10", "last": "2026-11-14 00:29:46",
        "count": 11, "collectors": 3, "irr_invalid_origin": True, "rpki_invalid_origin": True,
        "rir_prefix": ["APNIC 2011-08-11 AU 266e3933"], "score": -24}
FRESH = {"prefix": "203.0.113.0/24", "origin": "AS65010", "first": "2026-11-15 08:00:00", "last": "2026-11-20 10:00:00",
         "count": 40, "collectors": 6, "rir_prefix": ["RIPE 2026-09-01 NL abc"], "score": -5}
SQUAT = {"prefix": "198.51.100.0/24", "origin": "AS65020", "first": "2026-10-21 00:00:00",
         "last": "2026-11-20 10:00:00", "count": 900, "collectors": 50, "rpki_invalid_origin": True}
NDJSON = "\n".join(__import__("json").dumps(r) for r in (CLOUDFLARE, LEAK)) + '\n{ "info": "end of results" }\n'


def origins():
    rows = bgp.origin_rows("1.1.1.1", {"one.example"}, [CLOUDFLARE, LEAK])
    rows += bgp.origin_rows("203.0.113.5", {"fresh.example"}, [FRESH])
    rows += bgp.origin_rows("198.51.100.7", {"squat.example"}, [SQUAT])
    return pd.DataFrame(rows, columns=bgp.ORIGIN_COLUMNS)


def asns():
    young = bgp.asn_row({"asn": "AS65010", "rir_asn": ["RIPE 2026-09-01 NL abc"], "asname": ["FRESHNET"],
                         "collectors": 6, "hop_upstream": 1, "first": "2026-11-15 08:00:00"}, "origin", {"fresh.example"})
    old = bgp.asn_row({"asn": "AS13335", "rir_asn": ["ARIN 2010-07-14 US x"], "asname": ["CLOUDFLARENET"],
                       "collectors": 70, "hop_upstream": 160, "hop_downstream": 1096}, "origin", {"one.example"})
    return pd.DataFrame([young, old], columns=bgp.ASN_COLUMNS)


def test_ndjson_answers_split_into_records_and_control_lines():
    records, info = bgp_parse(NDJSON)
    assert len(records) == 2 and info == {"info": "end of results"}
    records, info = bgp_parse('{ "prefix": "x" }\n{ "warn": "hit the result limit" }')
    assert len(records) == 1 and info["warn"].startswith("hit")
    assert bgp_parse('{ "info": "no results" }') == ([], {"info": "no results"})


def bgp_parse(text):
    return bgpdb.parse_ndjson(text)


def test_origin_rows_read_validity_and_the_rir_line():
    rows = origins()
    cloudflare, leak = rows.iloc[0], rows.iloc[1]
    assert cloudflare["Status"] == bgp.VALID and cloudflare["RIR"] == "APNIC" and cloudflare["RIR Country"] == "AU"
    assert leak["Status"] == bgp.UNAUTHORIZED and leak["RPKI"] == "invalid origin" and leak["Collectors"] == 3
    assert rows.iloc[3]["Status"] == bgp.UNAUTHORIZED and rows.iloc[2]["Status"] == bgp.UNVERIFIED


def test_findings_name_the_conflict_the_squat_the_new_prefix_and_the_young_network():
    found = bgp.findings(origins(), asns(), now=NOW)
    kinds = dict(zip(found["Finding"] + "|" + found["Prefix"] + found["ASN"], found["Severity"]))
    assert kinds[f"{bgp.CONFLICT}|1.1.1.0/24AS577"] == "High"           # seen 6 days before the data's end
    assert kinds[f"{bgp.UNAUTHORIZED_ORIGIN}|198.51.100.0/24AS65020"] == "Medium-High"
    assert f"{bgp.NEW_PREFIX}|203.0.113.0/24AS65010" in kinds
    assert kinds[f"{bgp.NEW_ASN}|AS65010"] == "Medium-High"               # registered 80 days earlier
    assert any(k.startswith(bgp.THIN_ROUTE) for k in kinds)                # 6 collectors, a single upstream
    assert not any("AS13335" in k for k in kinds)                          # the authorized origin is not a finding


def test_a_prefix_announced_since_the_window_began_is_not_new():
    assert not bgp.is_new("2026-10-21 00:00", pd.Timestamp("2026-10-21"), pd.Timestamp("2026-11-20"))
    assert bgp.is_new("2026-11-15", pd.Timestamp("2026-10-21"), pd.Timestamp("2026-11-20"))


def test_ip_table_and_summary():
    frame, found = origins(), bgp.findings(origins(), asns(), now=NOW)
    table = bgp.ip_table(frame, found=found)
    one = table[table["IP"] == "1.1.1.1"].iloc[0]
    assert one["Origin"] == "AS13335" and one["Origins"] == 2 and bgp.CONFLICT in one["Findings"]
    stats = bgp.summary(frame, asns(), found=found)
    assert stats["ips"] == 3 and stats["conflicts"] == 1 and stats["new_prefixes"] == 1 and stats["new_asns"] == 1


def test_rules_raise_alerts_per_domain_and_the_vpndb_match():
    anonymizers = pd.DataFrame([{"IP": "203.0.113.5", "Domains": "fresh.example", "Category": "VPN",
                                 "Provider": "ExampleVPN", "Sharing": "LOW", "IOC Value": "HIGH", "Confidence": "High"}])
    result = detect_threat_flags(pd.DataFrame(), {}, enrichment_data={"one.example": {}, "fresh.example": {},
                                                                       "squat.example": {}},
                                 anonymizers=anonymizers, bgp_frames={"origins": origins(), "asns": asns()})
    alerts = set(zip(result.alerts["Domain"], result.alerts["Threat Type"]))
    assert ("one.example", "BGP Origin Conflict (Possible Hijack)") in alerts
    assert ("squat.example", "Unauthorized BGP Origin") in alerts
    assert ("fresh.example", "Newly Announced Prefix") in alerts
    assert ("fresh.example", "Anonymizer Exit on Unstable Routing") in alerts
    assert not any(t == "BGP Origin Conflict (Possible Hijack)" for d, t in alerts if d != "one.example")
    match = bgp.vpndb_ip_match(bgp.ip_table(origins(), found=bgp.findings(origins(), asns(), now=NOW)), anonymizers)
    assert list(match["IP"]) == ["203.0.113.5"] and bgp.NEW_PREFIX in match.iloc[0]["Findings"]


def test_covering_range_and_neighbours():
    assert bgp.covering_range("198.202.211.0/24") == "198.202.208.0/20"
    assert bgp.covering_range("8.0.0.0/9") is None and bgp.covering_range("2606:4700::/48") == "2606:4700::/40"
    assert bgp.covering_range("185.199.108.0/24+") == "185.199.96.0/20"
    rows = bgp.neighbour_rows("1.1.0.0/20", {"1.1.1.0/24"}, {"AS13335"},
                              [CLOUDFLARE, {**FRESH, "prefix": "1.1.2.0/24", "origin": "AS13335"}])
    assert [r["Prefix"] for r in rows] == ["1.1.2.0/24"] and rows[0]["Same Origin"]


def test_collect_bgp_queries_ip_route_asn_and_prefix(monkeypatch):
    calls = []

    def answer(command):
        def fetch(target, limit=None):
            calls.append((command, target))
            data = {"ip": [CLOUDFLARE, LEAK], "route": [{"route": "1.1.1.0/24", "path": ["AS174", "AS13335"],
                                                         "collectors": 30}],
                    "asn": [{"asn": target, "asname": ["NAME"], "rir_asn": ["ARIN 2010-01-01 US x"]}],
                    "prefix": [{**CLOUDFLARE, "prefix": "1.1.2.0/24"}]}[command]
            return FetchResult("BGPDB", f"{command} {target}", data=data, record_count=len(data))
        return fetch

    monkeypatch.setattr(bgpdb, "load_bgpdb_host", lambda: "bgpdb.example")
    for command in ("ip", "route", "asn", "prefix"):
        monkeypatch.setattr(bgpdb, f"lookup_{command}", answer(command))
    log = collector.StatusLog()
    found_origins, found_asns, routes, neighbours, raw = collector.collect_bgp(
        ["one.example"], ["1.1.1.1"], pd.DataFrame(), {}, log)
    assert {c for c, _ in calls} == {"ip", "route", "asn", "prefix"}
    assert set(found_origins["Origin"]) == {"AS13335", "AS577"} and set(found_asns["ASN"]) >= {"AS13335", "AS577", "AS174"}
    assert routes.iloc[0]["Upstream"] == "AS174" and neighbours.iloc[0]["Prefix"] == "1.1.2.0/24"
    assert len(raw) == len(calls) and len(log.rows) == len(calls)


def test_collect_bgp_is_skipped_without_a_host():
    origins_frame, *_ = collector.collect_bgp(["one.example"], ["1.1.1.1"], pd.DataFrame(), {}, collector.StatusLog())
    assert origins_frame.empty


def test_a_private_as_seen_by_one_collector_is_a_local_leak_not_a_conflict():
    local = {**LEAK, "origin": "AS65535", "collectors": 1}
    rows = pd.DataFrame(bgp.origin_rows("1.1.1.1", {"one.example"}, [CLOUDFLARE, local]), columns=bgp.ORIGIN_COLUMNS)
    assert rows.iloc[1]["Status"] == bgp.LOCAL_LEAK
    assert bgp.findings(rows, now=NOW).query("Finding == @bgp.CONFLICT").empty
    widely = pd.DataFrame(bgp.origin_rows("1.1.1.1", {"one.example"}, [CLOUDFLARE, {**local, "collectors": 30}]),
                          columns=bgp.ORIGIN_COLUMNS)
    assert widely.iloc[1]["Status"] == bgp.UNAUTHORIZED            # a private AS the internet saw is a real leak
    assert bgp.is_private_asn("AS64516") and bgp.is_private_asn("4200000001") and not bgp.is_private_asn("AS13335")


def test_sankey_colours_a_prefix_by_the_worst_origin_seen():
    from views.bgp_page import sankey_figure
    rows = pd.DataFrame(bgp.origin_rows("1.1.1.1", {"one.example"}, [CLOUDFLARE, LEAK]), columns=bgp.ORIGIN_COLUMNS)
    fig, _ = sankey_figure(rows, pd.DataFrame(columns=bgp.ROUTE_COLUMNS))
    node = fig.data[0].node
    assert node.color[list(node.label).index("1.1.1.0/24")] == bgp.STATUS_COLORS[bgp.UNAUTHORIZED]


def test_bgp_routing_vector_only_for_domains_with_bgpdb_data():
    from core.risk_profile import ROUTING_VECTOR, generate_digital_risk_profile, score_drivers
    alerts = pd.DataFrame([{"Domain": "one.example", "Threat Type": bgp.CONFLICT, "Severity": "High",
                            "MITRE ATT&CK": "T1557 (Adversary-in-the-Middle)", "Confidence": "High"}])
    profiles = generate_digital_risk_profile(["one.example", "two.example"], alerts, pd.DataFrame(), pd.DataFrame(),
                                             pd.DataFrame(), {}, routed_domains={"one.example"})
    one, two = profiles.iloc[0], profiles.iloc[1]
    assert one[ROUTING_VECTOR] > 0 and pd.isna(two[ROUTING_VECTOR]) and one["Unified Risk"] > 0
    assert any(ROUTING_VECTOR in text for _, text in score_drivers(one, alerts))


def test_lookup_queries_give_bgpdbq_and_curl_for_each_bgpdb_lookup(monkeypatch):
    from core.lookup_queries import build_lookup_queries
    monkeypatch.setattr("integrations.bgpdb.request_url",
                        lambda c, a, limit=None: f"https://bgpdb.example/v1/{c}/{a}" + (f"?limit={limit}" if limit else ""))
    data = collector.CollectedData(targets=["one.example"])
    data.statuses = [{"Source": "BGPDB", "Target": t, "Status": "OK", "Records": 2, "Detail": ""}
                     for t in ("ip 1.1.1.1", "route 1.1.1.0/24", "asn AS13335")]
    queries = build_lookup_queries(data)
    assert list(queries["Tool"]) == ["BGPDB"] * 3
    route = queries.iloc[1]
    assert route["Query"] == "bgpdbq route 1.1.1.0/24 --limit=100"
    assert "curl -s 'https://bgpdb.example/v1/route/1.1.1.0/24?limit=100'" in route["Command"]
    assert queries.iloc[0]["Query"] == "bgpdbq ip 1.1.1.1"


def test_evidence_reads_a_bgpdb_answer_as_records():
    from views.raw_view import bgpdb_records, cache_summary
    frame = bgpdb_records({"Response": NDJSON})
    assert list(frame["origin"]) == ["AS13335", "AS577"] and frame.iloc[0]["rir_prefix"].startswith("APNIC")
    statuses = [{"Source": "BGPDB", "Target": "ip 1.1.1.1", "Status": "OK", "Detail": "", "Cached At": None},
                {"Source": "Iris Investigate", "Target": "3 domain(s)", "Status": "OK", "Detail": "", "Cached At": None}]
    assert list(cache_summary(statuses, 3600)["Source"]) == ["BGPDB"]   # a BGPDB lookup is not a summary row


def test_network_filter_keeps_domains_on_picked_networks_and_verdicts():
    from views.results_toolbar import network_domains, network_options
    data = collector.CollectedData(targets=["one.example", "fresh.example", "squat.example"])
    data.bgp_origins = origins()
    data.anonymizers = pd.DataFrame([{"IP": "203.0.113.5", "Domains": "fresh.example", "Category": "VPN"},
                                     {"IP": "1.1.1.1", "Domains": "one.example", "Category": "Not anonymous"}])
    labels, by_asn, by_verdict = network_options(data)
    assert set(labels) == {"AS13335", "AS65010", "AS65020"} and by_verdict["VPN"] == {"fresh.example"}
    assert network_domains(data, ["AS13335", "AS65010"], []) == {"one.example", "fresh.example"}
    assert network_domains(data, ["AS13335", "AS65010"], ["VPN"]) == {"fresh.example"}
    assert network_domains(data, [], []) is None


def test_tor_page_lists_every_network_bgp_saw():
    from types import SimpleNamespace

    from views.tor_page import run_tor_networks
    routes = pd.DataFrame([{"Prefix": "1.1.1.0/24", "Path": "AS60729 → AS174 → AS13335"}], columns=bgp.ROUTE_COLUMNS)
    ds = SimpleNamespace(anonymizers=pd.DataFrame(), ip_intel={}, bgp_origins=origins(), bgp_routes=routes,
                         bgp_neighbours=pd.DataFrame())
    networks = pd.DataFrame([{"asn": 60729, "organization": "Tor host"}, {"asn": 577, "organization": "Leaker"},
                             {"asn": 13335, "organization": "Cloudflare"}])
    hits = run_tor_networks(ds, networks).set_index("asn")
    assert hits.loc[60729, "Seen as"] == "BGP upstream / transit"
    assert hits.loc[577, "Seen as"] == "BGP unauthorized origin" and "one.example" in hits.loc[577, "Run domains"]
    assert hits.loc[13335, "Seen as"] == "BGP origin"


def test_t1557_is_a_credential_access_technique():
    from core.intel_data import MITRE_TACTICS
    assert MITRE_TACTICS["T1557"] == "Credential Access"


def test_collect_bgp_stops_when_the_host_does_not_answer(monkeypatch):
    calls = []

    def down(ip):
        calls.append(ip)
        return FetchResult("BGPDB", f"ip {ip}", error="Connection timed out", extras={bgpdb.UNREACHABLE: True})

    monkeypatch.setattr(bgpdb, "load_bgpdb_host", lambda: "bgpdb.example")
    monkeypatch.setattr(bgpdb, "lookup_ip", down)
    monkeypatch.setattr(bgp_stage, "_parallel", lambda items, func, **kw: [func(i) for i in items])
    log = collector.StatusLog()
    ips = [f"8.8.{n}.1" for n in range(20)]
    found, *_ = collector.collect_bgp(["one.example"], ips, pd.DataFrame(), {}, log)
    assert found.empty and len(calls) == bgpdb.STOP_AFTER_FAILURES
    assert len(log.rows) == bgpdb.STOP_AFTER_FAILURES + 1 and "BGPDB stopped" in log.rows[-1]["Detail"]


def test_breaker_resets_on_an_answer():
    breaker = bgpdb.Breaker(limit=2)
    fail = FetchResult("BGPDB", "x", error="timeout", extras={bgpdb.UNREACHABLE: True})
    breaker.call(lambda: fail, "x")
    breaker.call(lambda: FetchResult("BGPDB", "x", data=[]), "x")
    breaker.call(lambda: fail, "x")
    assert not breaker.tripped
    breaker.call(lambda: fail, "x")
    assert breaker.tripped and "stopped" in breaker.call(lambda: fail, "x").error


def test_byoip_networks_and_a_parent_upstream_count_lower():
    cust = {"prefix": "154.83.31.0/24", "origin": "AS134494", "first": "2026-10-21 00:23:13",
            "last": "2026-11-07 06:45:30", "count": 4072, "collectors": 44, "irr_valid": True, "rpki_valid": True}
    spectrum = {"prefix": "154.83.30.0/23", "origin": "AS209242", "first": "2026-10-21 00:02:55",
                "last": "2026-11-10 15:46:22", "count": 8947, "collectors": 49, "irr_invalid_origin": True}
    frame = pd.DataFrame(bgp.origin_rows("154.83.31.138", {"byoip.example"}, [spectrum, cust]),
                         columns=bgp.ORIGIN_COLUMNS)
    asn = bgp.asn_row({"asn": "AS209242", "asname": ["CLOUDFLARESPECTRUM CLOUDFLARE"], "hop_upstream": 1,
                       "rir_asn": ["RIPE 2015-01-01 GB x"]}, "origin", {"byoip.example"})
    parent = bgp.asn_row({"asn": "AS13335", "asname": ["CLOUDFLARENET CLOUDFLARE"]}, "upstream")
    routes = pd.DataFrame(bgp.route_rows("154.83.30.0/23", [{"path": ["AS13335", "AS209242"], "collectors": 40}]),
                          columns=bgp.ROUTE_COLUMNS)
    found = bgp.findings(frame, pd.DataFrame([asn, parent], columns=bgp.ASN_COLUMNS), routes, now=NOW)
    squat = found[found["Finding"] == bgp.UNAUTHORIZED_ORIGIN].iloc[0]
    assert squat["Severity"] == "Low" and "bring-your-own-IP" in squat["Detail"] and "AS134494" in squat["Detail"]
    assert not (found["Finding"] == bgp.THIN_ROUTE).any() or "AS209242" not in set(
        found.loc[found["Finding"] == bgp.THIN_ROUTE, "ASN"])
    assert bgp.same_organisation("CLOUDFLARESPECTRUM CLOUDFLARE", "CLOUDFLARENET CLOUDFLARE")
    assert not bgp.same_organisation("LEVEL3 LEVEL 3 PARENT", "CLOUDFLARENET CLOUDFLARE")


def test_a_byoip_network_in_a_conflict_is_low():
    frame = pd.DataFrame(bgp.origin_rows("1.1.1.1", {"one.example"}, [CLOUDFLARE, {**LEAK, "origin": "AS20940"}]),
                         columns=bgp.ORIGIN_COLUMNS)
    conflict = bgp.findings(frame, now=NOW).query("Finding == @bgp.CONFLICT").iloc[0]
    assert conflict["Severity"] == "Low" and "Akamai" in conflict["Detail"]


def test_clean_routing_never_lowers_unified_risk():
    from core.risk_profile import generate_digital_risk_profile
    alerts = pd.DataFrame([{"Domain": "a.example", "Threat Type": "Fast-Flux DNS", "Severity": "High",
                            "MITRE ATT&CK": "T1568 (Dynamic Resolution)", "Confidence": "High"}])
    args = (["a.example"], alerts, pd.DataFrame(), pd.DataFrame(), pd.DataFrame(), {})
    without = generate_digital_risk_profile(*args).iloc[0]["Unified Risk"]
    clean = generate_digital_risk_profile(*args, routed_domains={"a.example"}).iloc[0]["Unified Risk"]
    assert without == clean > 0


def test_hosting_moved_to_a_new_network_against_the_earlier_run():
    earlier = [{"created": "2026-11-01T10:00:00+00:00",
                "artifacts": {"one.example": {"ASN": ["as9999"], "Prefix": ["9.9.9.0/24"]},
                              "fresh.example": {"ASN": ["as65010", "as65099"], "Prefix": ["203.0.113.0/24"]}}}]
    previous = bgp.previous_routing(earlier, {"one.example", "fresh.example", "squat.example"})
    assert previous["one.example"][1] == ("AS9999",) and "squat.example" not in previous
    result = detect_threat_flags(pd.DataFrame(), {}, enrichment_data={"one.example": {}, "fresh.example": {}},
                                 bgp_frames={"origins": origins(), "asns": asns(), "previous": previous})
    moved = result.alerts[result.alerts["Threat Type"] == bgp.MOVED].set_index("Domain")
    assert moved.loc["one.example", "Severity"] == "Medium" and "AS13335" in moved.loc["one.example", "Triggering IOCs"]
    assert "fresh.example" not in moved.index      # its network was already there


def test_exports_carry_networks_and_prefixes_as_context():
    import json as _json
    from types import SimpleNamespace

    from core.export import collect_iocs, ioc_type, to_misp_event, to_stix_bundle
    ds = SimpleNamespace(selected_domains=["one.example", "fresh.example"], events_utc=pd.DataFrame(), enrichment={},
                         ssl_utc=pd.DataFrame(), bgp_origins=origins(), bgp_asns=asns(), bgp_routes=None)
    iocs = collect_iocs(ds)
    routing = iocs[iocs["Source"] == "BGPDB"].set_index("Value")
    assert routing.loc["AS13335", "Type"] == "autonomous-system" and routing.loc["1.1.1.0/24", "Type"] == "ipv4-prefix"
    assert "AS577" in routing.index and "Routing finding" in routing.loc["AS577", "Note"]
    assert "AS65020" not in routing.index                           # squat.example is not selected
    misp = _json.loads(to_misp_event(iocs.assign(Reason="")))["Event"]["Attribute"]
    asn = next(a for a in misp if a["type"] == "AS" and a["value"] == "13335")
    assert asn["to_ids"] is False
    alerts = pd.DataFrame([{"Domain": "one.example", "Threat Type": bgp.CONFLICT, "Severity": "High",
                            "Confidence": "Medium", "MITRE ATT&CK": "T1557 (Adversary-in-the-Middle)"}])
    names = [o["name"] for o in _json.loads(to_stix_bundle(iocs, alerts))["objects"] if o["type"] == "indicator"]
    assert "autonomous-system: AS577" in names and "autonomous-system: AS13335" not in names
    assert ioc_type("AS13335") == "autonomous-system" and ioc_type("10.0.0.0/8") == "ipv4-prefix"


def test_iris_queries_for_a_network_and_a_prefix():
    from core.irisql import narrow, network_query, problems
    assert network_query("AS13335") == '# IrisQL-1.0\nasn matches "13335"\nAND\nCREATE_DATE WITHIN "The last 30 days"'
    assert network_query("AS13335", ()) == '# IrisQL-1.0\nasn matches "13335"'
    assert 'ip greater_than_or_equal "185.199.108.0"' in network_query("185.199.108.0/24+", ())
    assert network_query("not a network") is None
    both = network_query("AS16509", ["Created in the last 7 days", "Risk score above 70"])
    assert both.count("\nAND\n") == 2 and not problems(both)
    assert narrow(both, ["Risk score above 70"]) == both           # a condition is not added twice


def test_a_collector_local_leak_alone_raises_no_finding():
    leak = {"prefix": "52.213.114.0/24+", "origin": "AS65001", "first": "2026-11-10 00:00:00",
            "last": "2026-11-10 01:00:00", "count": 3, "collectors": 1}
    frame = pd.DataFrame(bgp.origin_rows("52.213.114.9", {"aws.example"}, [leak]), columns=bgp.ORIGIN_COLUMNS)
    assert bgp.findings(frame, now=NOW).empty


def test_vpndb_focus_keeps_the_networks_and_exits_from_bgp():
    from core.anonymizers import focus_tables
    frames = {"anonymizers": pd.DataFrame([{"IP": "1.1.1.1", "ASN": 13335.0}, {"IP": "2.2.2.2", "ASN": 60729},
                                           {"IP": "3.3.3.3", "ASN": 15169}]),
              "exit_weeks": pd.DataFrame([{"IP": "2.2.2.2"}, {"IP": "3.3.3.3"}]),
              "exit_neighbours": None,
              "neighbour_ranges": pd.DataFrame([{"CIDR": "2.2.2.0/24", "Hosting IPs": "2.2.2.2"},
                                                {"CIDR": "3.3.3.0/24", "Hosting IPs": "3.3.3.3"}]),
              "hosting_asns": pd.DataFrame([{"ASN": 60729}, {"ASN": 15169}])}
    out = focus_tables(frames, asns=["AS60729"], ips=["1.1.1.1"])
    assert sorted(out["anonymizers"]["IP"]) == ["1.1.1.1", "2.2.2.2"]
    assert list(out["exit_weeks"]["IP"]) == ["2.2.2.2"] and list(out["neighbour_ranges"]["CIDR"]) == ["2.2.2.0/24"]
    assert list(out["hosting_asns"]["ASN"]) == [60729] and out["exit_neighbours"] is None

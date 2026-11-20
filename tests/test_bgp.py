"""BGPDB: NDJSON parsing, BGP tables, routing findings, the rules, the VPNDB match and the collection stage."""
import pandas as pd

from core import bgp
from core.threat_detection import detect_threat_flags
from integrations import bgpdb, collector
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

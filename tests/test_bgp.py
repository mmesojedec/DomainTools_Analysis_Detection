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

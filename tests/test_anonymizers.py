import json

import pandas as pd

from core import anonymizers
from core.export import IOC_COLUMNS, confirmed_indicators, to_misp_event
from core.risk_profile import VECTOR_RULES
from core.threat_detection.engine import detect_threat_flags
from integrations import collector
from integrations.http import FetchResult, StatusLog

BULK = {"total": 4, "anonymous": 3, "results": [
    {"ip": "45.248.77.91", "anonymous": True, "provider": "nordvpn", "types": ["VPN"], "infrastructure": "DATACENTER",
     "confidence": 3, "method": "probe", "asn": 136787, "asnOrganization": "PacketHub", "country": "US",
     "lastSeen": "2026-10-30", "feeds": ["x4bnet"]},
    {"ip": "81.2.3.4", "anonymous": True, "provider": "brightdata", "types": ["PROXY"], "infrastructure": "RESIDENTIAL",
     "confidence": 1, "method": "probe", "lastSeen": "2026-10-29"},
    {"ip": "185.220.101.1", "anonymous": True, "types": ["TOR"], "method": "feed"},
    {"ip": "93.184.216.34", "anonymous": False},
]}
DETAILS = {
    "45.248.77.91": {"ip": "45.248.77.91", "anonymous": True, "confidence": 3, "types": ["VPN"],
                     "attribution": [{"provider": "nordvpn", "weight": 1, "confidence": 3, "methods": ["probe"]}],
                     "sharing": {"level": "HIGH", "iocValue": "LOW"},
                     "evidence": {"confidenceBasis": {"explanation": "120 probe events."}},
                     "asn": {"number": 136787, "organization": "PacketHub"}, "location": {"country": "US"}},
    "185.220.101.1": {"ip": "185.220.101.1", "anonymous": True, "confidence": 3, "types": ["TOR"],
                      "tor": {"exit": {"current": True, "days": 300},
                              "relays": [{"role": "exit", "fingerprint": "F", "nickname": "n", "port": 443, "flags": [],
                                          "firstSeen": "2025-01-01", "exitProbability": 0.01, "guardProbability": 0,
                                          "familySize": 0}]}},
}
CANDIDATES = {"45.248.77.91": {"vpn.com"}, "81.2.3.4": {"home.com"}, "185.220.101.1": {"tor.com"},
              "93.184.216.34": {"clean.com"}}


def table():
    return anonymizers.build_rows(CANDIDATES, BULK, DETAILS)


def test_only_public_ipv4_non_cdn_hosting_ips_are_checked_most_recent_first():
    pdns = pd.DataFrame([
        {"Domain": "a.com", "Date": pd.Timestamp("2026-01-01"), "Last Seen": "2026-01-02", "Field": "A", "Value": "8.8.4.4"},
        {"Domain": "a.com", "Date": pd.Timestamp("2026-06-01"), "Last Seen": "2026-10-01", "Field": "A", "Value": "45.248.77.91"},
        {"Domain": "a.com", "Date": pd.Timestamp("2026-06-01"), "Last Seen": "2026-10-01", "Field": "A", "Value": "10.0.0.1"},
        {"Domain": "a.com", "Date": pd.Timestamp("2026-06-01"), "Last Seen": "2026-10-01", "Field": "A", "Value": "104.16.1.1"},
        {"Domain": "a.com", "Date": pd.Timestamp("2026-06-01"), "Last Seen": "2026-10-01", "Field": "AAAA", "Value": "2001:4860::1"},
    ])
    chosen = anonymizers.select_ips(["a.com"], pdns, {}, ip_targets=["81.2.3.4"], max_ips=10, per_domain=1)
    assert chosen == {"81.2.3.4": {"81.2.3.4"}, "45.248.77.91": {"a.com"}}   # private, Cloudflare and IPv6 left out
    assert len(anonymizers.select_ips(["a.com"], pdns, {}, max_ips=1, per_domain=5)) == 1


def test_rows_join_the_bulk_answer_and_the_full_verdicts():
    rows = table().set_index("IP")
    assert list(rows["Category"]) == ["VPN", "Residential proxy", "Tor", "Not observed"]
    vpn = rows.loc["45.248.77.91"]
    assert (vpn["Provider"], vpn["Confidence"], vpn["Sharing"], vpn["IOC Value"], vpn["ASN"]) == \
        ("nordvpn", "High", "HIGH", "LOW", 136787)
    assert vpn["Basis"] == "120 probe events." and vpn["Feeds"] == "x4bnet" and vpn["Domains"] == "vpn.com"
    assert rows.loc["185.220.101.1", "Tor"] == "Exit (current); Relay (exit)"
    assert rows.loc["81.2.3.4", "Confidence"] == "Low"
    assert anonymizers.shared_exit(rows.loc["45.248.77.91"]) and not anonymizers.shared_exit(rows.loc["81.2.3.4"])
    assert len(anonymizers.anonymizer_rows(table())) == 3
    assert list(anonymizers.for_domains(table(), ["home.com"])["IP"]) == ["81.2.3.4"]


def test_rules_alert_on_the_anonymizers_a_domain_resolves_to():
    events = pd.DataFrame([{"Domain": d, "Date": pd.Timestamp("2026-10-01"), "Field": "A", "Value": ip}
                           for ip, domains in CANDIDATES.items() for d in domains])
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table()).alerts.set_index("Domain")
    assert alerts.loc["tor.com", "Threat Type"] == "Domain on Tor Relay / Exit Node"
    assert alerts.loc["home.com", "Threat Type"] == "Domain on Residential Proxy Exit"
    assert alerts.loc["home.com", "Confidence"] == "Low"   # VPNDB's own confidence for the IP
    vpn = alerts.loc["vpn.com"]
    assert (vpn["Threat Type"], vpn["Severity"], vpn["Confidence"]) == ("Domain on VPN / Proxy Exit", "Medium-High", "High")
    assert "shared exit" in vpn["Triggering IOCs"] and "clean.com" not in alerts.index
    assert detect_threat_flags(events, {"risk_score": 0}).alerts.empty   # no VPNDB data, no anonymizer alerts
    assert "Proxy Exit" in VECTOR_RULES["App & C2 Footprint"][0]


def test_shared_exits_are_marked_in_confirmed_indicators_and_not_for_detection():
    iocs = pd.DataFrame([{"Type": "ipv4-addr", "Value": ip, "Domain": "vpn.com", "Source": "pDNS"}
                         for ip in ("45.248.77.91", "93.184.216.34")], columns=IOC_COLUMNS)
    found = confirmed_indicators(iocs, pd.DataFrame(), {"vpn.com": "Malicious"}, table()).set_index("Value")
    assert found.loc["45.248.77.91", "VPNDB"] == "VPN · nordvpn" and found.loc["45.248.77.91", "Shared Exit"]
    assert found.loc["93.184.216.34", "VPNDB"] == "" and not found.loc["93.184.216.34", "Shared Exit"]
    attributes = json.loads(to_misp_event(found.reset_index()))["Event"]["Attribute"]
    assert [a["to_ids"] for a in attributes] == [False, True]


def test_collection_checks_in_one_bulk_request_then_details_for_anonymizers(monkeypatch):
    calls = []
    monkeypatch.setattr(collector, "load_vpndb_key", lambda: "vpndb_test")
    monkeypatch.setattr(collector.anonymizers, "select_ips", lambda *args: CANDIDATES)
    monkeypatch.setattr(collector, "bulk_lookup", lambda ips: calls.append(ips) or FetchResult("VPNDB", "4", data=BULK,
                                                                                               record_count=4))
    monkeypatch.setattr(collector, "lookup_ip", lambda ip: calls.append(ip) or FetchResult("VPNDB", ip, data=DETAILS.get(ip, {})))
    log = collector.StatusLog()
    frame = collector.collect_anonymizers(["vpn.com"], [], pd.DataFrame(), {}, log)
    assert calls[0] == tuple(sorted(CANDIDATES)) and sorted(calls[1:]) == ["185.220.101.1", "45.248.77.91", "81.2.3.4"]
    assert len(frame) == 4 and len(log.rows) == 4
    monkeypatch.setattr(collector, "load_vpndb_key", lambda: None)
    assert collector.collect_anonymizers(["vpn.com"], [], pd.DataFrame(), {}, log).empty and len(calls) == 4


def test_ip_check_runs_only_vpndb_and_alerts_on_the_ip_targets(monkeypatch):
    from core.use_cases import BY_KEY, query_plan
    plan = query_plan(BY_KEY["ipcheck"].settings)
    assert [row["Source"] for row in plan] == ["VPNDB"]
    calls = []
    for name in ("collect_domain_history", "collect_certificates", "collect_enrichment", "collect_pdns",
                 "collect_cert_events", "collect_ct_telemetry"):
        monkeypatch.setattr(collector, name, lambda *args, name=name, **kwargs: calls.append(name))
    monkeypatch.setattr(collector, "load_vpndb_key", lambda: "vpndb_test")
    bulk = {"results": [BULK["results"][0], {"ip": "2001:db8::1", "anonymous": False, "note": "IPv6 not collected"}]}
    monkeypatch.setattr(collector, "bulk_lookup", lambda ips: calls.append(ips) or FetchResult("VPNDB", "2", data=bulk))
    monkeypatch.setattr(collector, "lookup_ip", lambda ip: calls.append(ip) or FetchResult("VPNDB", ip, data=DETAILS[ip]))
    data = collector.collect_all(["45.248.77.91", "2001:db8::1", "example.com"], "DNSDB Scout", 5000, vpndb_only=True)
    assert calls == [("45.248.77.91", "2001:db8::1"), "45.248.77.91"]   # no other source; IPv6 only in the bulk
    assert data.has_data and list(data.anonymizers["Domains"]) == ["45.248.77.91", "2001:db8::1"]
    assert tuple(data.anonymizers.iloc[1][["Category", "Note"]]) == ("Not checked", "IPv6 not collected")
    assert any("domain target(s) skipped" in row["Detail"] for row in data.statuses)
    alerts = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, anonymizers=data.anonymizers).alerts
    assert list(zip(alerts["Domain"], alerts["Threat Type"])) == [("45.248.77.91", "Domain on VPN / Proxy Exit")]


PREFIX = {"network": "104.21.59.0/24", "networkSize": 256, "observedIps": 12, "infrastructure": "DATACENTER",
          "attribution": [{"provider": "nordvpn", "weight": 0.75, "confidence": 2, "methods": ["probe"]},
                          {"provider": "surfshark", "weight": 0.25, "confidence": 1, "methods": ["probe"]}],
          "providerCount": 2, "singleTenant": False, "exact": True,
          "prefixes": {"contained": [], "covering": [{"prefix": "104.21.0.0/16"}]},
          "networks": [{"number": 13335, "organization": "Cloudflare", "addresses": 12}],
          "countries": {"origin": "dbip", "edition": "2026-09", "countries": [{"country": "US", "addresses": 256,
                                                                                "share": 1.0}]}}
ADDRESSES = {"network": "104.21.59.0/24", "addresses": [
    {"ip": "104.21.59.3", "providers": [{"provider": "nordvpn", "weight": 1, "days": 4, "lastSeen": "2026-10-30"}],
     "shared": False, "methods": ["wireguard"], "pool": "datacenter", "firstSeen": "2026-10-01",
     "lastSeen": "2026-10-30", "observations": 9}]}


def test_cidr_targets_are_recognized_and_kept_apart_from_single_ips():
    from core.cert_inputs import parse_inputs
    items = [(i.kind, i.value) for i in parse_inputs("104.21.59.7/24\n104[.]21[.]59[.]0/24 2a00:1450::/32\n8.8.8.8/32")]
    assert items == [("cidr", "104.21.59.0/24"), ("cidr", "2a00:1450::/32"), ("ip", "8.8.8.8")]


def test_cidr_ranges_go_to_vpndb_only(monkeypatch):
    seen = {}
    def record(key, value, returned):
        seen[key] = value
        return returned

    monkeypatch.setattr(collector, "collect_domain_history", lambda *a: (pd.DataFrame(), pd.DataFrame()))
    monkeypatch.setattr(collector, "collect_enrichment", lambda *a: {})
    monkeypatch.setattr(collector, "collect_cert_events", lambda *a: pd.DataFrame())
    monkeypatch.setattr(collector, "collect_certificates", lambda targets, *a: record("certs", targets, pd.DataFrame()))
    monkeypatch.setattr(collector, "collect_pdns", lambda targets, *a: record("pdns", targets, (pd.DataFrame(), {})))
    monkeypatch.setattr(collector, "collect_anonymizers", lambda domains, ips, *a: record("ips", ips, pd.DataFrame()))
    monkeypatch.setattr(collector, "load_vpndb_key", lambda: "vpndb_test")
    monkeypatch.setattr(collector, "lookup_prefix", lambda cidr: FetchResult("VPNDB", cidr, data=PREFIX, record_count=1))
    monkeypatch.setattr(collector, "prefix_addresses", lambda cidr, **kw: record(
        "addresses", (cidr, kw), FetchResult("VPNDB", cidr, data=ADDRESSES, record_count=1)))
    monkeypatch.setattr(collector, "bulk_lookup", lambda ips: record("bulk", ips, FetchResult("VPNDB", "256", data={
        "results": [{"ip": "104.21.59.3", "anonymous": True, "provider": "nordvpn", "types": ["VPN"], "method": "probe",
                     "confidence": 2}] + [{"ip": f"104.21.59.{n}", "anonymous": False} for n in (0, 1, 2)]})))
    data = collector.collect_all(["a.com", "8.8.8.8", "104.21.59.0/24"], "DNSDB Scout", 5000, include_ct=False,
                                 vpndb_check=True)
    assert seen["certs"] == seen["pdns"] == ["a.com", "8.8.8.8"] and seen["ips"] == ["8.8.8.8"]
    assert seen["addresses"] == ("104.21.59.0/24", {"method": "observed", "size": 200, "max_pages": 1})
    row = data.prefixes.iloc[0]
    assert (row["CIDR"], row["Top Provider"], row["Known Exits"], row["Coverage"], row["ASN"]) == \
        ("104.21.59.0/24", "nordvpn", 12, "4.7%", 13335)
    assert row["Providers"] == "nordvpn 75% (Medium), surfshark 25% (Low)" and row["Covering Prefix"] == "104.21.0.0/16"
    assert list(data.prefix_addresses["IP"]) == ["104.21.59.3"] and data.prefix_addresses.iloc[0]["Category"] == "VPN"
    assert any("VPNDB only" in r["Detail"] for r in data.statuses)

    assert len(seen["bulk"]) == 256 and seen["bulk"][0] == "104.21.59.0"   # every address of the range, one request
    assert list(data.range_ips["CIDR"].unique()) == ["104.21.59.0/24"] and len(data.range_ips) == 4
    from views.anonymizer_view import range_ip_table
    table = range_ip_table(data.range_ips, data.prefix_addresses, "104.21.59.0/24")
    first = table.iloc[0]
    assert (first["IP"], first["Category"], first["Tunnel"], first["Pool"]) == ("104.21.59.3", "VPN", "wireguard",
                                                                               "datacenter")


def _verdicts(rows):
    """A VPNDB table from {ip: (domains, category fields)} without the bulk round trip."""
    base = dict.fromkeys(anonymizers.COLUMNS, "")
    return pd.DataFrame([{**base, "IP": ip, "Domains": domains, **fields} for ip, (domains, fields) in rows.items()],
                        columns=anonymizers.COLUMNS)


def _a(domain, ip, day):
    return {"Domain": domain, "Date": pd.Timestamp(day), "Field": "A", "Value": ip}


def test_dedicated_rotating_moved_and_shared_exit_rules():
    vpn = {"Category": "VPN", "Confidence": "High"}
    table = _verdicts({
        "1.1.1.10": ("moved.com", {"Category": "Not observed"}),
        "45.0.0.1": ("moved.com, twin.com", {**vpn, "Provider": "nordvpn", "Sharing": "LOW", "IOC Value": "HIGH"}),
        "45.0.0.2": ("rotor.com", {**vpn, "Provider": "nordvpn", "Sharing": "HIGH", "IOC Value": "LOW"}),
        "45.0.0.3": ("rotor.com", {**vpn, "Provider": "mullvad", "Sharing": "HIGH", "IOC Value": "LOW"}),
        "45.0.0.4": ("rotor.com", {"Category": "Residential proxy", "Provider": "rayobyte", "Confidence": "Medium"}),
    })
    events = pd.DataFrame([_a("moved.com", "1.1.1.10", "2026-01-01"), _a("moved.com", "45.0.0.1", "2026-09-01"),
                           _a("twin.com", "45.0.0.1", "2026-09-02")]
                          + [_a("rotor.com", f"45.0.0.{n}", "2026-10-01") for n in (2, 3, 4)])
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table).alerts
    fired = {(r["Domain"], r["Threat Type"]): r for r in alerts.to_dict("records")}
    assert ("moved.com", "Domain on Dedicated Anonymizer Exit") in fired
    assert ("rotor.com", "Domain on Dedicated Anonymizer Exit") not in fired       # shared exits only
    moved = fired[("moved.com", "Hosting Moved onto Anonymizer Exit")]
    assert "1.1.1.10" in moved["Triggering IOCs"] and "2026-09-01" in moved["Threat Logic"]
    assert ("twin.com", "Hosting Moved onto Anonymizer Exit") not in fired          # never had other hosting
    rotation = fired[("rotor.com", "Domain Rotates Across Anonymizer Exits")]
    assert rotation["Confidence"] == "High" and "mullvad, nordvpn, rayobyte" in rotation["Threat Logic"]
    shared = fired[("moved.com", "Anonymizer Exit Shared by Analyzed Domains")]
    assert "twin.com" in shared["Threat Logic"] and shared["Confidence"] == "High"
    assert ("twin.com", "Anonymizer Exit Shared by Analyzed Domains") in fired
    assert not any(t == "Anonymizer Exit Shared by Analyzed Domains" and d == "rotor.com" for d, t in fired)


def test_new_domain_on_exit_needs_both_a_recent_registration_and_an_exit():
    table = _verdicts({"45.0.0.1": ("fresh.com", {"Category": "Tor", "Tor": "Exit (current)"})})
    events = pd.DataFrame([_a("fresh.com", "45.0.0.1", "2026-10-30")])
    created = (pd.Timestamp.now(tz="UTC") - pd.Timedelta(days=3)).strftime("%Y-%m-%d")
    enrichment = {"fresh.com": {"domain": "fresh.com", "create_date": {"value": created}}}
    alerts = detect_threat_flags(events, {"risk_score": 0}, enrichment_data=enrichment, anonymizers=table).alerts
    assert "Newly Registered Domain on Anonymizer Exit" in set(alerts["Threat Type"])
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table).alerts
    assert "Newly Registered Domain on Anonymizer Exit" not in set(alerts["Threat Type"])


def test_profile_and_summary_show_each_domains_vpndb_verdicts():
    from views.anonymizer_view import domain_verdict_text
    from views.profile_view import domain_vpndb
    from views.summary_view import domain_overview
    rows = domain_vpndb(table(), "vpn.com", {"45.248.77.91"}, {"45.248.77.91", "8.8.8.8"})
    assert list(rows["IP"]) == ["45.248.77.91"] and rows.iloc[0]["Seen In"] == "Iris (now) + passive DNS"
    assert domain_vpndb(table(), "vpn.com", set(), set()).iloc[0]["Seen In"] == "passive DNS (before the window)"
    assert domain_verdict_text(table(), "vpn.com") == "1 of 1 IPs: VPN nordvpn"
    assert domain_verdict_text(table(), "clean.com") == "0 of 1 IPs" and domain_verdict_text(table(), "x.com") == ""
    profiles = pd.DataFrame([{"Domain": "vpn.com", "Unified Risk": 50}])
    assert domain_overview(profiles, pd.DataFrame(), anonymizers=table()).iloc[0]["VPNDB"] == "1 of 1 IPs: VPN nordvpn"
    assert "VPNDB" not in domain_overview(profiles, pd.DataFrame())


def _iris(domain, ip, asn, country, count):
    return {"domain": domain, "ip": [{"address": {"value": ip, "count": count}, "asn": [{"value": asn}],
                                      "isp": {"value": "Host"}, "country_code": {"value": country}}]}


def test_exit_alerts_need_the_ip_to_have_been_an_exit_while_the_domain_used_it():
    table = _verdicts({"45.0.0.1": ("old.com, live.com", {"Category": "VPN", "Provider": "nordvpn",
                                                          "Confidence": "High"})})
    events = pd.DataFrame([{**_a("old.com", "45.0.0.1", "2025-01-01"), "Last Seen": pd.Timestamp("2025-02-01")},
                           {**_a("live.com", "45.0.0.1", "2026-09-01"), "Last Seen": pd.Timestamp("2026-10-20")}])
    weeks = anonymizers.exit_week_rows({"45.0.0.1": {"weeks": [
        {"week": "2026-09-07", "status": "probe", "providers": [{"provider": "nordvpn", "weight": 1}]},
        {"week": "2026-09-14", "status": "none", "providers": []}]}})
    assert list(weeks["Status"]) == ["probe"]   # weeks without evidence are dropped
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table,
                                 vpndb_context={"exit_weeks": weeks}).alerts
    fired = set(zip(alerts["Domain"], alerts["Threat Type"]))
    assert ("live.com", "Domain on VPN / Proxy Exit") in fired
    assert ("old.com", "Domain on VPN / Proxy Exit") not in fired   # the address became an exit after old.com left
    live = alerts[(alerts["Domain"] == "live.com") & (alerts["Threat Type"] == "Domain on VPN / Proxy Exit")].iloc[0]
    assert "exit while the domain used it: 1 week(s), 2026-09-07" in live["Triggering IOCs"]
    old_only = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table).alerts   # no history: both alert
    assert ("old.com", "Domain on VPN / Proxy Exit") in set(zip(old_only["Domain"], old_only["Threat Type"]))


def test_iris_crosscheck_rates_pivots_and_flags_disagreements():
    enrichment = {"vpn.com": _iris("vpn.com", "45.248.77.91", 9009, "nl", 4200),
                  "home.com": _iris("home.com", "81.2.3.4", 1234, "us", 12)}
    frame = anonymizers.crosscheck(table(), enrichment).set_index("IP")
    assert frame.loc["45.248.77.91", "Pivot Value"] == "Noise: shared exit"
    assert frame.loc["45.248.77.91", "Disagreement"] == "network AS9009 vs AS136787; country NL vs US"
    assert frame.loc["81.2.3.4", "Pivot Value"] == "Strong pivot" and frame.loc["81.2.3.4", "Iris Domains"] == 12


def test_neighbour_ranges_networks_and_reverse_ip_rows():
    checked = _verdicts({"93.1.2.3": ("a.com", {"Category": "Not observed"}),
                         "93.1.2.9": ("b.com", {"Category": "Not observed"}), "2001:db8::1": ("a.com", {})})
    ranges = anonymizers.neighbour_cidrs(checked)
    assert list(ranges) == ["93.1.2.0/24"] and ranges["93.1.2.0/24"]["domains"] == {"a.com", "b.com"}
    frame = anonymizers.neighbour_frame({"93.1.2.0/24": {"observedIps": 12, "networkSize": 256, "singleTenant": True,
                                                         "attribution": [{"provider": "mullvad", "weight": 1}]}},
                                        ranges)
    assert frame.iloc[0][["Known Exits", "Top Provider", "Coverage"]].tolist() == [12, "mullvad", "4.7%"]
    asns = anonymizers.hosting_asns({"a.com": _iris("a.com", "93.1.2.3", 39351, "se", 3)}, ["a.com"])
    networks = anonymizers.asn_frame({39351: {"organization": "31173 Services", "observedIps": 900,
                                              "singleTenant": True, "attribution": [{"provider": "mullvad"}],
                                              "collateral": {"nonAnonymousShare": 0.02}}}, asns)
    assert networks.iloc[0][["ASN", "Top Provider", "Non-anonymous Share", "Domains"]].tolist() == \
        [39351, "mullvad", "2%", "a.com"]
    dnsdb = pd.DataFrame([{"RRName": "www.other.net.", "First Seen": pd.Timestamp("2026-01-01"),
                           "Last Seen": pd.Timestamp("2026-10-01")},
                          {"RRName": "a.com.", "First Seen": None, "Last Seen": pd.Timestamp("2026-09-01")}])
    names = anonymizers.exit_neighbour_rows({"45.0.0.1": dnsdb}, ["a.com"]).set_index("Name")
    assert names.loc["www.other.net", "Domain"] == "other.net" and not names.loc["www.other.net", "Analyzed"]
    assert names.loc["a.com", "Analyzed"]


def test_hosted_among_exits_rule():
    table = _verdicts({"93.1.2.3": ("a.com", {"Category": "Not observed"})})
    ranges = anonymizers.neighbour_frame({"93.1.2.0/24": {"observedIps": 12, "networkSize": 256, "singleTenant": True,
                                                          "attribution": [{"provider": "mullvad", "weight": 1}]}},
                                         anonymizers.neighbour_cidrs(table))
    events = pd.DataFrame([_a("a.com", "93.1.2.3", "2026-10-01")])
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table,
                                 vpndb_context={"neighbour_ranges": ranges}).alerts
    hit = alerts[alerts["Threat Type"] == "Hosted Among Anonymizer Exits"].iloc[0]
    assert hit["Confidence"] == "Medium" and "93.1.2.0/24: 12 known exit(s)" in hit["Triggering IOCs"]


def test_context_collection_looks_up_history_ranges_networks_and_dedicated_exits(monkeypatch):
    calls = []
    monkeypatch.setattr(collector, "load_vpndb_key", lambda: "k")
    monkeypatch.setattr(collector, "load_dnsdb_key", lambda: "k")
    monkeypatch.setattr(collector, "ip_history", lambda ip: calls.append(("history", ip)) or FetchResult(
        "VPNDB", ip, data={"weeks": [{"week": "2026-10-05", "status": "probe", "providers": []}]}))
    monkeypatch.setattr(collector, "lookup_prefix", lambda cidr: calls.append(("prefix", cidr)) or FetchResult(
        "VPNDB", cidr, data={"observedIps": 3, "networkSize": 256}))
    monkeypatch.setattr(collector, "lookup_asn", lambda asn: calls.append(("asn", asn)) or FetchResult(
        "VPNDB", asn, data={"observedIps": 0}))
    monkeypatch.setattr(collector, "fetch_dnsdb_history", lambda ip, limit: calls.append(("dnsdb", ip)) or FetchResult(
        "DNSDB", ip, data=[{"rrname": "x.evil.net.", "rrtype": "A", "rdata": [ip], "time_first": 1, "time_last": 2}]))
    checked = table().copy()
    checked.loc[checked["IP"] == "81.2.3.4", "Sharing"] = "LOW"   # a dedicated residential exit
    weeks, ranges, networks, names = collector.collect_anonymizer_context(
        checked, ["home.com"], {"home.com": _iris("home.com", "81.2.3.4", 1234, "us", 2)}, StatusLog())
    assert {c[0] for c in calls} == {"history", "prefix", "asn", "dnsdb"}
    assert ("prefix", "93.184.216.0/24") in calls and ("dnsdb", "81.2.3.4") in calls
    assert len(weeks) == 3 and list(ranges["CIDR"]) == ["93.184.216.0/24"] and list(networks["ASN"]) == [1234]
    assert list(names["Domain"]) == ["evil.net"]


def test_a_hoster_with_one_proxy_exit_is_not_a_vpn_network():
    table = _verdicts({"45.150.167.82": ("x.cc", {"Category": "Not anonymous"})})
    enrichment = {"x.cc": _iris("x.cc", "45.150.167.82", 201106, "us", 155752)}
    asns = anonymizers.hosting_asns(enrichment, ["x.cc"])

    def alerts(exits):
        networks = anonymizers.asn_frame({201106: {"organization": "Spartan Host Ltd", "observedIps": exits,
                                                   "singleTenant": True, "attribution": [{"provider": "shifter"}]}}, asns)
        found = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, enrichment_data=enrichment, anonymizers=table,
                                    vpndb_context={"hosting_asns": networks}).alerts
        return set(found["Threat Type"]) if not found.empty else set()
    assert "Hosted Among Anonymizer Exits" not in alerts(1)
    assert "Hosted Among Anonymizer Exits" in alerts(400)


def test_vpndb_lookups_keep_their_request_and_answer(monkeypatch):
    monkeypatch.setattr(collector, "load_vpndb_key", lambda: "k")
    monkeypatch.setattr(collector, "bulk_lookup", lambda ips: FetchResult("VPNDB", f"{len(ips)} IP(s)", data=BULK,
                                                                          record_count=4))
    monkeypatch.setattr(collector, "lookup_ip", lambda ip: FetchResult("VPNDB", ip, data=DETAILS.get(ip, {}),
                                                                       record_count=1))
    monkeypatch.setattr(collector.anonymizers, "select_ips", lambda *args: CANDIDATES)
    log = StatusLog()
    collector.collect_anonymizers(["vpn.com"], [], pd.DataFrame(), {}, log, max_details=1)
    assert [r["Request"]["endpoint"] for r in log.rows] == ["/bulk", "/ip/{ip}"]   # one full verdict: the budget
    assert log.rows[0]["Request"]["body"]["ips"] == sorted(CANDIDATES)
    raw = collector.vpndb_raw_frame(log.raw)
    assert list(raw["Endpoint"]) == ["/bulk", "/ip/{ip}"] and json.loads(raw.iloc[0]["Response"])["total"] == 4

    from core.lookup_queries import build_lookup_queries
    from integrations.collector import CollectedData
    monkeypatch.setattr("core.lookup_queries.vpndb_base_url", lambda: "https://vpndb.test/api/v1")
    queries = build_lookup_queries(CollectedData(statuses=log.rows + [
        {"Source": "VPNDB", "Target": "45.248.77.0/24", "Status": "OK", "Records": 1, "Detail": ""}]))
    vpndb = queries[queries["Tool"] == "VPNDB"].set_index("Search")
    assert vpndb.loc["POST /bulk", "Query"].split("\n") == sorted(CANDIDATES)
    assert vpndb.loc["POST /bulk", "Command"].startswith("curl -s -X POST -H \"Authorization: Bearer $VPNDB_API_KEY\"")
    assert vpndb.loc["GET /ip/{ip}", "Command"].endswith("https://vpndb.test/api/v1/ip/45.248.77.91")
    assert vpndb.loc["GET /prefix/{cidr}", "Query"] == "/prefix/45.248.77.0/24"   # an older row: read from target
    assert vpndb.loc["GET /prefix/{cidr}", "Command"].endswith("/prefix/45.248.77.0%2F24")


def test_raw_vpndb_answers_are_shown_as_tables():
    from views.raw_view import response_tables
    tables = response_tables(BULK)
    assert list(tables) == ["Fields", "results"] and len(tables["results"]) == 4
    assert dict(zip(tables["Fields"]["Field"], tables["Fields"]["Value"]))["total"] == "4"
    detail = response_tables(DETAILS["45.248.77.91"])
    fields = dict(zip(detail["Fields"]["Field"], detail["Fields"]["Value"]))
    assert fields["sharing.level"] == "HIGH" and fields["asn.number"] == "136787"
    assert list(detail["attribution"]["provider"]) == ["nordvpn"]


def test_every_use_case_checks_vpndb_within_its_own_budget():
    from core.use_cases import USE_CASES, effective_settings, query_plan
    budgets = {case.key: effective_settings(case) for case in USE_CASES}
    assert all(s["opt_vpndb"] for s in budgets.values())
    assert not any(s["opt_vpndb_only"] for key, s in budgets.items() if key != "ipcheck")
    assert budgets["infrastructure"]["opt_vpndb_max_ips"] == 500 and budgets["triage"]["opt_vpndb_max_ips"] == 100
    assert not budgets["phishing"]["opt_vpndb_context"] and budgets["c2"]["opt_vpndb_context"]
    plan = {row["Key"]: row for row in query_plan(budgets["takeover"])}
    assert plan["vpndb"]["Limit"].startswith("100 IPs per run") and "DNSDB" not in plan["vpndb"]["Lookup"]


TOR = {"relaysPublished": "2026-11-03 12:00", "counts": {"relays": 9000, "exitRelays": 1500},
       "concentration": {"top5Networks": 0.41, "top10Networks": 0.55},
       "exitNetworks": [{"asn": 60729, "organization": "Zwiebelfreunde", "exitAddresses": 120, "exitRelays": 140,
                         "exitShare": 0.081}, {"asn": 136787, "organization": "PacketHub", "exitAddresses": 2,
                                               "exitRelays": 2, "exitShare": 0.001}],
       "exitCountries": [{"country": "DE", "exitAddresses": 400, "exitRelays": 450, "exitShare": 0.3}],
       "exitPrefixes": [{"prefix": "185.220.101.0/24", "asn": 60729, "exitAddresses": 60, "exitRelays": 70,
                         "exitShare": 0.04, "reachedVia": []}]}


def test_tor_overview_places_an_ip_in_the_tor_network(monkeypatch):
    tables = anonymizers.tor_tables(TOR)
    assert list(tables["Networks"]["asn"]) == [60729, 136787] and tables["Networks"].iloc[0]["Exit share %"] == 8.1
    context = dict(anonymizers.tor_context(TOR, "185.220.101.1", 60729, "de"))
    assert set(context) == {"Network", "Prefix", "Country"} and "8.10% of all Tor exit traffic" in context["Network"]
    assert anonymizers.tor_context(TOR, "8.8.8.8", 15169, "US") == []

    monkeypatch.setattr(collector, "load_vpndb_key", lambda: "k")
    monkeypatch.setattr(collector, "tor_overview", lambda: FetchResult("VPNDB", "tor", data=TOR, record_count=1))
    log = StatusLog()
    assert collector.collect_tor_overview(log)["counts"]["relays"] == 9000
    assert log.rows[0]["Request"]["endpoint"] == "/tor" and log.raw[0]["Response"] is TOR


def test_the_ip_card_reads_the_runs_answers_first(monkeypatch):
    from views import ip_card
    raw = collector.vpndb_raw_frame([{"Source": "VPNDB", "Target": "45.248.77.91", "Status": "OK", "Records": 1,
                                      "Request": {"endpoint": "/ip/{ip}"}, "Response": DETAILS["45.248.77.91"]}])

    class Ds:
        vpndb_raw = raw
    monkeypatch.setattr(ip_card.st, "session_state", {ip_card.FETCHED_KEY: {"81.2.3.4": {"verdict": {"ip": "81.2.3.4"}}}})
    assert ip_card._raw_answer(Ds, "/ip/{ip}", "45.248.77.91")["sharing"]["level"] == "HIGH"
    assert ip_card._raw_answer(Ds, "/ip/{ip}", "81.2.3.4") == {"ip": "81.2.3.4"}   # fetched from the card
    assert ip_card._raw_answer(Ds, "/ip/{ip}/history", "45.248.77.91") is None


def _tor_row(**fields):
    return {"Category": "Tor", "Tor": "Exit (current)", "Tor Exit First Seen": "2025-01-01", "Tor Exit Last Seen": "",
            "Tor Exit Current": True, **fields}


def test_tor_alerts_are_time_aware_and_rate_exits_above_relays():
    table = _verdicts({"185.220.101.1": ("live.com, old.com", _tor_row(
        **{"Tor Exit First Seen": "2026-06-01", "Tor Relays": "relay1 (exit: Exit, Fast; since 2026-06-01)",
           "Tor Exit Probability": 0.0012, "Tor Family": 12})),
        "95.216.1.1": ("guard.com", {"Category": "Tor", "Tor": "Relay (guard)",
                                     "Tor Relays": "g1 (guard: Guard, Stable; since 2024-01-01)"})})
    events = pd.DataFrame([{**_a("old.com", "185.220.101.1", "2025-01-01"), "Last Seen": pd.Timestamp("2025-03-01")},
                           {**_a("live.com", "185.220.101.1", "2026-09-01"), "Last Seen": pd.Timestamp("2026-10-01")},
                           _a("guard.com", "95.216.1.1", "2026-09-01")])
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table).alerts
    tor = alerts[alerts["Threat Type"] == "Domain on Tor Relay / Exit Node"].set_index("Domain")
    assert "old.com" not in tor.index   # it used the IP before the address exited Tor traffic
    assert tor.loc["live.com", "Severity"] == "High" and tor.loc["guard.com", "Severity"] == "Medium-High"
    assert "operator family of 12 relays" in tor.loc["live.com", "Triggering IOCs"]
    assert "0.120% of Tor exit traffic" in tor.loc["live.com", "Triggering IOCs"]


def test_hosted_among_tor_exits_uses_the_tor_overview():
    table = _verdicts({"185.220.101.77": ("near.com", {"Category": "Not observed", "ASN": 60729}),
                       "93.1.2.3": ("net.com", {"Category": "Not anonymous", "ASN": 60729}),
                       "8.8.8.8": ("clean.com", {"Category": "Not anonymous", "ASN": 15169})})
    events = pd.DataFrame([_a("near.com", "185.220.101.77", "2026-10-01"), _a("net.com", "93.1.2.3", "2026-10-01"),
                           _a("clean.com", "8.8.8.8", "2026-10-01")])
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=table,
                                 vpndb_context={"tor_overview": TOR}).alerts
    hits = alerts[alerts["Threat Type"] == "Hosted Among Tor Exits"].set_index("Domain")
    assert hits.loc["near.com", "Confidence"] == "Medium" and "Tor exit prefix 185.220.101.0/24" in \
        hits.loc["near.com", "Triggering IOCs"]
    assert hits.loc["net.com", "Confidence"] == "Low" and "clean.com" not in hits.index


def test_tor_fields_come_from_the_verdict():
    fields = anonymizers.tor_fields(DETAILS["185.220.101.1"]["tor"])
    assert fields["Tor Exit Current"] and fields["Tor Relays"] == "n (exit; since 2025-01-01)"
    assert fields["Tor Exit Probability"] == 0.01 and fields["Tor Family"] is None


def test_tor_columns_left_empty_in_a_table_do_not_break_the_rules():
    rows = table()   # a residential proxy without Tor data next to a Tor relay with a family: NaN in the column
    rows["Tor Family"] = pd.to_numeric(rows["Tor Family"], errors="coerce")
    rows.loc[rows["IP"] == "185.220.101.1", "Tor Family"] = 5.0
    events = pd.DataFrame([_a("home.com", "81.2.3.4", "2026-10-01")])
    alerts = detect_threat_flags(events, {"risk_score": 0}, anonymizers=rows).alerts
    assert "Domain on Residential Proxy Exit" in set(alerts["Threat Type"])
    assert "operator family" not in alerts.iloc[0]["Triggering IOCs"]

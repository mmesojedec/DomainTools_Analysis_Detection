import json

import pandas as pd
import pytest

from core.correlation import build_ip_observations, collect_artifacts, correlate, detect_domain_hops
from core.export import _stix_pattern, to_stix_bundle
from core.lookalike import analyze_lookalike, edit_distance, parse_brand_list, parse_official_domains, skeleton
from core.network_intel import build_ip_intel, cdn_for_ip, cdn_fronting, find_origin_candidates, network_key
from core.persistence import (
    add_suppression,
    apply_suppressions,
    load_suppressions,
    new_alert_mask,
    remove_suppression,
)
from core.run_history import diff_artifacts
from core.threat_detection import detect_threat_flags
from core.timeline import build_domain_timeline
from integrations.enrichment import extract_iris_profile
from visualizations.network_graph import build_graph_elements, force_layout


def iris(domain, ips=(), create=None, ns=(), redirect=None, ga4=None):
    obj = {"domain": domain,
           "ip": [{"address": {"value": ip}, "asn": [{"value": asn}], "isp": {"value": isp}, "country_code": {"value": cc}}
                  for ip, asn, isp, cc in ips],
           "name_server": [{"host": {"value": h}} for h in ns]}
    if create:
        obj["create_date"] = {"value": create}
    if redirect:
        obj["redirect_domain"] = {"value": redirect}
    if ga4:
        obj["ga4"] = [{"value": ga4}]
    return obj


def events(rows):
    df = pd.DataFrame(rows)
    df["Date"] = pd.to_datetime(df["Date"], format="mixed")
    if "Last Seen" in df.columns:
        df["Last Seen"] = pd.to_datetime(df["Last Seen"], format="mixed")
    return df


def types(result):
    return set(result.alerts["Threat Type"]) if not result.alerts.empty else set()


# --- Iris profile & network intel -----------------------------------------------------------------

def test_extract_iris_profile():
    profile = extract_iris_profile(iris("a.com", ips=[("1.2.3.4", 13335, "Cloudflare, Inc.", "us")], create="2024-05-01",
                                        ns=["Ns1.Example.NET."], redirect="Other.com"))
    assert profile["ips"] == [{"ip": "1.2.3.4", "count": None, "asn": 13335, "isp": "Cloudflare, Inc.", "country": "US"}]
    assert profile["create_date"] == pd.Timestamp("2024-05-01")
    assert profile["name_servers"] == ["ns1.example.net"] and profile["redirect_domain"] == "other.com"
    assert extract_iris_profile(None)["ips"] == []


def test_cdn_detection_and_network_keys():
    assert cdn_for_ip("104.16.1.1") == "Cloudflare"
    assert cdn_for_ip("2606:4700::1") == "Cloudflare"
    assert cdn_for_ip("151.101.1.1") == "Fastly"
    assert cdn_for_ip("8.8.8.8") is None
    intel = build_ip_intel({"a.com": iris("a.com", ips=[("9.9.9.9", 19281, "Akamai Technologies", "us")])})
    assert cdn_for_ip("9.9.9.9", intel) == "Akamai"
    assert network_key("9.9.9.9", intel) == "AS19281"
    assert network_key("5.6.7.8") == "net:5.6.0.0/16"


def test_cdn_fronting_and_origin_candidates():
    profile = extract_iris_profile(iris("a.com", ips=[("104.16.1.1", 13335, "Cloudflare", "us")]))
    ev = events([
        {"Domain": "a.com", "RRName": "a.com", "Date": "2023-01-01", "Field": "A", "Value": "45.33.12.10"},
        {"Domain": "a.com", "RRName": "a.com", "Date": "2024-01-01", "Field": "A", "Value": "104.16.1.1"},
        {"Domain": "a.com", "RRName": "a.com", "Date": "2024-01-01", "Field": "A", "Value": "10.0.0.5"},
    ])
    assert cdn_fronting("a.com", ev, profile, {}) == "Cloudflare"
    candidates = find_origin_candidates("a.com", ev, pd.DataFrame(), {})
    assert list(candidates["IP"]) == ["45.33.12.10"]  # CDN and private IPs excluded


# --- Lookalikes ---------------------------------------------------------------------------------------

def test_brand_parsing():
    assert parse_brand_list("PayPal, acme.co.uk\nabc") == ("paypal", "acme")
    assert parse_official_domains("paypal\nacme.co.uk") == ("acme.co.uk",)


def test_lookalike_primitives():
    assert edit_distance("paypal", "paypa1") == 1
    assert edit_distance("paypal", "papyal") == 1  # transposition
    assert skeleton("pаypal") == "paypal"  # Cyrillic а
    assert skeleton("xn--pypal-4ve") == "paypal"


@pytest.mark.parametrize("host, expected", [
    ("paypa1.com", "Homoglyph / IDN Brand Impersonation"),
    ("paypall.com", "Typosquatting Lookalike"),
    ("paypal-login-secure.com", "Combosquatting (Brand + Keyword)"),
    ("paypal.secure-billing.net", "Brand in Subdomain"),
    ("paypal.net", "Brand Name on Alternate TLD"),
])
def test_lookalike_findings(host, expected):
    assert expected in {f["type"] for f in analyze_lookalike(host, ("paypal",))}


def test_lookalike_ignores_official_and_unrelated():
    assert analyze_lookalike("paypal.com", ("paypal",)) == []
    assert analyze_lookalike("acme.co.uk", ("acme",), ("acme.co.uk",)) == []
    assert analyze_lookalike("weather.com", ("paypal",)) == []


# --- New engine rules ---------------------------------------------------------------------------------

def test_newly_registered_and_weaponized():
    created = (pd.Timestamp.now() - pd.Timedelta(days=5)).strftime("%Y-%m-%d")
    enrichment = {"a.com": iris("a.com", create=created)}
    ssl = pd.DataFrame([{"Domain": "a.com", "Hash": "h", "Common Name": "a.com", "Issuer": "R3", "Alt Names List": ["a.com"],
                         "Not Before Date": pd.Timestamp.now() - pd.Timedelta(days=4)}])
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl, enrichment_data=enrichment)
    assert "Newly Registered & Weaponized Domain" in types(result)
    old = detect_threat_flags(pd.DataFrame(), {}, enrichment_data={"a.com": iris("a.com", create="2010-01-01")})
    assert not ({"Newly Registered Domain", "Newly Registered & Weaponized Domain"} & types(old))


def test_hosting_watchlist_and_redirect():
    enrichment = {"a.com": iris("a.com", ips=[("198.51.100.1", 44477, "Stark Industries Solutions", "nl")], redirect="landing.net")}
    result = detect_threat_flags(pd.DataFrame(), {}, enrichment_data=enrichment)
    assert {"High-Abuse / Offshore Hosting Provider", "Cross-Domain Redirect"} <= types(result)


def test_parking_and_parking_exit():
    ev = events([
        {"Domain": "a.com", "Date": "2023-01-01", "Last Seen": "2024-01-01", "Field": "NS", "Value": "ns1.sedoparking.com\nns2.sedoparking.com"},
        {"Domain": "a.com", "Date": "2024-02-01", "Field": "NS", "Value": "ns1.evilhost.net"},
        {"Domain": "a.com", "Date": "2024-02-02", "Field": "A", "Value": "45.33.12.5"},
    ])
    result = detect_threat_flags(ev, {})
    assert {"Parked Domain (Parking Name Servers)", "Parking Exit / Reactivation"} <= types(result)


def test_fast_flux_on_cdn_is_low_confidence_and_multi_network_flux():
    cdn = events([{"Domain": "a.com", "Date": f"2024-01-0{i + 1}", "Field": "A", "Value": f"104.16.0.{i}"} for i in range(6)])
    alerts = detect_threat_flags(cdn, {"flux_ips": 5}).alerts.set_index("Threat Type")
    assert alerts.loc["Rapid IP Rotation (Fast-Flux)", "Confidence"] == "Low"
    assert "Multi-Network Fast-Flux (ASN-Diverse)" not in alerts.index

    spread = events([{"Domain": "b.com", "Date": f"2024-01-0{i + 1}", "Field": "A", "Value": f"{10 + i * 20}.1.1.1"} for i in range(6)])
    result = detect_threat_flags(spread, {"flux_ips": 5, "flux_networks": 3})
    assert "Multi-Network Fast-Flux (ASN-Diverse)" in types(result)
    assert result.alerts.set_index("Threat Type").loc["Rapid IP Rotation (Fast-Flux)", "Confidence"] == "Medium"


def test_volume_anomaly():
    rows = [{"Domain": "a.com", "Date": f"2024-01-{d:02d}", "Field": "A", "Value": "45.33.12.1", "Count": 100 + d} for d in range(1, 15)]
    rows.append({"Domain": "a.com", "Date": "2024-01-20", "Field": "A", "Value": "45.33.12.2", "Count": 50000})
    assert "Query Volume Anomaly" in types(detect_threat_flags(events(rows), {}))


def test_origin_exposure_rule():
    enrichment = {"a.com": iris("a.com", ips=[("104.16.1.1", 13335, "Cloudflare", "us")])}
    ev = events([{"Domain": "a.com", "RRName": "a.com", "Date": "2022-01-01", "Field": "A", "Value": "45.33.12.10"}])
    assert "Potential Origin IP Exposure (Behind CDN)" in types(detect_threat_flags(ev, {}, enrichment_data=enrichment))


def test_lookalike_rule_via_engine():
    result = detect_threat_flags(pd.DataFrame(), {}, enrichment_data={"paypa1.com": iris("paypa1.com")}, brands=("paypal",))
    assert "Homoglyph / IDN Brand Impersonation" in types(result)


def test_alerts_have_confidence_and_category():
    ev = events([{"Domain": "a.com", "Date": "2024-01-01", "Field": "MX", "Value": "mx.yandex.ru"}])
    row = detect_threat_flags(ev, {}).alerts.iloc[0]
    assert row["Confidence"] in ("High", "Medium", "Low") and row["Category"] == "Email"


# --- Correlation ----------------------------------------------------------------------------------------

def test_clusters_require_strong_or_two_weak_links():
    enrichment = {
        "a.com": iris("a.com", ips=[("45.33.12.7", 1, "Host", "us")], ga4="G-1"),
        "b.com": iris("b.com", ips=[("45.33.12.7", 1, "Host", "us")], ga4="G-1"),
        "c.com": iris("c.com", ips=[("45.33.12.7", 1, "Host", "us")]),
    }
    correlation = correlate(collect_artifacts(pd.DataFrame(), pd.DataFrame(), enrichment, {}))
    assert [c["Domains"] for c in correlation.clusters] == [["a.com", "b.com"]]  # c.com only shares a weak IP
    assert correlation.clusters[0]["Strength"] == "Strong"
    result = detect_threat_flags(pd.DataFrame(), {}, enrichment_data=enrichment)
    clustered = result.alerts[result.alerts["Threat Type"] == "Shared Infrastructure Cluster"]
    assert sorted(clustered["Domain"]) == ["a.com", "b.com"]


def test_cdn_ips_do_not_create_clusters():
    enrichment = {d: iris(d, ips=[("104.16.1.1", 13335, "Cloudflare", "us")], ns=["ns1.private-dns.org", "ns2.private-dns.org"]) for d in ("a.com", "b.com")}
    correlation = correlate(collect_artifacts(pd.DataFrame(), pd.DataFrame(), enrichment, {}))
    assert set(correlation.shared["Type"]) == {"Name Server"} and not correlation.clusters


def test_domain_hopping():
    pivots = pd.DataFrame([
        {"IP": "45.33.12.9", "RRName": "old-stream.com", "First Seen": pd.Timestamp("2024-01-01"), "Last Seen": pd.Timestamp("2024-03-01"), "Related": "target.com"},
        {"IP": "45.33.12.9", "RRName": "www.new-stream.com", "First Seen": pd.Timestamp("2024-03-05"), "Last Seen": pd.Timestamp("2024-05-01"), "Related": "target.com"},
        {"IP": "45.33.12.9", "RRName": "target.com", "First Seen": pd.Timestamp("2024-05-03"), "Last Seen": pd.Timestamp("2024-06-01"), "Related": "target.com"},
    ])
    hops = detect_domain_hops(build_ip_observations(pd.DataFrame(), pivots), hop_days=14)
    assert list(hops["To Domain"]) == ["new-stream.com", "target.com"]
    result = detect_threat_flags(pd.DataFrame(), {}, enrichment_data={"target.com": iris("target.com")}, ip_observations=pivots)
    assert "Domain Hopping on Shared IP" in types(result)


# --- Persistence ------------------------------------------------------------------------------------------

def test_suppressions_roundtrip(tmp_path):
    path = tmp_path / "supp.json"
    entry = add_suppression("a.com", "High-Risk Mail Provider", "known", path=path)
    add_suppression("*", "DGA / High Entropy Domain", path=path)
    assert len(load_suppressions(path)) == 2
    alerts = pd.DataFrame([{"Domain": "a.com", "Threat Type": "High-Risk Mail Provider"},
                           {"Domain": "b.com", "Threat Type": "High-Risk Mail Provider"},
                           {"Domain": "c.com", "Threat Type": "DGA / High Entropy Domain"}])
    active, suppressed = apply_suppressions(alerts, load_suppressions(path))
    assert list(active["Domain"]) == ["b.com"] and len(suppressed) == 2
    remove_suppression(entry["id"], path=path)
    assert len(load_suppressions(path)) == 1


def test_run_diff_and_new_alerts():
    diff = diff_artifacts({"a.com": {"IP": ["1.1.1.1"]}}, {"a.com": {"IP": ["2.2.2.2"]}, "b.com": {"Certificate": ["h"]}})
    assert set(zip(diff["Value"], diff["Change"])) == {("2.2.2.2", "Added"), ("1.1.1.1", "Removed"), ("h", "Added")}
    alerts = pd.DataFrame([{"Domain": "a.com", "Threat Type": "X", "Threat Logic": "old"}, {"Domain": "a.com", "Threat Type": "Y", "Threat Logic": "new"}])
    mask = new_alert_mask(alerts, {"alerts": [["a.com", "X", "old"]]})
    assert list(mask) == [False, True]


# --- Export, timeline, graph ------------------------------------------------------------------------------

def test_stix_bundle():
    iocs = pd.DataFrame([{"Type": "domain-name", "Value": "a.com", "Domain": "a.com", "Source": "Target", "First Seen": "", "Last Seen": "", "Note": ""},
                         {"Type": "x509-sha256", "Value": "ab" * 32, "Domain": "a.com", "Source": "Cert", "First Seen": "", "Last Seen": "", "Note": ""}])
    bundle = json.loads(to_stix_bundle(iocs, pd.DataFrame([{"Domain": "a.com", "Threat Type": "Typosquatting Lookalike"}])))
    kinds = [o["type"] for o in bundle["objects"]]
    assert kinds == ["identity", "indicator", "indicator", "report"]
    assert "Typosquatting Lookalike" in bundle["objects"][1]["description"]
    assert _stix_pattern("ipv6-addr", "2001:db8::1") == "[ipv6-addr:value = '2001:db8::1']"


def test_domain_timeline():
    from core.dataset import Dataset
    ds = Dataset(selected_domains=["a.com"], timezone="UTC", pdns_provider="DNSDB Scout",
                 enrichment={"a.com": iris("a.com", create="2024-01-01")},
                 pdns=events([{"Domain": "a.com", "RRName": "a.com", "Date": "2024-01-02", "Field": "A", "Value": "1.1.1.1\n2.2.2.2"}]),
                 ssl=pd.DataFrame([{"Domain": "a.com", "Hash": "h", "Issuer": "R3", "Not Before Date": pd.Timestamp("2024-01-03")}]))
    timeline = build_domain_timeline(ds, "a.com")
    assert list(timeline["Lane"]) == ["Registration", "DNS: A/AAAA", "DNS: A/AAAA", "Certificate Issued"]


def test_graph_elements_and_layout():
    artifacts = pd.DataFrame([("a.com", "IP", "1.1.1.1"), ("b.com", "IP", "1.1.1.1"), ("a.com", "IP", "2.2.2.2")],
                             columns=["Domain", "Type", "Value"])
    nodes, edges = build_graph_elements(artifacts, shared_only=True)
    assert set(nodes["label"]) == {"a.com", "b.com", "1.1.1.1"} and len(edges) == 2
    pos = force_layout(3, [(0, 2), (1, 2)])
    assert pos.shape == (3, 2) and abs(pos).max() <= 1.0 + 1e-9

"""IP and CIDR targets go to every source that takes addresses: DNSDB, certificates, BGPDB, Iris (no real request)."""
import pandas as pd

from core import bgp
from integrations import bgp_stage, collector
from integrations.certificates import build_search_queries, match_target_against_hit
from integrations.dnsdb import _lookup_urls
from integrations.http import FetchResult, StatusLog


def test_dnsdb_and_certificates_take_a_range():
    assert _lookup_urls("104.21.59.0/24") == ["https://api.dnsdb.info/dnsdb/v2/lookup/rdata/ip/104.21.59.0,24"]
    assert _lookup_urls("2001:db8::/32")[0].endswith("/rdata/ip/2001%3Adb8%3A%3A,32")
    queries = dict(build_search_queries(["104.21.59.0/24", "2001:db8::/126"]))
    assert queries["104.21.59.0/24"].endswith('san_ip_v4 between ["104.21.59.0", "104.21.59.255"]\n')
    assert '"2001:db8::", "2001:db8::3"' in queries["2001:db8::/126"]
    hit = {"san_ip_v4": ["104.21.59.7"], "subject_common_name": "x"}
    assert match_target_against_hit("104.21.59.0/24", hit) and not match_target_against_hit("104.21.60.0/24", hit)


def test_bgp_keeps_cdn_targets_and_looks_up_ranges():
    chosen = bgp.select_ips([], None, {}, ["104.21.59.7", "10.0.0.1"], cidr_targets=["104.21.59.0/24"])
    assert chosen == {"104.21.59.7": {"104.21.59.7"}, "104.21.59.0": {"104.21.59.0/24"}}   # CDN target kept, private not


def test_collect_bgp_looks_up_what_is_announced_inside_a_range(monkeypatch):
    calls = []
    record = {"prefix": "104.21.0.0/16", "origin": 13335, "first": 1, "last": 2, "count": 5, "collectors": 60,
              "rpki": "valid", "irr": "valid"}

    def query(command, argument, limit=None):
        calls.append((command, argument))
        data = {"ip": [record], "prefix": [{**record, "prefix": "104.21.59.0/24"}]}.get(command, [])
        return FetchResult("BGPDB", f"{command} {argument}", data=data, record_count=len(data))

    monkeypatch.setattr(bgp_stage.bgpdb, "load_bgpdb_host", lambda: "bgpdb.example")
    for name in ("lookup_ip", "lookup_route", "lookup_asn", "lookup_prefix"):
        command = name.removeprefix("lookup_")
        monkeypatch.setattr(bgp_stage.bgpdb, name, lambda arg, limit=None, hops=None, c=command: query(c, arg, limit))
    *_, neighbours, _ = bgp_stage.collect_bgp([], [], None, {}, StatusLog(), context=False,
                                             cidr_targets=["104.21.59.0/24"])
    assert ("ip", "104.21.59.0/24") in calls and ("prefix", "104.21.59.0/24") in calls   # covering route, then inside
    assert list(neighbours["Covering Range"]) == ["104.21.59.0/24"]


def test_iris_domains_on_targets(monkeypatch):
    def fetch(query, max_results, sort_by):
        if "less_than" in query:
            return FetchResult("Iris Investigate", "IrisQL", data=[], error="Maximum 10000 results exceeded")
        return FetchResult("Iris Investigate", "IrisQL", data=[{"domain": "bad.example", "domain_risk": {
            "risk_score": 90}}], record_count=1)

    monkeypatch.setattr(collector, "fetch_irisql", fetch)
    log = StatusLog()
    frame = collector.collect_target_domains(["192.0.2.7", "198.51.0.0/16"], log)
    assert list(frame["Target"]) == ["192.0.2.7"] and frame.iloc[0]["Domain"] == "bad.example"
    rows = pd.DataFrame(log.rows)
    assert list(rows["Target"]) == ["192.0.2.7", "198.51.0.0/16"]
    assert "more than 10,000 domains in 198.51.0.0/16" in rows.iloc[1]["Detail"]


def test_target_table_and_related_domains():
    from types import SimpleNamespace

    from core.address_targets import related_domains, target_table
    seen = pd.Timestamp("2026-11-01")
    ds = SimpleNamespace(
        pdns=pd.DataFrame({"Domain": ["104.21.59.0/24", "104.21.59.0/24", "a.com"],
                           "RRName": ["www.evil-site.com.", "mail.evil-site.com.", "a.com."], "Field": ["A"] * 3,
                           "Value": ["104.21.59.7"] * 3, "First Seen": [seen] * 3, "Last Seen": [seen] * 3,
                           "Count": [3, 1, 1]}),
        target_domains=pd.DataFrame({"Target": ["104.21.59.0/24", "104.21.59.0/24"], "Domain": ["low.example",
                                     "risky.example"], "Risk Score": [10, 95]}),
        ssl=pd.DataFrame({"Domain": ["104.21.59.0/24"], "Hash": ["ab"]}),
        bgp_origins=pd.DataFrame({"Domains": ["104.21.59.0/24"], "Prefix": ["104.21.0.0/16"], "Origin": ["AS13335"],
                                  "AS Name": ["CLOUDFLARENET"], "Status": ["Valid"], "Updates": [9]}),
        bgp_neighbours=pd.DataFrame({"Covering Range": ["104.21.59.0/24", "104.21.48.0/20"]}),
        anonymizers=pd.DataFrame(), prefixes=pd.DataFrame())
    row = target_table(ds, ["a.com", "104.21.59.0/24"]).iloc[0]
    assert (row["Target"], row["Kind"], row["Names in passive DNS"], row["Domains in Iris"], row["High-risk in Iris"],
            row["Certificates"], row["Origin"], row["Prefixes inside"]) == \
        ("104.21.59.0/24", "IPv4 range", 2, 2, 1, 1, "AS13335 CLOUDFLARENET", 1)
    assert related_domains(ds, "104.21.59.0/24") == ["risky.example", "low.example", "evil-site.com"]


def test_iris_target_lookup_is_rebuilt_as_irisql():
    from types import SimpleNamespace

    from core.lookup_queries import build_lookup_queries
    collected = SimpleNamespace(statuses=[{"Source": "Iris Investigate (domains on target)", "Target": "198.51.0.0/24",
                                           "Status": "OK", "Records": 3, "Detail": ""}], targets=["198.51.0.0/24"])
    rows = build_lookup_queries(collected)
    assert list(rows["Tool"]) == ["IrisQL"] and 'ip less_than_or_equal_to "198.51.0.255"' in rows.iloc[0]["Query"]

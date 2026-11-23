"""Infrastructure similarity: features, rarity, pair scores, clusters, earlier runs (LSH) and learned weights."""
from types import SimpleNamespace

import pandas as pd

from core import similarity as sim


def iris(ip, ns, registrar="NameCheap", created="2026-11-01", ip_count=3, ns_count=4):
    return {"ip": [{"address": {"value": ip, "count": ip_count}}],
            "name_server": [{"host": {"value": ns, "count": ns_count}}],
            "registrar": {"value": registrar}, "create_date": {"value": created}}


def dataset(enrichment, profiles=None):
    ds = SimpleNamespace(selected_domains=list(enrichment), enrichment=enrichment, pdns_utc=pd.DataFrame(),
                         txt_apps=pd.DataFrame(), bgp_origins=pd.DataFrame(), ssl_all_utc=pd.DataFrame(),
                         ssl=pd.DataFrame())
    return ds, profiles


CAMPAIGN = {"xwfa3ak.cc": iris("45.1.2.3", "ns1.rare-dns.net"),
            "spr7tsc.cc": iris("45.1.2.9", "ns1.rare-dns.net", created="2026-11-02"),
            "sqv5zzx.cc": iris("45.1.2.3", "ns1.rare-dns.net", created="2026-11-02"),
            "bank-example.com": iris("104.16.1.1", "ns.cloudflare.com", registrar="MarkMonitor",
                                     created="2005-01-01", ip_count=900000, ns_count=500000)}


def scored(enrichment=CAMPAIGN, profiles=None):
    feats, iris_counts = sim.domain_features(*dataset(enrichment, profiles))
    counts = sim.value_counts(feats, iris_counts)
    return feats, counts, sim.pair_scores(feats, counts)


def test_features_read_iris_and_the_name():
    feats, _, _ = scored()
    f = feats["xwfa3ak.cc"]
    assert ("ip", "45.1.2.3") in f.tokens and ("net24", "45.1.2.0/24") in f.tokens
    assert ("nsdom", "rare-dns.net") in f.tokens and f.shape == "llllnll.cc" and f.registrar == "namecheap"


def test_campaign_domains_score_high_and_the_bank_low():
    _, _, pairs = scored()
    score = {(r["Domain A"], r["Domain B"]): r["Similarity %"] for _, r in pairs.iterrows()}
    assert score[("sqv5zzx.cc", "xwfa3ak.cc")] > 80                 # same IP, name server, registrar, shape
    assert score[("spr7tsc.cc", "xwfa3ak.cc")] > 60                 # same /24 and name server, not the IP
    assert all(s < 30 for (a, b), s in score.items() if "bank-example.com" in (a, b))
    top = pairs.iloc[0]
    assert top["Rare Shared"] >= 2 and "Hosting" in top["Matched"] and "IP 45.1.2.3" in top["Shared Values"]


def test_common_values_link_little():
    assert sim.rarity(("ca", "letsencrypt"), {}) == sim.COMMON_MARK
    assert sim.rarity(("asn", "AS13335"), {}) == sim.COMMON_MARK
    assert sim.rarity(("ip", "9.9.9.9"), {("ip", "9.9.9.9"): 1}) == 1.0
    assert sim.rarity(("ip", "9.9.9.9"), {("ip", "9.9.9.9"): 1000}) == 0.25


def test_dif_parts_ignore_the_hash_and_closest_dif_counts_parts():
    assert sim.dif_parts("F-UN_NAZS-U_NO_3325d3") == ("F", "UN", "NA", "ZS", "U", "NO")
    assert sim.dif_parts("P-UN_NOCERT_NO_2711de")[2:5] == ("NOCERT",) * 3
    profiles = pd.DataFrame({"Domain": ["a.cc", "b.cc", "c.cc"],
                             "DIF Fingerprint": ["F-UN_NAZS-U_NO_3325d3", "F-UN_NAZS-U_NO_7a5c45",
                                                 "P-UN_NOCERT_NO_2711de"]})
    assert sim.closest_dif(profiles)["a.cc"] == "F-UN_NAZS-U_NO_7a5c45 (b.cc, 6/6 parts)"


def test_threshold_and_rare_filter_and_clusters():
    _, _, pairs = scored()
    assert len(sim.passing(pairs, 60)) == 3 and sim.passing(pairs, 60, min_rare=10).empty
    groups = sim.clusters(pairs, sorted(CAMPAIGN), threshold=60)
    assert groups == [["spr7tsc.cc", "sqv5zzx.cc", "xwfa3ak.cc"]]
    assert sim.clusters(pairs, sorted(CAMPAIGN), threshold=99) == []
    grid = sim.matrix(pairs, sorted(CAMPAIGN))
    assert grid.loc["xwfa3ak.cc", "xwfa3ak.cc"] == 100 and grid.loc["xwfa3ak.cc", "sqv5zzx.cc"] > 80


def test_earlier_runs_are_found_by_lsh():
    runs = [("k1", {"id": "r1", "created": "2026-10-12T09:00:00", "name": "October hunt",
                    "artifacts": {"7h1r0.cc": {"IP": ["45.1.2.3"], "Name Server": ["ns1.rare-dns.net"]},
                                  "unrelated.org": {"IP": ["8.8.8.8"], "Name Server": ["ns.google.com"]}}})]
    index = sim.build_index(runs)
    feats, counts, _ = scored()
    tokens = sim.artifact_tokens({"IP": ["45.1.2.3"], "Name Server": ["ns1.rare-dns.net"]})
    found = sim.similar_in_runs("xwfa3ak.cc", tokens, index, sim.value_counts(feats, runs=runs))
    assert list(found["Domain"]) == ["7h1r0.cc"] and found.iloc[0]["Run Name"] == "October hunt"
    assert found.iloc[0]["Similarity %"] >= 40
    assert sim.similar_in_runs("xwfa3ak.cc", tokens, index, counts, exclude_run="r1").empty


def test_weights_are_learned_only_with_enough_verdicts():
    rows = []
    for i in range(12):
        rows.append({"Domain A": f"m{i}", "Domain B": f"m{i + 1}", "Hosting": 90, "DNS": 80, "Naming": 20})
        rows.append({"Domain A": f"m{i}", "Domain B": f"b{i}", "Hosting": 10, "DNS": 5, "Naming": 25})
    pairs = pd.DataFrame(rows).reindex(columns=sim.PAIR_COLUMNS)
    verdicts = {**{f"m{i}": "Malicious" for i in range(13)}, **{f"b{i}": "Benign" for i in range(12)}}
    weights, report = sim.learn_weights(pairs, verdicts)
    assert report["positives"] == 12 and report["negatives"] == 12 and report["accuracy"] == 100
    assert weights["Hosting"] + weights["DNS"] > 80 and sum(weights.values()) in (99, 100, 101)
    assert sim.learn_weights(pairs.head(4), verdicts)[0] is None


def test_cluster_indicators_cover_every_source_and_the_share():
    ds, _ = dataset(CAMPAIGN)
    ds.anonymizers = pd.DataFrame({"IP": ["45.1.2.3"], "Domains": ["xwfa3ak.cc, sqv5zzx.cc"], "Category": ["VPN"],
                                   "Provider": ["ExampleVPN"]})
    ds.bgp_origins = pd.DataFrame({"IP": ["45.1.2.3", "45.1.2.9"], "Domains": ["xwfa3ak.cc, sqv5zzx.cc", "spr7tsc.cc"],
                                   "Prefix": ["45.1.2.0/24"] * 2, "Origin": ["AS64999"] * 2,
                                   "AS Name": ["BAD-HOST"] * 2, "Status": ["Unauthorized"] * 2,
                                   "Collectors": [40, 40], "Updates": [3, 3]})
    ds.bgp_routes = pd.DataFrame({"Prefix": ["45.1.2.0/24"], "Upstream": ["AS1234"], "Collectors": [40],
                                  "Updates": [3]})
    feats, iris_counts = sim.domain_features(ds)
    counts = sim.value_counts(feats, iris_counts)
    group = ["spr7tsc.cc", "sqv5zzx.cc", "xwfa3ak.cc"]
    found = sim.cluster_indicators(group, feats, counts)
    by_type = {(r["Type"], r["Indicator"]): r for _, r in found.iterrows()}
    assert by_type[("Name server", "ns1.rare-dns.net")]["Share %"] == 100
    assert by_type[("IP", "45.1.2.3")]["Domains"] == 2 and by_type[("IP", "45.1.2.3")]["Share %"] == 67
    assert by_type[("Anonymizer provider", "ExampleVPN (VPN)")]["Source"] == "VPNDB"
    assert {("Upstream network", "AS1234"), ("Route status", "Unauthorized"), ("Announced prefix", "45.1.2.0/24"),
            ("Registrar", "NameCheap")} <= set(by_type)
    assert by_type[("Registrar", "NameCheap")]["Rarity"] is None or pd.isna(by_type[("Registrar", "NameCheap")]["Rarity"])
    assert found.iloc[0]["Domains"] == 3
    _, _, pairs = scored()
    rows = sim.cluster_pairs(group, feats, pairs)
    assert len(rows) == 3
    top = rows[(rows["Domain A"] == "sqv5zzx.cc") & (rows["Domain B"] == "xwfa3ak.cc")].iloc[0]
    assert "Anonymizer exit VPN" in top["Shared Indicators"] and "IP 45.1.2.3" in top["Shared Indicators"]
    assert 0 < top["Shared %"] <= 100

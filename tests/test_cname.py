import pandas as pd

from core.cname import (
    NOT_CHASED,
    build_cname_map,
    chase_plan,
    classify_target,
    cname_links,
    full_path,
    merge_chases,
    merge_rdata,
    order_by_domain,
    rdata_candidates,
    rdata_rows,
    rdata_summary,
    related_domains,
)
from core.lookup_queries import build_lookup_queries
from core.threat_detection import detect_threat_flags
from integrations import collector, dnsdb
from integrations.collector import CollectedData
from integrations.http import FetchResult, StatusLog


def pdns(rows):
    """Passive DNS rows: (domain, rrname, type, value, first seen, last seen)."""
    frame = pd.DataFrame(rows, columns=["Domain", "RRName", "Field", "Value", "First Seen", "Last Seen"])
    for col in ("First Seen", "Last Seen"):
        frame[col] = pd.to_datetime(frame[col])
    frame["Date"] = frame["First Seen"]
    return frame


def chase(start, path, outcome, final=""):
    return {"Start": start, "Path": " → ".join(path), "Hops": len(path) - 1, "Outcome": outcome, "Final": final,
            "Final Last Seen": pd.Timestamp("2026-10-01") if final else pd.NaT, "Note": ""}


def types(result):
    return dict(zip(result.alerts["Threat Type"], result.alerts["Severity"])) if not result.alerts.empty else {}


def test_classify_target_by_service():
    assert classify_target("abc.ngrok-free.app") == ("Dynamic DNS / tunnel", "ngrok")
    assert classify_target("victim.herokudns.com.") == ("Takeover-prone", "Heroku")
    assert classify_target("files.s3.eu-west-1.amazonaws.com") == ("Takeover-prone", "AWS S3")
    assert classify_target("x.cloudfront.net") == ("CDN", "Amazon CloudFront")
    assert classify_target("shop.pages.dev") == ("Free hosting", "pages.dev")
    assert classify_target("mail.example.org") == ("", "")
    assert classify_target("parkingpage.namecheap.com.") == ("Parking", "Namecheap parking")


def test_chains_follow_collected_records_and_mark_the_current_target():
    frame = pdns([
        ("a.com", "www.a.com", "CNAME", "edge.a.com.", "2024-01-01", "2026-10-01"),
        ("a.com", "edge.a.com", "CNAME", "a.b-cdn.net.", "2024-01-01", "2026-10-01"),
        ("a.com", "a.b-cdn.net", "A", "1.2.3.4", "2024-01-01", "2026-10-01"),
        ("a.com", "old.a.com", "CNAME", "a.github.io.", "2023-01-01", "2024-01-01"),
        ("a.com", "old.a.com", "CNAME", "a.netlify.app.", "2024-06-01", "2026-10-01"),
    ])
    cmap = build_cname_map(frame).set_index(["Hostname", "Target"])
    www = cmap.loc[("www.a.com", "edge.a.com")]
    assert www["Chain"] == "www.a.com → edge.a.com → a.b-cdn.net" and www["Outcome"] == "Resolves"
    assert www["Final"] == "1.2.3.4" and www["Hops"] == 2 and not www["External"]
    assert cmap.loc[("old.a.com", "a.netlify.app"), "Current"]
    assert not cmap.loc[("old.a.com", "a.github.io"), "Current"]
    assert cmap.loc[("old.a.com", "a.netlify.app"), "Outcome"] == NOT_CHASED


def test_free_hosting_inside_the_analyzed_platform_is_not_labelled():
    cmap = build_cname_map(pdns([("pages.dev", "x.pages.dev", "CNAME", "y.pages.dev", "2026-01-01", "2026-10-01")]))
    assert cmap.loc[0, "Service Type"] == "" and not cmap.loc[0, "External"]


def test_chases_continue_chains_and_candidates_rank_risky_services_first():
    frame = pdns([
        ("a.com", "app.a.com", "CNAME", "a.herokudns.com", "2026-01-01", "2026-10-01"),
        ("a.com", "cdn.a.com", "CNAME", "a.cloudfront.net", "2026-01-01", "2026-10-02"),
        ("a.com", "vpn.a.com", "CNAME", "x.duckdns.org", "2026-01-01", "2026-09-01"),
    ])
    assert chase_plan(build_cname_map(frame)) == {"a.com": ["x.duckdns.org", "a.herokudns.com", "a.cloudfront.net"]}
    chases = pd.DataFrame([chase("a.herokudns.com", ["a.herokudns.com"], "Dead end")])
    cmap = build_cname_map(frame, chases).set_index("Hostname")
    assert cmap.loc["app.a.com", "Outcome"] == "Dead end"
    assert chase_plan(build_cname_map(frame, chases)) == {"a.com": ["x.duckdns.org", "a.cloudfront.net"]}


def test_chase_plan_lists_names_per_domain_most_hostnames_first():
    frame = pdns([
        ("big.com", "h0.big.com", "CNAME", "t0.example.net", "2026-01-01", "2026-10-01"),
        *[("big.com", f"s{i}.big.com", "CNAME", "shared.example.net", "2026-01-01", "2026-09-01") for i in range(3)],
        ("small.com", "www.small.com", "CNAME", "shared.example.net", "2026-01-01", "2026-09-01"),
        ("small.com", "m.small.com", "CNAME", "s.example.org", "2026-01-01", "2026-09-01"),
    ])
    plan = chase_plan(order_by_domain(build_cname_map(frame), ["big.com", "small.com"]))
    # the name 3 hostnames share before the more recent one; a name two domains share is chased once
    assert plan == {"big.com": ["shared.example.net", "t0.example.net"], "small.com": ["s.example.org"]}


def test_chases_stop_at_the_domain_query_budget_and_continue_next_time(monkeypatch):
    monkeypatch.setattr(dnsdb, "fetch_dnsdb_history", fake_dnsdb([
        dnsdb_record("a.example", "CNAME", "b.example.", "2026-01-01"),
        dnsdb_record("b.example", "CNAME", "c.example.", "2026-01-01"),
        dnsdb_record("c.example", "A", "1.2.3.4", "2026-01-01"),
    ]))
    run = collector.chase_cnames({"x.com": ["a.example", "other.example"]}, StatusLog(), max_queries=2)
    assert list(run.chases["Outcome"]) == ["Query limit"] and run.chases.loc[0, "Path"] == "a.example → b.example → c.example"
    assert run.queries == 2 and run.left == 1                    # other.example waits for the next click
    cmap = build_cname_map(pdns([("x.com", "www.x.com", "CNAME", "a.example", "2026-01-01", "2026-10-01")]), run.chases)
    assert cmap.loc[0, "Chain"] == "www.x.com → a.example → b.example → c.example" and cmap.loc[0, "Outcome"] == NOT_CHASED
    assert chase_plan(cmap) == {"x.com": ["c.example"]}          # the next click continues where the chase stopped


def test_cross_domain_links():
    frame = pdns([
        *[("a.com", f"h{i}.a.com", "CNAME", "proxy.evil.net", "2026-01-01", "2026-10-01") for i in range(3)],
        ("b.com", "www.b.com", "CNAME", "proxy.evil.net", "2026-01-01", "2026-10-01"),
        ("c.com", "cdn.c.com", "CNAME", "edge.d.com", "2026-01-01", "2026-10-01"),
        ("a.com", "x.a.com", "CNAME", "a.cloudfront.net", "2026-01-01", "2026-10-01"),
        ("b.com", "y.b.com", "CNAME", "b.cloudfront.net", "2026-01-01", "2026-10-01"),
        ("a.com", "a.cloudfront.net", "A", "9.9.9.9", "2026-01-01", "2026-10-01"),
        ("b.com", "b.cloudfront.net", "A", "9.9.9.9", "2026-01-01", "2026-10-01"),
    ])
    cmap = build_cname_map(frame)
    links = cname_links(cmap, ["d.com"]).set_index("Link")
    assert links.loc["edge.d.com", "Kind"] == "CNAME into analyzed domain"     # d.com has no CNAMEs of its own
    assert links.loc["edge.d.com", "Domains"] == "c.com, d.com"
    assert links.loc["proxy.evil.net", "Kind"] == "Shared CNAME"
    assert links.loc["9.9.9.9", "Service Type"] == "CDN"                       # shared only through CloudFront
    assert links.index[-1] == "9.9.9.9"                                         # CDN links last


def test_merge_chases_keeps_the_newest_chase_per_start():
    old = pd.DataFrame([chase("t.com", ["t.com"], "Lookup failed")])
    new = pd.DataFrame([chase("t.com", ["t.com"], "Resolves", "1.1.1.1")])
    assert list(merge_chases(old, new)["Outcome"]) == ["Resolves"]


def dnsdb_record(name, rrtype, value, last):
    return {"rrname": f"{name}.", "rrtype": rrtype, "rdata": [value], "time_last": int(pd.Timestamp(last).timestamp())}


def fake_dnsdb(records):
    def fetch(target, limit=500, rrtype="ANY", include_wildcard=True):
        data = [r for r in records if r["rrname"] == f"{target}." and r["rrtype"] == rrtype]
        return FetchResult("DNSDB", target, data=data, record_count=len(data))
    return fetch


def test_chase_follows_latest_cname_to_addresses(monkeypatch):
    monkeypatch.setattr(dnsdb, "fetch_dnsdb_history", fake_dnsdb([
        dnsdb_record("a.example", "CNAME", "old.example.", "2020-01-01"),
        dnsdb_record("a.example", "CNAME", "b.example.", "2026-01-01"),
        dnsdb_record("b.example", "CNAME", "c.example.", "2026-01-01"),
        dnsdb_record("c.example", "AAAA", "2001:db8::1", "2026-01-01"),
    ]))
    result, lookups = dnsdb.chase_cname("a.example")
    assert result["Path"] == "a.example → b.example → c.example" and result["Outcome"] == "Resolves"
    assert result["Final"] == "2001:db8::1" and result["Hops"] == 2
    assert [r.source for r in lookups][-2:] == ["DNSDB CNAME Chase (A)", "DNSDB CNAME Chase (AAAA)"]


def test_chase_reports_dead_ends_and_loops(monkeypatch):
    monkeypatch.setattr(dnsdb, "fetch_dnsdb_history", fake_dnsdb([
        dnsdb_record("x.example", "CNAME", "y.example.", "2026-01-01"),
        dnsdb_record("y.example", "CNAME", "x.example.", "2026-01-01"),
    ]))
    assert dnsdb.chase_cname("x.example")[0]["Outcome"] == "Loop"
    assert dnsdb.chase_cname("gone.example")[0]["Outcome"] == "Dead end"
    # a CDN edge passive DNS has no address for: unknown end, not a dangling CNAME (nytimes.com's datadome chain)
    assert dnsdb.chase_cname("detpi4b5pore2.cloudfront.net")[0]["Outcome"] == "Incomplete"


def test_cname_supplement_runs_wherever_the_main_lookup_was_capped(monkeypatch):
    calls = []

    def fake_fetch(target, limit=5000, rrtype="ANY", include_wildcard=True):
        calls.append((target, rrtype))
        data = [{"rrname": f"www.{target}.", "rrtype": "CNAME", "rdata": ["x.net."], "time_first": 1, "time_last": 2}] \
            if target == "has-cname.com" and rrtype == "ANY" else []
        return FetchResult("DNSDB Scout", target, data=data, truncated=rrtype == "ANY" and target != "small.com",
                           record_count=len(data))

    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake_fetch)
    log = StatusLog()
    collector.collect_pdns(["big.com", "has-cname.com", "small.com"], 10, log, cname_lookup=True)
    # a capped result holding some CNAMEs holds only some of them (nytimes.com: 10 names of thousands)
    assert sorted(c for c in calls if c[1] == "CNAME") == [("big.com", "CNAME"), ("has-cname.com", "CNAME")]


def test_cname_lookups_are_aggregated():
    assert dnsdb.client_params("CNAME")["aggr"] == "t" and dnsdb.client_params("A")["aggr"] == "t"
    assert dnsdb.client_params("ANY")["aggr"] == "f" and dnsdb.client_params("TXT")["aggr"] == "f"
    queries = build_lookup_queries(CollectedData(statuses=[
        {"Source": "DNSDB CNAME Lookup", "Target": "nytimes.com", "Status": "OK", "Records": 1}]))
    assert "aggr=t" in queries.loc[0, "Command"] and "limit=5000" in queries.loc[0, "Command"]


def test_cname_detections():
    frame = pdns([
        ("a.com", "shop.a.com", "CNAME", "a.myshopify.com", "2026-01-01", "2026-10-01"),
        ("a.com", "vpn.a.com", "CNAME", "x.duckdns.org", "2026-01-01", "2026-10-01"),
        ("a.com", "paypal-login.a.com", "CNAME", "p.pages.dev", "2026-01-01", "2026-10-01"),
        ("a.com", "app.a.com", "CNAME", "a.azurewebsites.net", "2026-01-01", "2026-10-01"),
        ("a.com", "blog.a.com", "CNAME", "a.wpengine.com", "2025-01-01", "2025-06-01"),
        ("a.com", "blog.a.com", "CNAME", "evil-host.net", "2026-02-01", "2026-10-01"),
        ("a.com", "deep.a.com", "CNAME", "h1.example.net", "2026-01-01", "2026-10-01"),
        ("b.com", "www.b.com", "CNAME", "evil-host.net", "2026-01-01", "2026-10-01"),
    ])
    chases = pd.DataFrame([
        chase("a.myshopify.com", ["a.myshopify.com"], "Dead end"),
        chase("h1.example.net", ["h1.example.net", "h2.example.net", "h3.example.net", "h4.example.net"], "Resolves", "9.9.9.9"),
    ])
    alerts = types(detect_threat_flags(frame, {}, cname_chases=chases))
    assert alerts["Dangling CNAME (Subdomain Takeover Risk)"] == "Critical"
    assert alerts["Unverified CNAME to Takeover-Prone Service"] == "Medium"   # azurewebsites, not chased
    assert alerts["CNAME to Dynamic DNS / Tunnel Service"] == "High"
    assert alerts["CNAME to Free Hosting Platform"] == "High"                 # paypal-login lure
    assert alerts["CNAME Retargeted to Another Provider"] == "Medium"         # wpengine → evil-host.net
    assert alerts["Long CNAME Chain / Loop"] == "Medium"                      # deep.a.com: 4 hops
    assert alerts["CNAME Link Between Analyzed Domains"] == "Medium-High"     # evil-host.net on a.com and b.com


def test_lookup_queries_rebuild_chase_and_supplement_requests():
    data = CollectedData(targets=["a.com"], domain_targets=["a.com"])
    data.statuses = [{"Source": src, "Target": target, "Status": "OK", "Records": 1, "Detail": ""} for src, target in [
        ("DNSDB CNAME Chase (CNAME)", "x.example"), ("DNSDB CNAME Chase (A)", "x.example"),
        ("DNSDB CNAME Lookup", "a.com")]]
    queries = build_lookup_queries(data)
    assert list(queries["Search"]) == ["RRset, type CNAME", "RRset, type A", "RRset, type CNAME"]
    assert "/rrset/name/x.example/A?limit=500" in queries.loc[1, "Command"]
    assert "*.a.com" in queries.loc[2, "Query"]


def test_history_targets_are_chased_after_current_ones():
    frame = pdns([
        ("a.com", "line.a.com", "CNAME", "line.old.net", "2026-01-15", "2026-01-15"),
        ("a.com", "line.a.com", "CNAME", "line.new.net", "2026-01-18", "2026-01-20"),
    ])
    cmap = build_cname_map(frame)
    assert chase_plan(cmap[cmap["Current"]]) == {"a.com": ["line.new.net"]}
    assert chase_plan(cmap) == {"a.com": ["line.new.net", "line.old.net"]}


def test_reverse_cname_rows_related_domains_and_links():
    records = [{"rrname": "www.other.org.", "rrtype": "CNAME", "rdata": ["proxy.evil.net."], "count": 3,
                "time_first": 1767225600, "time_last": 1767312000},
               {"rrname": "cdn.b.com.", "rrtype": "CNAME", "rdata": ["proxy.evil.net."], "count": 1,
                "time_first": 1767225600, "time_last": 1767312000}]
    rows = rdata_rows("proxy.evil.net.", records, ["a.com", "b.com"])
    assert list(rows["Apex"]) == ["other.org", "b.com"] and list(rows["Analyzed"]) == [False, True]
    related = related_domains(rows)
    assert list(related["Domain"]) == ["other.org", "b.com"]                 # other domains first
    assert related.loc[0, "Target Shared By"] == 2
    newer = rdata_rows("proxy.evil.net", records[:1], ["a.com", "b.com"])
    assert len(merge_rdata(rows, newer)) == 1                                # a newer lookup of a target replaces it
    cmap = build_cname_map(pdns([("a.com", "www.a.com", "CNAME", "proxy.evil.net", "2026-01-01", "2026-10-01")]))
    assert rdata_candidates(cmap, 5) == ["proxy.evil.net"]
    parked = build_cname_map(pdns([("a.com", "www.a.com", "CNAME", "pixie.porkbun.com", "2026-01-01", "2026-10-01")]))
    assert rdata_candidates(parked, 5) == [] and rdata_candidates(parked, 5, skip_shared=False) == ["pixie.porkbun.com"]
    assert cname_links(cmap).empty
    links = cname_links(cmap, ["b.com"], rows).set_index("Link")
    assert links.loc["proxy.evil.net", "Domains"] == "a.com, b.com"          # b.com found only by the reverse lookup


def test_lookup_queries_rebuild_reverse_cname_requests():
    data = CollectedData(targets=["a.com"], domain_targets=["a.com"])
    data.statuses = [{"Source": "DNSDB CNAME RDATA", "Target": "proxy.evil.net", "Status": "OK", "Records": 2,
                      "Detail": ""}]
    queries = build_lookup_queries(data)
    assert queries.loc[0, "Search"] == "Rdata name, type CNAME"
    assert "/rdata/name/proxy.evil.net/CNAME?limit=500" in queries.loc[0, "Command"]


def test_paths_start_at_the_analyzed_domain_and_rows_group_by_domain():
    frame = pdns([
        ("b.com", "www.b.com", "CNAME", "proxy.evil.net", "2026-01-01", "2026-10-01"),
        ("a.com", "line.a.com", "CNAME", "line.old.net", "2026-01-15", "2026-01-15"),
        ("b.com", "proxy.evil.net", "A", "5.5.5.5", "2026-01-01", "2026-10-01"),
        ("a.com", "line.a.com", "CNAME", "line.new.net", "2026-01-18", "2026-01-20"),
    ])
    cmap = order_by_domain(build_cname_map(frame), ["a.com", "b.com"])
    assert list(cmap["Domain"]) == ["a.com", "a.com", "b.com"] and cmap.loc[0, "Target"] == "line.new.net"
    assert full_path("b.com", "www.b.com → proxy.evil.net", "5.5.5.5") == "b.com → www.b.com → proxy.evil.net → 5.5.5.5"
    assert full_path("a.com", "a.com → x.net", "", NOT_CHASED) == "a.com → x.net (Not chased)"


def test_rdata_summary_counts_other_domains_per_target():
    rows = rdata_rows("proxy.evil.net", [
        {"rrname": f"www.o{i}.org.", "rrtype": "CNAME", "rdata": ["proxy.evil.net."]} for i in range(3)
    ] + [{"rrname": "cdn.b.com.", "rrtype": "CNAME", "rdata": ["proxy.evil.net."]}], ["b.com"])
    summary = rdata_summary(rows).iloc[0]
    assert summary["Other Domains"] == 3 and summary["Names"] == 4 and summary["Analyzed Domains"] == "b.com"
    assert not summary["Truncated"]
    repeated = rdata_rows("proxy.evil.net", [{"rrname": "www.o1.org.", "rrtype": "CNAME", "count": n,
                                              "time_first": t, "time_last": t} for n, t in ((2, 100), (3, 900))],
                          truncated=True)
    assert len(repeated) == 1 and repeated.loc[0, "Count"] == 5               # one row per name
    cmap = build_cname_map(pdns([("a.com", "www.a.com", "CNAME", "proxy.evil.net", "2026-01-01", "2026-10-01")]))
    summary = rdata_summary(repeated, cmap).iloc[0]
    assert summary["Truncated"] and summary["Analyzed Domains"] == "a.com"     # a.com's own chain, missed by DNSDB


def test_chain_map_draws_one_box_per_domain_starting_at_the_domain():
    from views.cname_view import _chain_graph, chain_groups
    frame = pdns([(d, f"h{i}.{d}", "CNAME", f"t{i}.{d[0]}.net", "2026-01-01", "2026-10-01")
                  for d in ("a.com", "b.com") for i in range(3)])
    cmap = order_by_domain(build_cname_map(frame), ["a.com", "b.com"])
    dot = _chain_graph(cmap)
    assert dot.count("subgraph") == 2 and '"domain::a.com" -> "hosts::a.com::t0.a.net::"' in dot
    history = build_cname_map(pdns([
        ("a.com", "line.a.com", "CNAME", "line.old.net", "2026-01-15", "2026-01-15"),
        ("a.com", "line.a.com", "CNAME", "line.new.net", "2026-01-18", "2026-01-20"),
        ("a.com", "line.new.net", "A", "1.2.3.4", "2026-01-18", "2026-01-20"),
    ]))
    dot = _chain_graph(history)
    assert 'style=dashed, color="#bbbbbb", label="until 2026-01-15"' in dot     # earlier CNAME, last seen that day
    assert '"line.new.net" -> "1.2.3.4" [style=dotted];' in dot                # into the final addresses
    kept = [domain for (domain, _, _), _ in chain_groups(cmap, limit=2)]
    assert kept == ["a.com", "b.com"]                       # every domain before any domain's second chain
    shared = build_cname_map(pdns([(f"h{i}.a.com"[3:], f"h{i}.a.com", "CNAME", "t.net", "2026-01-01", "2026-10-01")
                                   for i in range(3)]))
    assert len(chain_groups(shared)) == 1 and len(chain_groups(shared, by_hostname=True)) == 3


def test_chase_results_group_chased_chains_most_hostnames_first():
    from views.cname_view import chase_results
    frame = pdns([*[("a.com", f"h{i}.a.com", "CNAME", "big.net", "2026-01-01", "2026-10-01") for i in range(3)],
                  ("a.com", "x.a.com", "CNAME", "small.net", "2026-01-01", "2026-10-02"),
                  ("a.com", "y.a.com", "CNAME", "hidden.net", "2026-01-01", "2026-10-02"),
                  ("a.com", "big.net", "A", "1.1.1.1", "2026-01-01", "2026-10-01"),
                  ("a.com", "small.net", "A", "2.2.2.2", "2026-01-01", "2026-10-01")])
    rows = build_cname_map(frame)
    results = chase_results(rows.assign(Chased=rows["Target"] != "hidden.net"))   # y.a.com was not chased
    assert list(results["Chain"]) == ["big.net → 1.1.1.1", "small.net → 2.2.2.2"] and list(results["Hostnames"]) == [3, 1]


def test_chases_record_cache_use_and_can_be_redone_fresh(monkeypatch):
    from integrations.cache import cached_fetch
    calls = []
    fake = fake_dnsdb([dnsdb_record("a.example", "A", "1.2.3.4", "2026-01-01")])
    monkeypatch.setattr(dnsdb, "fetch_dnsdb_history", cached_fetch()(lambda *args: calls.append(args) or fake(*args)))
    first = collector.chase_cnames({"x.com": ["a.example"]}, StatusLog()).chases.iloc[0]
    again = collector.chase_cnames({"x.com": ["a.example"]}, StatusLog())
    assert not first["From Cache"] and again.chases.loc[0, "From Cache"] and again.queries == 0
    assert abs((again.chases.loc[0, "Chased At"] - first["Chased At"]).total_seconds()) < 1   # when first fetched
    fresh = collector.chase_cnames({"x.com": ["a.example"]}, StatusLog(), fresh=True)
    assert not fresh.chases.loc[0, "From Cache"] and fresh.queries == 2 and len(calls) == 4
    frame = pdns([("x.com", "www.x.com", "CNAME", "a.example", "2026-01-01", "2026-10-01")])
    cmap = build_cname_map(frame, again.chases)
    assert cmap.loc[0, "From Cache"] and chase_plan(cmap) == {}
    assert chase_plan(cmap, rechase=True, chases=again.chases) == {"x.com": ["a.example"]}


def test_cname_count_does_not_add_the_aggregated_supplement_to_time_slices():
    frame = pdns([("a.com", "www.a.com", "CNAME", "t.net", "2026-01-01", "2026-01-02"),
                  ("a.com", "www.a.com", "CNAME", "t.net", "2026-01-03", "2026-01-04"),
                  ("a.com", "www.a.com", "CNAME", "t.net", "2025-01-01", "2026-01-04")])
    frame["Count"] = [2, 3, 10]
    frame["Collection"] = ["Main", "Main", "CNAME supplement"]
    assert build_cname_map(frame).loc[0, "Count"] == 10      # the aggregated record already covers the slices


def test_a_new_run_restores_cached_chases_without_queries(monkeypatch):
    from integrations.cache import cached_fetch
    calls = []
    fake = fake_dnsdb([dnsdb_record("a.example", "CNAME", "b.example.", "2026-01-01"),
                       dnsdb_record("b.example", "A", "1.2.3.4", "2026-01-01")])
    monkeypatch.setattr(dnsdb, "fetch_dnsdb_history", cached_fetch()(lambda *args: calls.append(args) or fake(*args)))
    frame = pdns([("x.com", "www.x.com", "CNAME", "a.example", "2026-01-01", "2026-10-01"),
                  ("x.com", "m.x.com", "CNAME", "never.example", "2026-01-01", "2026-10-01")])
    collector.chase_cnames({"x.com": ["a.example"]}, StatusLog())             # the first run's chase: 3 queries
    later = CollectedData(pdns=frame)                                          # the next run: no chases yet
    log = StatusLog()
    assert collector.restore_cached_chases(later, log) == 1 and len(calls) == 3   # never.example is not cached
    cmap = build_cname_map(later.pdns, later.cname_chases).set_index("Hostname")
    assert cmap.loc["www.x.com", "Final"] == "1.2.3.4" and cmap.loc["www.x.com", "From Cache"]
    assert cmap.loc["m.x.com", "Outcome"] == NOT_CHASED and "Restored 1" in log.rows[0]["Detail"]

"""DNS resolution tree and dangling DNS (core.resolver) and its DNSDB lookups (integrations.collector.resolve_tree)."""
import pandas as pd

from core import resolver as r

NOW = pd.Timestamp("2026-11-20")


def _pdns(rows):
    return pd.DataFrame([{"Domain": "ex.com", "RRName": name, "Field": kind, "Value": value,
                          "Last Seen": NOW - pd.Timedelta(days=age)} for name, kind, value, age in rows])


def _lookups(rows):
    frame = pd.DataFrame([{"Lookup": name, "Name": name, "Type": kind, "Value": value, "Last Seen": NOW if kind else pd.NaT,
                           "Looked Up At": NOW, "From Cache": False} for name, kind, value in rows])
    return frame.reindex(columns=r.LOOKUP_COLUMNS)


def _tree(pdns, lookups=None, truncated=False):
    index = r.build_index(pdns, lookups, {"ex.com": {"truncated": truncated}}, ["ex.com"])
    return r.build_tree(index, ["ex.com"])


def _row(tree, name, kind):
    return tree[(tree["Name"] == name) & (tree["Type"] == kind)].iloc[0]


def test_records_resolve_through_cname_mx_ns_and_spf():
    pdns = _pdns([("ex.com", "A", "93.184.216.34", 0), ("www.ex.com", "CNAME", "edge.cdnhost.net.", 0),
                  ("ex.com", "MX", "10 mail.ex.com.", 0), ("mail.ex.com", "A", "93.184.216.35", 0),
                  ("ex.com", "NS", "ns1.dnsprov.net.", 0), ("ex.com", "TXT", '"v=spf1 include:_spf.mailer.com" " ~all"', 0),
                  ("old.ex.com", "A", "1.2.3.4", 400)])          # not seen for over a year: not in the current tree
    lookups = _lookups([("edge.cdnhost.net", "A", "203.0.113.9"), ("ns1.dnsprov.net", "A", "198.51.100.1"),
                        ("_spf.mailer.com", "TXT", '"v=spf1 ip4:192.0.2.0/24 -all"')])
    tree, todo = _tree(pdns, lookups)
    assert todo == [] and set(tree["Status"]) == {r.RESOLVES}
    assert _row(tree, "www.ex.com", "CNAME")["IPv4"] == ["203.0.113.9"]
    assert _row(tree, "www.ex.com", "CNAME")["Path"] == "www.ex.com → edge.cdnhost.net"
    assert _row(tree, "ex.com", "MX")["IPv4"] == ["93.184.216.35"]
    assert _row(tree, "ex.com", "NS")["Targets"] == ["ns1.dnsprov.net"]
    spf = _row(tree, "ex.com", "TXT")
    assert spf["Targets"] == ["_spf.mailer.com"] and spf["IPv4"] == ["192.0.2.0/24"]
    assert "old.ex.com" not in set(tree["Name"])


def test_names_outside_the_data_wait_for_a_lookup():
    pdns = _pdns([("www.ex.com", "CNAME", "x.elsewhere.org.", 0), ("ex.com", "MX", "10 mx.mailhost.com.", 0)])
    tree, todo = _tree(pdns)
    assert set(tree["Status"]) == {r.PENDING} and todo == ["mx.mailhost.com", "x.elsewhere.org"]


def test_dangling_targets_and_their_severity():
    pdns = _pdns([("shop.ex.com", "CNAME", "ex-shop.herokuapp.com.", 0),
                  ("promo.ex.com", "CNAME", "promo.lapsed-agency.com.", 0),
                  ("cdn.ex.com", "CNAME", "a1.cloudfront.net.", 0),
                  ("ex.com", "MX", "10 mx.oldmail.net.", 0),
                  ("ex.com", "NS", "ns1.gone-dns.org.", 0),
                  ("ex.com", "TXT", '"v=spf1 include:spf.vanished.io -all"', 0),
                  ("int.ex.com", "CNAME", "missing.ex.com.", 0),
                  ("vpn.ex.com", "A", "10.0.0.5", 0)])
    lookups = _lookups([("ex-shop.herokuapp.com", "", ""), ("herokuapp.com", "NS", "ns1.heroku.com"),
                        ("promo.lapsed-agency.com", "", ""), ("lapsed-agency.com", "", ""),
                        ("a1.cloudfront.net", "", ""), ("mx.oldmail.net", "", ""), ("oldmail.net", "NS", "ns.oldmail.net"),
                        ("ns1.gone-dns.org", "", ""), ("gone-dns.org", "", ""),
                        ("spf.vanished.io", "A", "198.51.100.7"), ("vanished.io", "NS", "ns.vanished.io")])
    tree, todo = _tree(pdns, lookups)
    assert todo == []
    shop = _row(tree, "shop.ex.com", "CNAME")
    assert (shop["Status"], shop["Severity"]) == (r.DANGLING, "Critical") and "subdomain takeover" in shop["Reason"][0]
    promo = _row(tree, "promo.ex.com", "CNAME")
    assert promo["Severity"] == "Critical" and "lapsed-agency.com has no current DNS record" in promo["Reason"][0]
    assert _row(tree, "cdn.ex.com", "CNAME")["Status"] == r.NO_ADDRESS    # a CDN edge without address: not dangling
    mx = _row(tree, "ex.com", "MX")
    assert (mx["Severity"], mx["Dangling"]) == ("High", ["mx.oldmail.net"]) and "incoming mail" in mx["Reason"][0]
    assert _row(tree, "ex.com", "NS")["Severity"] == "Critical"           # its domain lapsed: zone takeover
    spf = _row(tree, "ex.com", "TXT")
    assert (spf["Status"], spf["Severity"]) == (r.DANGLING, "Medium") and "no SPF record" in spf["Reason"][0]
    own = _row(tree, "int.ex.com", "CNAME")                                 # not claimable: stale, not dangling
    assert (own["Status"], own["Severity"], own["Dangling"], own["Stale"]) == (r.STALE, "", [], ["missing.ex.com"])
    assert "not claimable from outside" in own["Reason"][0]
    vpn = _row(tree, "vpn.ex.com", "A")
    assert vpn["Status"] == r.RESOLVES and vpn["Severity"] == "Low" and vpn["Warnings"] == ["Internal IP 10.0.0.5 in public DNS"]
    assert list(tree["Severity"])[:3] == ["Critical"] * 3                  # most severe first
    counts = r.summary(tree)
    assert (counts["Dangling"], counts["Stale"], counts["Critical"], counts["High"]) == (5, 1, 3, 1)


def test_a_dead_target_asks_for_its_domain_and_loops_are_caught():
    pdns = _pdns([("a.ex.com", "CNAME", "gone.other.com.", 0), ("b.ex.com", "CNAME", "c.ex.com.", 0),
                  ("c.ex.com", "CNAME", "b.ex.com.", 0)])
    tree, todo = _tree(pdns, _lookups([("gone.other.com", "", "")]))
    assert todo == ["other.com"] and "not looked up yet" in _row(tree, "a.ex.com", "CNAME")["Reason"][0]
    assert _row(tree, "b.ex.com", "CNAME")["Status"] == r.LOOP


def test_a_cut_off_lookup_does_not_prove_a_name_absent():
    pdns = _pdns([("www.ex.com", "CNAME", "app.ex.com.", 0)])
    assert _tree(pdns)[0].iloc[0]["Status"] == r.STALE           # a missing name of the domain itself: not claimable
    tree, todo = _tree(pdns, truncated=True)
    assert tree.iloc[0]["Status"] == r.PENDING and todo == ["app.ex.com"]


def test_lookup_rows_and_merge():
    records = [{"rrname": "x.com.", "rrtype": "A", "rdata": ["1.2.3.4"], "time_last": 1_700_000_000},
               {"rrname": "y.x.com.", "rrtype": "A", "rdata": ["5.6.7.8"], "time_last": 1_700_000_000}]
    rows = r.lookup_rows("x.com", records, NOW)
    assert [(row["Name"], row["Type"], row["Value"]) for row in rows] == [("x.com", "A", "1.2.3.4")]
    assert r.lookup_rows("z.com", [], NOW)[0]["Type"] == ""
    old = pd.DataFrame(r.lookup_rows("x.com", [], NOW) + r.lookup_rows("q.com", [], NOW))
    merged = r.merge_lookups(old, pd.DataFrame(rows))
    assert sorted(merged["Name"]) == ["q.com", "x.com"] and set(merged.loc[merged["Name"] == "x.com", "Type"]) == {"A"}


def test_resolve_tree_discovers_the_tree_then_looks_up_in_rounds_within_the_budget(monkeypatch):
    from integrations import collector
    from integrations.http import FetchResult, StatusLog
    stamp = NOW.timestamp()
    answers = {"a.host.net": [{"rrname": "a.host.net", "rrtype": "CNAME", "rdata": ["b.host.net."], "time_last": stamp}],
               "b.host.net": [{"rrname": "b.host.net", "rrtype": "A", "rdata": ["203.0.113.5"], "time_last": stamp}],
               # the time-fenced *.ex.com lookup finds a current name the (cut off) main lookup missed
               "*.ex.com": [{"rrname": "api.ex.com.", "rrtype": "A", "rdata": ["93.184.216.40"], "time_last": stamp}]}
    asked = []

    def fake(name, limit, rrtype, wildcard, since=None):
        key = f"*.{name}" if wildcard else name
        asked.append(key)
        assert not wildcard or since                      # the discovery is time-fenced
        return FetchResult("DNSDB", name, data=answers.get(key, []))
    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake)
    pdns = _pdns([("www.ex.com", "CNAME", "a.host.net.", 0), ("ex.com", "MX", "10 mx.other.org.", 0)])
    cut = {"ex.com": {"truncated": True}}
    run = collector.resolve_tree(pdns, ["ex.com"], cut, pd.DataFrame(), StatusLog(), max_queries=10)
    assert sorted(asked) == ["*.ex.com", "a.host.net", "b.host.net", "mx.other.org", "other.org"]
    assert (run.queries, run.discovered, run.cut_off) == (5, 1, 0)
    tree, todo = r.build_tree(r.build_index(pdns, run.lookups, cut, ["ex.com"]), ["ex.com"])
    assert todo == [] and _row(tree, "www.ex.com", "CNAME")["IPv4"] == ["203.0.113.5"]
    assert _row(tree, "api.ex.com", "A")["IPv4"] == ["93.184.216.40"]
    asked.clear()
    again = collector.resolve_tree(pdns, ["ex.com"], cut, run.lookups, StatusLog(), max_queries=10)
    assert asked == [] and again.discovered == 0                   # nothing left: no query
    asked.clear()
    short = collector.resolve_tree(pdns, ["ex.com"], cut, pd.DataFrame(), StatusLog(), max_queries=1)
    assert asked == ["*.ex.com"] and short.left == 2     # the CNAME target and the MX host wait for the next click


def test_a_cut_off_discovery_splits_by_record_type(monkeypatch):
    from integrations import collector
    from integrations.http import FetchResult, StatusLog
    asked = []

    def fake(name, limit, rrtype, wildcard, since=None):
        asked.append(rrtype)
        return FetchResult("DNSDB", name, data=[], truncated=rrtype in ("ANY", "TXT"))
    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake)
    rows, queries, _ = collector.discover_trees(["ex.com"], StatusLog(), max_queries=20)
    assert asked == ["ANY", *r.RESOLVE_TYPES] and queries == 7
    assert rows[-1]["Value"] == r.CUT_OFF                      # TXT was still cut off: absence proves nothing


def test_certificate_validation_cnames_are_stale_not_dangling():
    pdns = _pdns([("55e4907eff93797b070e4a7fbf64666b.admin.ex.com", "CNAME",
                   "4fd830a409fc8bdbfb11ed66db0442358d50806a.comodoca.com.", 60)])
    lookups = _lookups([("4fd830a409fc8bdbfb11ed66db0442358d50806a.comodoca.com", "", ""),
                        ("comodoca.com", "NS", "ns1.comodoca.com")])
    tree, todo = _tree(pdns, lookups)
    row = tree.iloc[0]
    assert todo == [] and row["Status"] == r.STALE and row["Severity"] == "" and row["Dangling"] == []
    assert row["Service"] == ["Sectigo (Comodo) certificate validation"] and "cannot be claimed" in row["Reason"][0]
    pending, _ = _tree(pdns)
    assert pending.iloc[0]["Status"] == r.PENDING                # until Resolve looks the target up


def test_lookups_saved_before_the_lookup_column_still_load():
    old = _lookups([("x.host.net", "A", "198.51.100.1")]).drop(columns="Lookup")
    merged = r.merge_lookups(old, pd.DataFrame(r.lookup_rows("y.host.net", [], NOW)))
    assert list(merged["Lookup"]) == ["x.host.net", "y.host.net"]
    assert r.build_index(None, old).looked == {"x.host.net"}


def _origin(ip, prefix, origin, status="Valid", collectors=40, updates=10, rpki="valid", irr="valid"):
    return {"IP": ip, "Domains": "", "Prefix": prefix, "Origin": origin, "AS Name": f"NET-{origin}", "Status": status,
            "Updates": updates, "Collectors": collectors, "Core": 0, "IRR": irr, "RPKI": rpki}


def test_resolved_addresses_carry_their_routing_and_warnings():
    from core import bgp
    pdns = _pdns([("www.ex.com", "CNAME", "edge.host.net.", 0), ("ex.com", "A", "93.184.216.34", 0)])
    lookups = _lookups([("edge.host.net", "A", "185.10.10.9")])
    hosting = pd.DataFrame([_origin("93.184.216.34", "93.184.216.0/24", "AS15133")]).reindex(columns=bgp.ORIGIN_COLUMNS)
    resolved = pd.DataFrame([
        _origin("185.10.10.9", "185.10.10.0/24", "AS64500", status=bgp.UNAUTHORIZED, rpki="invalid origin",
                collectors=3, updates=50),
        _origin("185.10.10.9", "185.10.10.0/24", "AS64511", updates=2),
        _origin("198.51.100.1", "", "", collectors=0)]).reindex(columns=bgp.ORIGIN_COLUMNS)   # nothing announced
    routing = r.routing_table(hosting, resolved, findings={"93.184.216.34": "Newly Announced Prefix"})
    assert set(routing) == {"93.184.216.34", "185.10.10.9"}
    assert routing["185.10.10.9"]["Origin"] == "AS64500" and routing["185.10.10.9"]["Origins"] == ["AS64500", "AS64511"]
    tree, _ = r.build_tree(r.build_index(pdns, lookups, {}, ["ex.com"]), ["ex.com"], routing)
    www = _row(tree, "www.ex.com", "CNAME")
    assert www["Origins"] == ["AS64500 NET-AS64500"] and "Unauthorized" in www["Routing"][0]
    text = " ".join(www["Warnings"])
    assert "which RPKI / IRR does not authorize" in text and "also announced by AS64511" in text
    assert "seen by only 3 route collector(s)" in text
    assert "Newly Announced Prefix" in _row(tree, "ex.com", "A")["Warnings"][0]
    summary = r.origins(tree, routing)
    assert list(summary["Origin"]) == ["AS64500", "AS15133"]                # unauthorized first
    assert summary.iloc[0][["Unauthorized", "Min Collectors", "Record Types"]].tolist() == [1, 3, "CNAME"]
    assert r.unrouted_ips(tree, hosting) == ["185.10.10.9"]
    assert r.unrouted_ips(tree, hosting, resolved) == []
    assert "198.51.100.1" in r.routed_set(resolved)                         # looked up, nothing announced: not again


def test_route_ips_looks_up_each_address_once(monkeypatch):
    from integrations import bgpdb, collector
    from integrations.http import FetchResult, StatusLog
    monkeypatch.setattr(bgpdb, "load_bgpdb_host", lambda: "bgpdb.example")
    answers = {"185.10.10.9": [{"prefix": "185.10.10.0/24", "origin": 64500, "count": 5, "collectors": 30,
                                "rpki_valid": True}]}
    monkeypatch.setattr(bgpdb, "lookup_ip", lambda ip: FetchResult("BGPDB", ip, data=answers.get(ip, [])))
    run = collector.route_ips(["185.10.10.9", "198.51.100.1"], None, StatusLog())
    assert run.looked == 2 and not run.stopped
    assert set(run.origins["IP"]) == {"185.10.10.9", "198.51.100.1"}
    routing = r.routing_table(run.origins)
    assert routing["185.10.10.9"]["Status"] == "Valid" and "198.51.100.1" not in routing
    again = collector.route_ips(["185.10.10.9"], run.origins, StatusLog())
    assert len(again.origins) == 2
    monkeypatch.setattr(bgpdb, "load_bgpdb_host", lambda: "")
    assert collector.route_ips(["1.1.1.1"], None, StatusLog()).left == 1


def test_resolved_addresses_table_and_raw_answers(monkeypatch):
    from core import bgp
    from integrations import bgpdb, collector
    from integrations.http import FetchResult, StatusLog
    pdns = _pdns([("www.ex.com", "CNAME", "edge.host.net.", 0), ("ex.com", "A", "93.184.216.34", 0),
                  ("ex.com", "MX", "10 mx.host.net.", 0)])
    lookups = _lookups([("edge.host.net", "A", "185.10.10.9"), ("mx.host.net", "A", "185.10.10.9")])
    hosting = pd.DataFrame([_origin("93.184.216.34", "93.184.216.0/24", "AS15133")]).reindex(columns=bgp.ORIGIN_COLUMNS)
    monkeypatch.setattr(bgpdb, "load_bgpdb_host", lambda: "bgpdb.example")
    monkeypatch.setattr(bgpdb, "lookup_ip", lambda ip: FetchResult("BGPDB", ip, data=[
        {"prefix": "185.10.10.0/24", "origin": 205000, "count": 5, "collectors": 2, "rpki_invalid_origin": True}]))
    run = collector.route_ips(["185.10.10.9"], None, StatusLog())
    assert list(run.raw["Command"]) == ["ip"] and run.raw.iloc[0]["Detail"].startswith("DNS resolution")
    collected = type("C", (), {"bgp_raw": pd.DataFrame([{"Command": "ip", "Argument": "93.184.216.34"}])})()
    run.keep_raw(collected)
    assert list(collected.bgp_raw["Argument"]) == ["93.184.216.34", "185.10.10.9"]
    routing = r.routing_table(hosting, run.origins)
    tree, _ = r.build_tree(r.build_index(pdns, lookups, {}, ["ex.com"]), ["ex.com"], routing)
    rows = r.resolved_routing(tree, routing, hosting)
    assert list(rows["IP"]) == ["185.10.10.9"]                   # the hosting IP is on the BGP page already
    row = rows.iloc[0]
    assert row["Reached By"] == "ex.com MX, www.ex.com CNAME" and row["Status"] == bgp.UNAUTHORIZED
    assert "seen by only 2 route collector(s)" in row["Warnings"]


def test_bogons_and_internal_addresses():
    assert [r.address_class(v) for v in ("10.1.2.3", "fd00::1", "127.0.0.1", "100.64.1.1", "192.0.2.7", "240.0.0.1",
                                         "0.0.0.0/8", "8.8.8.8", "185.10.10.0/24")] == \
        ["internal", "internal", "internal", "bogon", "bogon", "bogon", "bogon", "", ""]
    pdns = _pdns([("lab.ex.com", "A", "100.64.3.4", 0), ("ex.com", "TXT", '"v=spf1 ip4:192.168.0.0/16 -all"', 0)])
    tree, _ = _tree(pdns)
    assert "Bogon address 100.64.3.4" in _row(tree, "lab.ex.com", "A")["Warnings"][0]
    assert _row(tree, "ex.com", "TXT")["Warnings"] == ["Internal IP 192.168.0.0/16 in public DNS"]
    route = {"IP": "185.10.10.9", "Prefix": "185.10.10.0/24", "Origin": "AS64512", "AS Name": "", "Status": "Valid",
             "IRR": "valid", "RPKI": "valid", "Collectors": 40, "Origins": ["AS64512"], "Findings": ""}
    assert r.routing_warnings("185.10.10.9", route) == ["BGP 185.10.10.9: bogon origin AS64512 (private or reserved AS "
                                                        "number)"]

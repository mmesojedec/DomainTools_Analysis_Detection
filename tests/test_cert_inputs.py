import json
from unittest import mock

import pandas as pd

from core.cert_inputs import (
    InputItem,
    derive_targets,
    domain_search_query,
    input_problems,
    parse_inputs,
    run_key_labels,
    seed_query,
)
from core.persistence import target_set_key
from integrations import certificates, collector
from integrations.http import FetchResult

SHA256 = "a" * 63 + "b"


def kinds(raw):
    return [(item.kind, item.value) for item in parse_inputs(raw)]


def test_domains_ips_and_hashes_are_recognized():
    raw = f"example.com hxxp://evil[.]net/path, 203.0.113.5\n{SHA256.upper()}\n{'c' * 40}\n{'d' * 32}"
    assert kinds(raw) == [("domain", "example.com"), ("domain", "evil.net"), ("ip", "203.0.113.5"),
                          ("sha256", SHA256), ("sha1", "c" * 40), ("md5", "d" * 32)]
    assert all(item.auto for item in parse_inputs(SHA256))


def test_colon_separated_fingerprint_is_recognized():
    colon = ":".join(SHA256[i:i + 2] for i in range(0, 64, 2)).upper()
    assert kinds(colon) == [("sha256", SHA256)]


def test_prefixed_lines_are_read_whole():
    raw = "cn: Kubernetes Ingress Controller Fake Certificate\norg:\"Acme Corp\"\nissuer: R11\ncn~:login\nsan:*.Example.com\n" \
          "spki:" + SHA256 + "\nserial: 0A:1B:2C"
    assert kinds(raw) == [("cn", "Kubernetes Ingress Controller Fake Certificate"), ("org", "Acme Corp"), ("issuer", "R11"),
                          ("cn~", "login"), ("san", "*.example.com"), ("spki", SHA256), ("serial", "0a1b2c")]
    assert kinds("*.example.com") == [("san", "*.example.com")]


def test_duplicates_are_removed_and_labels_are_stable():
    items = parse_inputs(f"{SHA256}\nsha256:{SHA256}\nexample.com\nexample.com")
    assert [i.label for i in items] == [f"sha256:{SHA256}", "example.com"]


def test_input_problems_are_caught_before_any_api_call():
    items = parse_inputs("sha256:abc\ncn~:ab\nspki:" + "z" * 64)
    problems = input_problems(items)
    assert len(problems) == 3 and "64 hexadecimal" in problems[0] and "3 to 63" in problems[1]
    assert input_problems(parse_inputs(f"{SHA256}\ncn:x")) == []


def test_seed_queries_follow_certsql():
    assert seed_query(InputItem("sha256", SHA256)) == f"# CertsQL-1.0\nsha256 in {json.dumps([SHA256, SHA256.upper()])}\n"
    assert "public_key_sha256 in" in seed_query(InputItem("spki", SHA256))
    assert seed_query(InputItem("cn", "Acme VPN")) == '# CertsQL-1.0\nsubject_common_name equals "Acme VPN"\n'
    assert "subject_common_name contains \"login\"" in seed_query(InputItem("cn~", "login"))
    assert seed_query(InputItem("issuer", "R11")).count("\n") == 3   # two OR'd lines in one clause
    assert "san_ip_v4 between" in seed_query(InputItem("san", "203.0.113.5"))
    assert "san_ip_v6 between" in seed_query(InputItem("san", "2001:db8::1"))
    assert 'san_dns equals "*.example.com"' in seed_query(InputItem("san", "*.example.com"))


def test_domain_search_includes_subdomains():
    assert domain_search_query("Example.com.") == '# CertsQL-1.0\nsan_dns equals "example.com"\nsan_dns ends_with ".example.com"\n'
    assert dict(certificates.build_search_queries(["example.com"]))["example.com"] == domain_search_query("example.com")


def test_derive_targets_from_sans_cn_and_observations():
    seed = InputItem("sha256", SHA256)
    hits = [
        {"sha256": "c1", "san_dns": ["www.example.com", "*.example.com", "login.other.org", "sni.cloudflaressl.com"],
         "san_ip_v4": ["93.184.216.34", "10.0.0.1"]},
        {"sha256": "c2", "san_dns": ["api.example.com"]},
        {"sha256": "c3", "subject_common_name": "panel.bad.xyz"},             # no SANs: CN used
        {"sha256": "c4", "subject_common_name": "Acme Internal CA"},          # not a hostname
    ]
    events = [{"sha256": SHA256, "domain": "seen.net", "hostname": "a.seen.net", "ip": "151.101.1.1"}]
    # 10.0.0.1 (private) and the Cloudflare SNI name are never offered
    derived = derive_targets([(seed, hits, events)], max_selected=2).set_index("Target")
    assert set(derived.index) == {"example.com", "other.org", "93.184.216.34", "bad.xyz", "seen.net", "151.101.1.1"}
    assert derived.loc["example.com", "Certificates"] == 2 and derived.loc["example.com", "Via"] == "SAN DNS"
    assert derived.loc["bad.xyz", "Via"] == "CN" and derived.loc["93.184.216.34", "Type"] == "IP"
    assert derived.loc["seen.net", "Via"] == "Observed domain, Observed hostname"
    assert derived["Analyze"].sum() == 2 and derived.loc["example.com", "Analyze"]   # most certificates pre-selected first
    assert derived.loc["example.com", "Seeds"] == seed.label


def test_derive_targets_empty():
    derived = derive_targets([(InputItem("cn", "x"), [], [])])
    assert derived.empty and list(derived.columns)[:2] == ["Analyze", "Target"]


def test_run_key_includes_certificate_inputs():
    plain = target_set_key(run_key_labels(["a.com"], []))
    assert plain == target_set_key(["a.com"])                                # unchanged for plain runs
    assert target_set_key(run_key_labels(["a.com"], ["cn:Acme"])) != plain


def test_resolve_seeds_retries_auto_sha256_as_public_key():
    calls = []

    def fake_search(target, query, max_records=0):
        calls.append(query)
        hits = [{"sha256": "c9", "san_dns": ["key.example.com"]}] if "public_key_sha256" in query else []
        return FetchResult("Certificate Search", target, data=hits, record_count=len(hits))

    with mock.patch.object(collector, "search_certificates", fake_search), \
            mock.patch.object(collector, "fetch_cert_events_sha256",
                              lambda sha, max_records=0: FetchResult("Cert Events (SHA256)", sha, data=[])):
        resolution = collector.resolve_seeds(parse_inputs(SHA256))
    assert len(calls) == 2 and "public_key_sha256" in calls[1]
    row = resolution.seeds.iloc[0]
    assert row["Seed"] == f"spki:{SHA256}" and row["Certificates"] == 1 and "public key" in row["Note"]
    assert list(resolution.derived["Target"]) == ["example.com"] and row["Derived Targets"] == 1


def test_resolve_seeds_uses_observations_for_fingerprints():
    hits = [{"sha256": SHA256, "san_dns": ["a.com"]}]
    events = [{"sha256": SHA256, "domain": "b.com", "ip": "93.184.216.34"}]
    with mock.patch.object(collector, "search_certificates",
                           lambda target, query, max_records=0: FetchResult("Certificate Search", target, data=hits)), \
            mock.patch.object(collector, "fetch_cert_events_sha256",
                              lambda sha, max_records=0: FetchResult("Cert Events (SHA256)", sha, data=events)):
        resolution = collector.resolve_seeds([InputItem("sha256", SHA256)])
    assert set(resolution.derived["Target"]) == {"a.com", "b.com", "93.184.216.34"}
    assert resolution.seeds.iloc[0]["Observations"] == 1
    assert {row["Source"] for row in resolution.statuses} == {"Certificate Search", "Cert Events (SHA256)"}


def test_certificate_events_send_a_one_year_window():
    payloads = []

    def fake_post(path, payload, api_key):
        payloads.append(payload)
        return {"events": [], "pagination": {"has_more": False}}, None

    with mock.patch.object(certificates, "_post", fake_post), mock.patch.object(certificates, "load_cert_api_key", lambda: "k"):
        certificates._fetch_paginated_events("Cert Events (Hostname)", "a.com", "events/hostname",
                                             {"hostname": "a.com"}, "events", 10)
    start = pd.Timestamp(payloads[0]["start_time"])
    days = (pd.Timestamp.now() - start).days
    assert 365 <= days <= 366 and payloads[0]["hostname"] == "a.com"


def test_offline_round_trip_keeps_seeds(tmp_path, monkeypatch):
    from core import offline
    monkeypatch.setattr(offline, "OFFLINE_DIR", tmp_path)
    data = collector.CollectedData(targets=["a.com"], seed_inputs=["cn:Acme"],
                                   seeds=pd.DataFrame([{"Seed": "cn:Acme", "Certificates": 2}]),
                                   derived=pd.DataFrame([{"Target": "a.com", "Via": "SAN DNS"}]))
    manifest = offline.save_offline_dataset(data)
    loaded, saved_manifest = offline.load_offline_dataset(manifest["id"])
    assert loaded.seed_inputs == ["cn:Acme"] and saved_manifest["seeds"] == ["cn:Acme"]
    assert loaded.seeds.iloc[0]["Seed"] == "cn:Acme" and loaded.derived.iloc[0]["Via"] == "SAN DNS"


def test_snapshot_stores_seeds(tmp_path, monkeypatch):
    from core import persistence
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path)
    key = target_set_key(run_key_labels(["a.com"], ["cn:Acme"]))
    snapshot = persistence.save_snapshot(key, ["a.com"], {}, pd.DataFrame(), seeds=["cn:Acme"])
    assert snapshot["seeds"] == ["cn:Acme"]
    assert persistence.list_target_sets()[0]["seeds"] == ["cn:Acme"]


SERIAL = "65f2be6f97a1fb4b0e52c45675e55788"   # 16-byte serial: same length as an MD5 fingerprint


def test_hex_of_hash_length_is_searched_as_fingerprint_or_serial():
    item = parse_inputs(SERIAL)[0]
    assert (item.kind, item.ambiguous, item.kind_name) == ("md5", True, "MD5 or serial")
    query = seed_query(item)
    assert "md5 in" in query and "serial_number in" in query and "\nAND" not in query   # one clause: either matches
    assert parse_inputs("c" * 40)[0].ambiguous
    assert not parse_inputs(f"md5:{SERIAL}")[0].ambiguous and "serial_number" not in seed_query(parse_inputs(f"md5:{SERIAL}")[0])


def test_other_hex_lengths_are_serials_not_domains():
    for serial in ("3987ad14", "00d0ea69cf76138168131b9e06ebed24c7", "4c0000003ba4231f15ad46b2d600010000003b", "0x3987AD14"):
        item = parse_inputs(serial)[0]
        assert (item.kind, item.auto) == ("serial", True), serial
    assert parse_inputs("0x3987AD14")[0].value == "3987ad14"
    assert parse_inputs("serial: 0x65:F2:BE")[0].value == "65f2be"
    assert kinds("cafe example.com") == [("domain", "example.com"), ("org~", "cafe")]   # short hex words are text, not serials


def test_matched_kind_decides_between_hash_and_serial():
    from core.cert_inputs import matched_kind
    item = parse_inputs(SERIAL)[0]
    assert matched_kind(item, [{"md5": SERIAL.upper()}]) == "md5"
    assert matched_kind(item, [{"md5": "x", "serial_number": SERIAL}]) == "serial"
    assert matched_kind(item, []) == "md5"


def test_resolve_seeds_relabels_a_serial_match():
    hits = [{"sha256": "c1", "md5": "other", "serial_number": SERIAL, "san_dns": ["a.example.com"]}]
    with mock.patch.object(collector, "search_certificates",
                           lambda target, query, max_records=0: FetchResult("Certificate Search", target, data=hits)), \
            mock.patch.object(collector, "fetch_cert_events_sha256",
                              lambda sha, max_records=0: FetchResult("Cert Events (SHA256)", sha, data=[])):
        resolution = collector.resolve_seeds(parse_inputs(SERIAL))
    row = resolution.seeds.iloc[0]
    assert row["Seed"] == f"serial:{SERIAL}" and row["Note"] == "Matched as a serial number"
    assert list(resolution.derived["Target"]) == ["example.com"]


def test_search_as_labels_round_trip():
    from core.cert_inputs import SEARCH_AS, item_for, search_as_label
    for raw in (SHA256, SERIAL, "c" * 40, "3987ad14", "cn:Acme VPN", "cn~:login", "san:*.example.com", "org:Acme",
                "issuer:R11", f"spki:{SHA256}", f"md5:{SERIAL}", f"sha256:{SHA256}"):
        item = parse_inputs(raw)[0]
        label = search_as_label(item)
        assert label in SEARCH_AS and seed_query(item_for(item.value, label)) == seed_query(item), raw   # same search
    assert search_as_label(parse_inputs(SHA256)[0]) == "SHA-256 (or public key)"
    assert search_as_label(parse_inputs(SERIAL)[0]) == "MD5 or serial"


def test_changing_search_as_changes_the_query():
    from core.cert_inputs import item_for
    as_serial = item_for(SERIAL, "Serial")
    assert (as_serial.kind, as_serial.auto) == ("serial", False)
    assert "serial_number in" in seed_query(as_serial) and "md5" not in seed_query(as_serial)
    assert input_problems([item_for(SHA256, "MD5")]) == [f"md5:{SHA256}: expected 32 hexadecimal characters"]
    assert item_for("0x65:F2", "Serial").value == "65f2"


def test_seed_certificates_are_reused_in_the_run():
    """Records found by a certificate input are merged into the run's certificates, without another lookup for them."""
    seed_hit = {"sha256": "s1", "san_dns": ["vpn.example.com"], "subject_common_name": "vpn.example.com"}
    other_hit = {"sha256": "s2", "san_dns": ["www.example.com"]}
    log = collector.StatusLog()
    with mock.patch.object(collector, "search_certificates",
                           lambda target, query, max_records=0: FetchResult("Certificate Search", target, data=[other_hit])):
        ssl = collector.collect_certificates(["example.com"], log, seed_hits=[seed_hit])
    assert set(ssl["Hash"]) == {"s1", "s2"} and set(ssl["Domain"]) == {"example.com"}
    with mock.patch.object(collector, "search_certificates",
                           lambda target, query, max_records=0: FetchResult("Certificate Search", target, data=[seed_hit])):
        ssl = collector.collect_certificates(["example.com"], log, seed_hits=[seed_hit])
    assert list(ssl["Hash"]) == ["s1"]   # found twice, kept once


def test_resolution_keeps_items_and_hits():
    hits = [{"sha256": "c1", "serial_number": SERIAL, "san_dns": ["a.example.com"]}]
    with mock.patch.object(collector, "search_certificates",
                           lambda target, query, max_records=0: FetchResult("Certificate Search", target, data=hits)), \
            mock.patch.object(collector, "fetch_cert_events_sha256",
                              lambda sha, max_records=0: FetchResult("Cert Events (SHA256)", sha, data=[])):
        resolution = collector.resolve_seeds(parse_inputs(SERIAL))
    assert [i.label for i in resolution.items] == [f"serial:{SERIAL}"] and resolution.hits == hits


def test_company_names_are_organization_searches_not_domains():
    assert kinds("DomainTools LLC") == [("org~", "DomainTools LLC")]
    assert kinds("DomainTools") == [("org~", "DomainTools")]
    assert kinds("Acme, Inc.") == [("org~", "Acme, Inc.")]
    assert kinds("example.com Acme Corp 8.8.8.8") == [("domain", "example.com"), ("ip", "8.8.8.8"), ("org~", "Acme Corp")]
    assert kinds("HP") == [("org", "HP")]   # too short for `contains`: exact match
    assert seed_query(parse_inputs("DomainTools LLC")[0]) == '# CertsQL-1.0\nsubject_organization contains "DomainTools LLC"\n'
    assert all(item.is_certificate for item in parse_inputs("DomainTools LLC"))


def test_organization_search_as_choices():
    from core.cert_inputs import item_for, search_as_label
    item = parse_inputs("DomainTools")[0]
    assert search_as_label(item) == "Organization contains"
    assert seed_query(item_for("DomainTools LLC", "Organization")).endswith('subject_organization equals "DomainTools LLC"\n')
    assert input_problems([item_for("ab", "Organization contains")]) == ["org~:ab: 'contains' text must be 3 to 63 characters"]
    assert input_problems([item_for("", "Organization")]) == ["Organization: enter a value to search"]
    assert kinds("org~:DomainTools") == [("org~", "DomainTools")]


def test_found_certificates_are_listed_for_review():
    from views.seed_view import CERTIFICATE_COLUMNS, certificate_rows
    hits = [{"subject_common_name": "domaintools.com", "subject_organization": "DomainTools LLC",
             "issuer_common_name": "Sectigo Public Server Authentication CA EV R36", "validation_level": "ev",
             "validity_not_before": "2026-01-02T00:00:00Z", "validity_not_after": "2026-12-31T23:59:59Z",
             "san_dns": ["domaintools.com", "api.domaintools.com"], "sha256": SHA256},
            {"subject_common_name": "domaintools.com", "validity_not_before": "2026-08-20T00:00:00Z", "sha256": "b" * 64}]
    rows = certificate_rows(hits)
    assert list(rows.columns) == CERTIFICATE_COLUMNS
    assert rows["SHA-256"].tolist() == ["b" * 64, SHA256]   # newest first
    assert rows.loc[1, "Validation"] == "EV" and rows.loc[1, "SANs"] == "domaintools.com, api.domaintools.com"
    assert certificate_rows([]).empty


DT_SANS = ["domaintools.com", "account.domaintools.com", "api.domaintools.com", "iris.domaintools.com"]


def test_hostnames_are_kept_per_apex():
    from core.cert_inputs import HOSTNAME_COLUMNS, derive_hostnames
    seed = InputItem("org~", "DomainTools")
    hits = [{"sha256": "c1", "san_dns": DT_SANS + ["*.Other.org", "sni.cloudflaressl.com"], "san_ip_v4": ["93.184.216.34"]},
            {"sha256": "c2", "san_dns": ["api.domaintools.com"]}]
    hosts = derive_hostnames([(seed, hits, [])])
    assert list(hosts.columns) == HOSTNAME_COLUMNS and not hosts["Focus"].any()
    assert set(hosts["Hostname"]) == {*DT_SANS, "*.other.org"}          # no IPs, no shared CDN names
    by_name = hosts.set_index("Hostname")
    assert by_name.loc["api.domaintools.com", "Apex"] == "domaintools.com" and by_name.loc["*.other.org", "Apex"] == "other.org"
    assert hosts.iloc[0]["Hostname"] == "api.domaintools.com"              # per apex, most certificates first
    derived = derive_targets([(seed, hits, [])]).set_index("Target")
    assert derived.loc["domaintools.com", "Hostnames"] == 4 and derived.loc["93.184.216.34", "Hostnames"] == 0


def test_host_focus_from_ticked_rows():
    from core.cert_inputs import derive_hostnames, host_focus_from
    hosts = derive_hostnames([(InputItem("cn", "x"), [{"sha256": "c1", "san_dns": DT_SANS}], [])])
    assert host_focus_from(hosts) == {}
    hosts.loc[hosts["Hostname"].isin(["iris.domaintools.com", "api.domaintools.com"]), "Focus"] = True
    assert host_focus_from(hosts) == {"domaintools.com": ["api.domaintools.com", "iris.domaintools.com"]}


def test_hostname_search_names_hostnames_and_covering_wildcards():
    from core.cert_inputs import hostname_search_query
    query = hostname_search_query(["api.domaintools.com", "domaintools.com", "*.domaintools.com", "a.b.domaintools.com"])
    assert query == ('# CertsQL-1.0\nsan_dns equals "api.domaintools.com"\nsan_dns equals "domaintools.com"\n'
                     'san_dns equals "*.domaintools.com"\nsan_dns equals "a.b.domaintools.com"\n'
                     'san_dns equals "*.b.domaintools.com"\n')


def _record(name, first=1700000000):
    return {"rrname": f"{name}.", "rrtype": "A", "rdata": ["93.184.216.34"], "time_first": first, "time_last": first + 100}


def test_apex_is_looked_up_in_full_and_gaps_filled_only_when_capped(monkeypatch):
    calls = []

    def fake_dnsdb(target, limit=5000, rrtype="ANY", include_wildcard=True):
        calls.append((target, include_wildcard))
        if target == "domaintools.com":
            return FetchResult("DNSDB Scout", target, data=[_record("www.domaintools.com")], truncated=capped)
        return FetchResult("DNSDB Scout", target, data=[_record(target, 1600000000)])

    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake_dnsdb)
    focus = {"domaintools.com": ["api.domaintools.com"]}
    capped = False
    pdns, coverage = collector.collect_pdns(["domaintools.com"], 10, collector.StatusLog())
    assert collector.fill_pdns_gaps(pdns, coverage, focus, 10, collector.StatusLog()) is pdns   # complete: no extra lookup
    assert calls == [("domaintools.com", True)]
    capped, log = True, collector.StatusLog()
    pdns, coverage = collector.collect_pdns(["domaintools.com"], 10, log)
    merged = collector.fill_pdns_gaps(pdns, coverage, focus, 10, log)
    assert ("api.domaintools.com", False) in calls and set(merged["Domain"]) == {"domaintools.com"}
    assert set(merged["RRName"]) == {"www.domaintools.com", "api.domaintools.com"}
    assert any(row["Source"] == "DNSDB Hostname Gap-Fill" for row in log.rows)


def test_certificate_and_event_gaps_filled_only_when_capped():
    searches, events = [], []

    def fake_search(target, query, max_records=0):
        searches.append(query)
        hits = [{"sha256": "h1", "san_dns": ["api.domaintools.com"]}] if "equals \"api" in query else \
            [{"sha256": "h0", "san_dns": ["www.domaintools.com"]}]
        return FetchResult("Certificate Search", target, data=hits, truncated="ends_with" in query)

    def fake_events(hostname, include_subdomains=True, max_records=0):
        events.append((hostname, include_subdomains))
        return FetchResult("Cert Events (Hostname)", hostname, data=[{"hostname": hostname, "sha256": "e"}],
                           truncated=hostname == "domaintools.com")

    focus = {"domaintools.com": ["api.domaintools.com", "*.domaintools.com"]}
    with mock.patch.object(collector, "search_certificates", fake_search), \
            mock.patch.object(collector, "fetch_cert_events_hostname", fake_events):
        log = collector.StatusLog()
        ssl = collector.collect_certificates(["domaintools.com"], log, host_focus=focus)
        frame = collector.collect_cert_events(["domaintools.com"], [], log, focus)
        assert len(searches) == 2 and set(ssl["Hash"]) == {"h0", "h1"}
        assert events == [("domaintools.com", True), ("api.domaintools.com", False)]   # wildcards are not observable
        assert set(frame["Domain"]) == {"domaintools.com"}
        searches.clear()
        collector.collect_certificates(["domaintools.com"], log)                     # no focus: no gap-fill
        assert len(searches) == 1


def test_collect_all_keeps_focus_for_analyzed_domains_only(monkeypatch):
    monkeypatch.setattr(collector, "collect_domain_history", lambda domains, log, days=0, max_changes=1000: (pd.DataFrame(), pd.DataFrame()))
    monkeypatch.setattr(collector, "collect_certificates", lambda *a: pd.DataFrame())
    monkeypatch.setattr(collector, "collect_enrichment", lambda *a: {})
    monkeypatch.setattr(collector, "collect_pdns", lambda *a: (pd.DataFrame(), {}))
    monkeypatch.setattr(collector, "collect_cert_events", lambda *a: pd.DataFrame())
    data = collector.collect_all(["a.com"], 10, include_ct=False,
                                 host_focus={"a.com": ["x.a.com"], "b.com": ["y.b.com"], "c.com": []})
    assert data.host_focus == {"a.com": ["x.a.com"]}


def test_focus_is_stored_in_snapshot_and_offline_but_not_the_run_key(tmp_path, monkeypatch):
    from core import offline, persistence
    focus = {"domaintools.com": ["api.domaintools.com"]}
    monkeypatch.setattr(persistence, "RUNS_DIR", tmp_path / "runs")
    snapshot = persistence.save_snapshot(target_set_key(["domaintools.com"]), ["domaintools.com"], {}, pd.DataFrame(),
                                         host_focus=focus)
    assert snapshot["host_focus"] == focus
    monkeypatch.setattr(offline, "OFFLINE_DIR", tmp_path / "offline")
    manifest = offline.save_offline_dataset(collector.CollectedData(targets=["domaintools.com"], host_focus=focus))
    loaded, saved = offline.load_offline_dataset(manifest["id"])
    assert loaded.host_focus == focus and saved["host_focus"] == focus

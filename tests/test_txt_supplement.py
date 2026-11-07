import pandas as pd

import integrations.collector as collector
from integrations.dnsdb import _lookup_urls, fetch_dnsdb_history
from integrations.http import FetchResult, StatusLog
from integrations.iris import build_pdns_payload

DAY = 86400
BASE = 1704067200  # 2024-01-01


def dnsdb_txt(name, value, day):
    return {"rrname": f"{name}.", "rrtype": "TXT", "rdata": [f'"{value}"'], "time_first": BASE + day * DAY, "time_last": BASE + day * DAY + 3600}


def test_txt_lookup_urls_and_ip_skip():
    urls = _lookup_urls("a.com", "TXT")
    assert urls[0].endswith("/rrset/name/*.a.com/TXT") and urls[1].endswith("/rrset/name/a.com/TXT")
    result = fetch_dnsdb_history.__wrapped__("1.2.3.4", 10, "TXT")
    assert result.ok and result.data == [] and result.source == "DNSDB TXT Supplement"


def test_iris_txt_payload():
    payload = build_pdns_payload("a.com", "TXT")
    assert payload["rrtype"] == "TXT" and payload["sort_on"] == "time_first" and payload["sort_descending"]
    assert build_pdns_payload("a.com")["rrtype"] == ""


def test_latest_records_per_domain():
    frame = pd.DataFrame({
        "Domain": ["a.com"] * 3 + ["b.com"],
        "First Seen": pd.to_datetime(["2024-01-01", "2024-02-01", "2024-03-01", "2024-01-01"]),
        "Last Seen": pd.to_datetime(["2024-01-05", None, "2024-03-05", "2024-01-02"]),
    })
    kept = collector.latest_records(frame, 2)
    assert list(kept["First Seen"].dt.strftime("%m")) == ["03", "02", "01"]  # a.com: Mar, Feb (fallback); b.com: Jan
    assert collector.latest_records(frame, 0).empty


def test_dnsdb_supplement_merges_missing_txt(monkeypatch):
    def fake_fetch(target, limit=5000, rrtype="ANY", include_wildcard=True):
        if rrtype == "TXT":
            records = [dnsdb_txt("a.com", f"v=spf1 include:mail{i}.example -all", i) for i in range(15)]
            records.append({"rrname": "a.com.", "rrtype": "A", "rdata": ["1.1.1.1"], "time_first": BASE, "time_last": BASE + 60})  # main dup
            return FetchResult("DNSDB TXT Supplement", target, data=[r for r in records if r["rrtype"] == "TXT"], record_count=15)
        return FetchResult("DNSDB Scout", target, data=[{"rrname": "a.com.", "rrtype": "A", "rdata": ["1.1.1.1"], "time_first": BASE, "time_last": BASE + 60},
                                                        dnsdb_txt("a.com", "v=spf1 include:mail14.example -all", 14)], record_count=2,
                           truncated=True)   # supplements only run where the main lookup was cut off

    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake_fetch)
    log = StatusLog()
    pdns, _ = collector.collect_pdns(["a.com", "9.9.9.9"], "DNSDB Scout", 2, log, txt_records=10)
    txt = pdns[(pdns["Field"] == "TXT") & (pdns["Domain"] == "a.com")]
    assert len(txt) == 10  # latest 10 kept; the newest one was already in the main results and is not duplicated
    assert (txt["Collection"] == "TXT supplement").sum() == 9
    statuses = {(r["Source"], r["Target"]): r for r in log.rows}
    assert "Kept latest 10 of 15" in statuses[("DNSDB TXT Supplement", "a.com")]["Detail"]
    assert statuses[("TXT Supplement", "1 domain(s)")]["Records"] == 9
    assert ("DNSDB TXT Supplement", "9.9.9.9") not in statuses  # IP targets are not queried for TXT


def test_supplement_disabled(monkeypatch):
    calls = []
    monkeypatch.setattr(collector, "fetch_dnsdb_history", lambda t, limit=5000, rrtype="ANY", include_wildcard=True: calls.append(rrtype) or FetchResult("DNSDB Scout", t, data=[]))
    collector.collect_pdns(["a.com"], "DNSDB Scout", 10, StatusLog(), txt_records=0)
    assert calls == ["ANY"]


def test_iris_supplement_uses_same_session_extras(monkeypatch):
    def fake_iris(targets, on_auth_required=None, on_auth_done=None, extra_rrtypes=(), if_capped_rrtypes=(), on_result=None):
        return {t: one(t, extra_rrtypes) for t in targets}

    def one(target, extra_rrtypes):
        main = FetchResult("Iris pDNS", target, data=[{"rrname": "a.com", "rrtype": "A", "rdata": "1.1.1.1", "first_seen": "2024-01-01T00:00:00Z"}],
                           record_count=1)
        if "TXT" in extra_rrtypes:
            main.extras["TXT"] = FetchResult("Iris pDNS TXT Supplement", target, record_count=3, data=[
                {"rrname": "_dmarc.a.com", "rrtype": "TXT", "rdata": f'"v=DMARC1; p=reject; ri={i}"',
                 "first_seen": f"2024-0{i + 1}-01T00:00:00Z", "last_seen": f"2024-0{i + 1}-02T00:00:00Z"} for i in range(3)])
        return main

    monkeypatch.setattr(collector, "fetch_iris_pdns_many", fake_iris)
    log = StatusLog()
    pdns, _ = collector.collect_pdns(["a.com"], "Iris pDNS", 0, log, txt_records=2)
    txt = pdns[pdns["Field"] == "TXT"]
    assert len(txt) == 2 and set(txt["RRName"]) == {"_dmarc.a.com"}
    assert list(txt.sort_values("First Seen")["First Seen"].dt.month) == [2, 3]
    assert any(r["Source"] == "Iris pDNS TXT Supplement" and "Kept latest 2 of 3" in r["Detail"] for r in log.rows)


def test_dnsdb_supplements_skip_domains_whose_main_lookup_was_complete(monkeypatch):
    calls = []

    def fake_fetch(target, limit=5000, rrtype="ANY", include_wildcard=True):
        calls.append((target, rrtype))
        return FetchResult("DNSDB Scout", target, data=[], truncated=rrtype == "ANY" and target == "big.com", record_count=0)

    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake_fetch)
    log = StatusLog()
    collector.collect_pdns(["big.com", "small.com"], "DNSDB Scout", 10, log, txt_records=5, caa_lookup=True)
    assert sorted(calls) == [("big.com", "ANY"), ("big.com", "CAA"), ("big.com", "TXT"), ("small.com", "ANY")]
    skipped = {r["Source"]: r for r in log.rows if r["Target"] == "1 domain(s)"}
    assert set(skipped) == {"DNSDB TXT Supplement", "DNSDB CAA Supplement"}
    assert skipped["DNSDB TXT Supplement"]["Detail"].startswith("Not needed")


class FakeResponse:
    def __init__(self, lines):
        self.lines, self.status_code, self.ok = lines, 200, True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_lines(self):
        return iter(self.lines)


def test_apex_is_looked_up_only_when_the_wildcard_lookup_is_capped(monkeypatch):
    import json

    import integrations.dnsdb as dnsdb
    requested = []

    def fake_get(url, **kwargs):
        requested.append(url.split("/rrset/name/")[1])
        record = {"obj": {"rrname": "a.com.", "rrtype": "A", "rdata": ["1.1.1.1"], "time_first": BASE, "time_last": BASE}}
        cond = "limited" if limited and url.endswith("*.a.com/ANY") else "succeeded"
        return FakeResponse([json.dumps(record), json.dumps({"cond": cond})])

    monkeypatch.setattr(dnsdb, "load_dnsdb_key", lambda: "key")
    monkeypatch.setattr(dnsdb, "get_session", lambda: type("S", (), {"get": staticmethod(fake_get)})())
    limited = False
    result = dnsdb.fetch_dnsdb_history.__wrapped__("a.com", 10)
    assert requested == ["*.a.com/ANY"] and not result.truncated
    requested.clear()
    limited = True
    result = dnsdb.fetch_dnsdb_history.__wrapped__("a.com", 10)
    assert requested == ["*.a.com/ANY", "a.com/ANY"] and result.truncated

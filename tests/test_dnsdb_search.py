"""DNSDB page: what a typed value searches, the request, curl, dnsdbq and Scout share link built from it, and the
records turned into domains and IPs (no request)."""
import pytest

from core import dnsdb_search as ds

SCOUT_EXAMPLE = ("https://scout.dnsdb.info/dashboard?share=eyJ1c2Vfc3RhbmRhcmRfc2VhcmNoIjp0cnVlLCJ1c2VfcmRhdGEiOnRydWUs"
                 "InJyZGF0YV9zZWFyY2hfZG9tYWluX3JhdyI6Ijg1LjE1OS4xOTYuMTc3IiwicmRhdGFfdHlwZSI6ImlwIiwidmVyYl9sb29rdXAiOnR"
                 "ydWV9")


@pytest.mark.parametrize("typed,mode", [
    ("example.com", "rrset"), ("*.example.com", "rrset"), ("www.example.*", "rrset"), ("evil[.]com", "rrset"),
    ("85.159.196.177", "rdata_ip"), ("104.21.59.0/24", "rdata_ip"), ("2620:11c:f004::/48", "rdata_ip"),
    ("10.0.0.1-10.0.0.9", "rdata_ip"), ("^login\\.paypal\\..*", "regex"), ("*paypal*", "glob"),
    ("ex[a-c]mple.com.", "glob"), ("", "rrset")])
def test_detect(typed, mode):
    assert ds.detect(typed) == mode


def test_scout_link_matches_scouts_own():
    assert ds.scout_link(ds.Search(mode="rdata_ip", value="85.159.196.177")) == SCOUT_EXAMPLE


def test_scout_link_of_other_searches():
    rrset = ds.scout_state_of(ds.scout_link(ds.Search(value="*.example.com", rrtype="NS", bailiwick="com",
                                                      limit=100, aggregated=False)))
    assert rrset == {"use_standard_search": True, "use_rrset": True, "rrset_search_domain_raw": "*.example.com",
                     "rrset_search_bailiwick_raw": "com", "use_deaggregate": True, "verb_lookup": True,
                     "rtype": "NS", "limit": "100"}
    cidr = ds.scout_state_of(ds.scout_link(ds.Search(mode="rdata_ip", value="104.21.59.7/24")))
    assert cidr["rrdata_search_domain_raw"] == "104.21.59.0,24" and "rtype" not in cidr
    flex = ds.scout_state_of(ds.scout_link(ds.Search(mode="glob", value="*paypal*.", field="rdata", rrtype="CNAME",
                                                     exclude="*.paypal.com.", after=1700000000, strict=True)))
    assert list(flex) == ["use_flexible_search", "flexible_syntax", "flexible_search_val_raw",
                          "flexible_search_exclude_raw", "flexible_field", "rtype", "use_timefence", "timefence_start",
                          "time_first_after", "time_last_after", "use_timefence_strict"]
    assert flex["time_first_after"] is True and flex["flexible_field"] == "rdata"
    assert ds.scout_link(ds.Search(mode="rrset_raw", value="0366736902696f00")) == ""   # no Scout form for it


def test_request_url_and_commands():
    ip6 = ds.Search(mode="rdata_ip", value="2620:11c:f004::/48")
    assert ds.path(ip6) == "/lookup/rdata/ip/2620%3A11c%3Af004%3A%3A,48"
    assert ds.cli(ip6) == "dnsdbq -i 2620:11c:f004::/48 -l 5000"
    ns = ds.Search(value="*.example.com", rrtype="NS", bailiwick="com", after=1700000000, before=1710000000)
    assert ds.path(ns) == "/lookup/rrset/name/*.example.com/NS/com"
    assert "time_last_after=1700000000&time_first_before=1710000000" in ds.url(ns)
    assert ds.cli(ns) == "dnsdbq -r '*.example.com' -b com -t NS -l 5000 -A 1700000000 -B 1710000000"
    regex = ds.Search(mode="regex", value="^login\\.", field="rrnames", exclude="\\.com\\.$", rrtype="A", limit=100)
    assert ds.url(regex).startswith("https://api.dnsdb.info/dnsdb/v2/regex/rrnames/%5Elogin%5C./A?limit=100&"
                                    "exclude=%5C.com%5C.%24")
    assert ds.flex_cli(regex) == "dnsdbflex --regex '^login\\.' --exclude '\\.com\\.$' -s rrnames -t A -l 100"
    assert ds.cli(regex) == ds.flex_cli(regex) + " -F | dnsdbq -f -j"   # dnsdbflex finds names, dnsdbq their records
    curl = ds.curl(regex)
    assert curl.startswith("curl -s -g -H \"X-API-Key: $DNSDB_API_KEY\"") and "$DNSDB_API_KEY" in curl
    assert "aggr" not in ds.url(regex)   # flexible search has no aggregation


def test_problems_and_notes():
    assert ds.problems(ds.Search(value="")) == ["Type what to search for."]
    assert ds.problems(ds.Search(value="ex*ample.com"))   # a lookup takes * only at the ends
    assert ds.problems(ds.Search(mode="glob", value="*.com.", field="rdata", rrtype="A"))   # rdata flex: no A
    assert ds.problems(ds.Search(mode="regex", value="(a"))
    assert ds.problems(ds.Search(mode="rdata_ip", value="not-an-ip"))
    assert ds.problems(ds.Search(mode="rdata_raw", value="abc"))
    assert not ds.problems(ds.Search(mode="rdata_ip", value="1.2.3.4", rrtype="MX"))   # only a note
    assert ds.notes(ds.Search(mode="rdata_ip", value="1.2.3.4", rrtype="MX"))
    assert ds.notes(ds.Search(mode="glob", value="*.paypal.com"))


RECORDS = [
    {"rrname": "www.evil.com.", "rrtype": "A", "rdata": ["93.184.215.14", "10.0.0.1"], "bailiwick": "evil.com.",
     "count": 4, "time_first": 1700000000, "time_last": 1710000000},
    {"rrname": "mail.evil.com.", "rrtype": "CNAME", "rdata": ["edge.cdn-host.net."], "count": 2,
     "time_first": 1700000000, "time_last": 1705000000},
    {"rrname": "evil.com.", "rrtype": "MX", "rdata": ["10 mx.mailhost.org."], "count": 1, "zone_time_first": 1700000000,
     "zone_time_last": 1700000500},
    {"rrname": "other.com.", "rrtype": "A", "rdata": "93.184.215.14", "count": 9, "time_first": 1600000000,
     "time_last": 1712000000},
]


def test_records_become_domains_and_ips():
    frame = ds.records_frame(RECORDS)
    assert list(frame.columns) == ds.RECORD_COLUMNS and frame["RData"].iloc[0] == "93.184.215.14\n10.0.0.1"
    domains, ips = ds.targets(RECORDS, preselect=1, searched="*.evil.com")
    assert list(domains["Target"]) == ["cdn-host.net", "mailhost.org", "other.com"]   # the searched domain left out
    assert domains.set_index("Target").loc["cdn-host.net", "Via"] == "CNAME"
    assert list(ips["Target"]) == ["93.184.215.14"] and ips.iloc[0]["Records"] == 2   # 10.0.0.1 is private
    assert bool(ips.iloc[0]["Analyze"]) and not domains["Analyze"].iloc[1:].any()
    assert ds.targets(RECORDS, searched="93.184.215.14")[1].empty   # the searched IP is not offered again


def test_flex_records_and_round_trip():
    frame = ds.records_frame([{"rrname": "a.evil.com.", "rrtype": "A"}, {"rrname": "b.evil.com.", "rrtype": "NS"}])
    assert list(frame.columns) == ["RRName", "RRType"]
    search = ds.Search(mode="glob", value="*evil*", field="rdata", exclude="x", limit=50)
    assert ds.from_dict({**search.to_dict(), "gone": 1}) == search


def test_page_shows_the_query_then_the_results():
    from streamlit.testing.v1 import AppTest

    def page():
        import streamlit as st

        from integrations.http import FetchResult
        from views import dnsdb_view
        calls = st.session_state.setdefault("calls", [])

        def fake(url):
            calls.append(url)
            return FetchResult("DNSDB search", url, data=[
                {"rrname": "www.evil.com.", "rrtype": "A", "rdata": ["93.184.215.14"], "count": 3,
                 "time_first": 1700000000, "time_last": 1710000000},
                {"rrname": "shop.other.com.", "rrtype": "A", "rdata": ["93.184.215.14"], "count": 1,
                 "time_first": 1700000000, "time_last": 1710000000}], record_count=2)
        dnsdb_view.fetch_dnsdb_search = fake
        dnsdb_view.render_dnsdb_page()

    at = AppTest.from_function(page).run(timeout=30)
    assert not at.exception
    at.text_area(key="dnsdb_search_value").set_value("85.159.196.177/32").run()
    assert at.selectbox(key="dnsdb_search_mode").value == "auto"
    assert any("/lookup/rdata/ip/85.159.196.177" in c.value for c in at.code)   # curl, before any request
    assert not at.session_state["calls"]
    at.button_group(key="dnsdb_search_show").set_value("Scout share link").run()
    assert any(c.value.startswith("https://scout.dnsdb.info/dashboard?share=") for c in at.code)
    assert any(b.label == "Open in DNSDB Scout" for b in at.get("link_button"))
    next(b for b in at.button if b.label == "Search").click().run()
    assert not at.exception and len(at.session_state["calls"]) == 1
    state = at.session_state["dnsdb_search_state"]
    assert list(state["domains"]["Target"]) == ["evil.com", "other.com"] and list(state["ips"]["Target"]) == \
        ["93.184.215.14"]


PASTED = "83.228.209.234\nxwfa3ak[.]cc\nspr7tsc.cc,\n\nsqv5zzx.cc\n7h1r0.cc\nspr7tsc.cc\n"


def test_several_values_get_a_search_each():
    values = ds.split_values(PASTED)
    assert values == ["83.228.209.234", "xwfa3ak[.]cc", "spr7tsc.cc", "sqv5zzx.cc", "7h1r0.cc"]
    assert ds.mode_counts(values) == {"RRset: name": 4, "RData: IP": 1}
    template = ds.Search(rrtype="A", bailiwick="cc", limit=100)
    searches = ds.expand(template, values, subdomains=True)
    assert [s.mode for s in searches] == ["rdata_ip"] + ["rrset"] * 4
    assert searches[1].value == "*.xwfa3ak[.]cc" and searches[0].bailiwick == "" and searches[1].bailiwick == "cc"
    frame = ds.batch_frame(searches)
    assert list(frame["Value"]) == ["83.228.209.234", "*.xwfa3ak.cc", "*.spr7tsc.cc", "*.sqv5zzx.cc", "*.7h1r0.cc"]
    assert frame["Scout link"].str.startswith("https://scout.dnsdb.info/dashboard?share=").all()
    assert ds.scout_state_of(frame["Scout link"][1])["rrset_search_domain_raw"] == "*.xwfa3ak.cc"
    assert frame["dnsdbq"][0] == "dnsdbq -i 83.228.209.234 -l 100"
    assert "/lookup/rrset/name/*.spr7tsc.cc/A/cc?limit=100" in frame["curl"][2]
    fixed = ds.batch_frame(ds.expand(ds.Search(mode="rdata_ip"), values, auto=False))
    assert fixed["Problem"].iloc[1] and fixed["Scout link"].iloc[1] == ""   # a domain is not an IP: no link


def test_page_with_several_values_shows_links_not_search():
    from streamlit.testing.v1 import AppTest

    def page():
        from views import dnsdb_view
        dnsdb_view.render_dnsdb_page()

    at = AppTest.from_function(page).run(timeout=30)
    at.text_area(key="dnsdb_search_value").set_value(PASTED).run()
    assert not at.exception
    assert next(b for b in at.button if b.label == "Search").disabled
    assert any("5 searches" in m.value for m in at.markdown)
    assert any(c.value == "Auto per line: RRset: name ×4, RData: IP ×1." for c in at.caption)
    table = at.dataframe[0].value
    assert table["Value"].tolist()[0] == "83.228.209.234" and "Problem" not in table   # no problem: no column
    assert [e.label for e in at.expander] == ["All commands and links (5 lines)"]   # commands below the table
    at.button_group(key="dnsdb_search_show").set_value("dnsdbflex").run()
    assert any("1 of 5 lines have no dnsdbflex form" in c.value for c in at.caption)
    assert any("# xwfa3ak.cc · RRset: name\ndnsdbflex --glob xwfa3ak.cc." in c.value for c in at.code)
    at.toggle(key="dnsdb_search_labels").set_value(False).run()
    assert any(c.value.startswith("dnsdbflex --glob xwfa3ak.cc.") for c in at.code)
    at.selectbox(key="dnsdb_search_mode").set_value("rdata_ip").run()   # domains are not IPs: no link for them
    table = at.dataframe[0].value
    assert table["Scout link"].isna().tolist() == [False, True, True, True, True] and "Problem" in table


def test_a_search_with_a_problem_has_no_scout_link():
    from streamlit.testing.v1 import AppTest

    def page():
        from views import dnsdb_view
        dnsdb_view.render_dnsdb_page()

    at = AppTest.from_function(page).run(timeout=30)
    at.text_area(key="dnsdb_search_value").set_value("ex*ample.com").run()
    at.selectbox(key="dnsdb_search_mode").set_value("rrset").run()
    at.button_group(key="dnsdb_search_show").set_value("Scout share link").run()
    assert not at.exception and not at.get("link_button")
    assert not any(c.value.startswith("https://scout.dnsdb.info") for c in at.code)


def test_dnsdbflex_for_lookups_where_it_has_a_form():
    assert ds.flex_cli(ds.Search(value="spr7tsc.cc")) == "dnsdbflex --glob spr7tsc.cc. -s rrnames -l 5000"
    assert ds.flex_cli(ds.Search(value="*.evil.com", rrtype="A", after=1700000000, strict=True)) == \
        "dnsdbflex --glob '*.evil.com.' -s rrnames -t A -l 5000 -A 1700000000 -c"
    assert ds.flex_cli(ds.Search(mode="rdata_name", value="ns1.evil.com", rrtype="NS")) == \
        "dnsdbflex --glob ns1.evil.com. -s rdata -t NS -l 5000"
    assert ds.flex_cli(ds.Search(mode="rdata_ip", value="1.2.3.4")) == ""      # Flexible Search has no addresses
    assert ds.flex_cli(ds.Search(mode="rdata_name", value="x.com", rrtype="A")) == ""
    frame = ds.batch_frame(ds.expand(ds.Search(), ds.split_values(PASTED)))
    assert frame["dnsdbflex"].tolist()[:2] == ["", "dnsdbflex --glob xwfa3ak.cc. -s rrnames -l 5000"]


def test_listing_names_each_entry():
    frame = ds.batch_frame(ds.expand(ds.Search(), ds.split_values(PASTED)))
    text = ds.listing(frame, "Scout link")
    blocks = text.split("\n\n")
    assert len(blocks) == 5 and blocks[0].startswith("# 83.228.209.234 · RData: IP\nhttps://scout.dnsdb.info/")
    assert blocks[1].startswith("# xwfa3ak.cc · RRset: name\nhttps://")
    flex = ds.listing(frame, "dnsdbflex")
    assert flex.count("# ") == 4 and "83.228.209.234" not in flex   # an IP has no dnsdbflex form
    bare = ds.listing(frame, "Scout link", labels=False).splitlines()
    assert len(bare) == 5 and all(line.startswith("https://scout.dnsdb.info/") for line in bare)

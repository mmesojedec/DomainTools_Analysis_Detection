import pandas as pd

from core.hostnames import INVENTORY_COLUMNS, sensitive_words
from core.subdomain_triage import (
    brands_in,
    build_subdomain_triage,
    embedded_domains,
    level_of,
    looks_random,
    name_signals,
    shared_platform,
)


def inventory(rows):
    base = {col: None for col in INVENTORY_COLUMNS}
    base.update({"Flags": "", "Certificates": 0, "pDNS Records": 0, "Current Values": "", "Latest Certificate Hash": ""})
    return pd.DataFrame([{**base, **row} for row in rows], columns=INVENTORY_COLUMNS)


def test_sensitive_words_lists_the_matches():
    assert sensitive_words("secure-login.example.com") == ["login", "secure"]
    assert sensitive_words("blog.example.com") == [] and sensitive_words("login.co.uk") == []


def test_random_names():
    assert looks_random("4h5sjhzrbvck9o1l") and looks_random("zbonljdchv") and looks_random("bddk-xkcdqwrtz")
    assert not looks_random("orderflow-staging-admin") and not looks_random("technologyspa")
    assert not looks_random("short1") and not looks_random("xn--pypal-4ve")


def test_brands_and_embedded_domains():
    assert brands_in(["paypal-verify"], "pages.dev") == ["paypal"]
    assert brands_in(["dhl-track"], "eu.cc") == ["dhl"] and brands_in(["groups"], "eu.cc") == []
    assert brands_in(["login"], "paypal.com") == []   # the domain's own brand
    assert embedded_domains(["support", "zoom", "us", "vip1"]) == ["zoom.us"]
    assert embedded_domains(["paypal-com-login"]) == ["paypal.com"]
    assert embedded_domains(["qa", "app"]) == [] and embedded_domains(["ai-research-site"]) == []


def test_name_signals_and_levels():
    signals, matched = name_signals("support.zoom.us.vip1.semangat.eu.cc", "eu.cc")
    assert signals == ["Phishing word", "Brand name", "Embedded domain", "Long or deep name"]
    assert matched == ["support", "zoom", "zoom.us"]
    assert level_of(9, signals) == "High"
    assert level_of(3, ["Phishing word"]) == "Medium"
    assert level_of(4, ["Random-looking", "New", "Burst"]) == "Medium"
    assert level_of(3, ["Random-looking", "New"]) == "Low"
    assert level_of(0, []) == ""


def test_shared_platforms():
    assert shared_platform("pages.dev") == "pages.dev" and shared_platform("eu.cc") == "eu.cc"
    assert shared_platform("example.com") == ""


def test_triage_ranks_and_skips_apex_and_wildcards():
    now = pd.Timestamp("2026-10-01 10:15")
    rows = [{"Hostname": "example.com", "Apex": "example.com"},
            {"Hostname": "*.example.com", "Apex": "example.com"},
            {"Hostname": "blog.example.com", "Apex": "example.com", "pDNS First Seen": pd.Timestamp("2020-01-01")},
            {"Hostname": "paypal-login.example.com", "Apex": "example.com", "Flags": "Certificate, never resolved, New",
             "First Certificate": now, "Certificates": 1}]
    rows += [{"Hostname": f"x{i}.example.com", "Apex": "example.com", "First Certificate": now + pd.Timedelta(minutes=i)}
             for i in range(4)]
    triage = build_subdomain_triage(inventory(rows))
    assert "example.com" not in set(triage["Hostname"]) and "*.example.com" not in set(triage["Hostname"])
    top = triage.iloc[0]
    assert top["Hostname"] == "paypal-login.example.com"
    assert top["Signals"] == "Phishing word, Brand name, New, Burst, Never resolved"
    assert (top["Score"], top["Level"], top["Matched"]) == (9, "High", "login, pay, paypal")
    assert set(triage.loc[triage["Hostname"].str.startswith("x"), "Signals"]) == {"Burst"}   # 5 names in one hour
    assert triage.set_index("Hostname").loc["blog.example.com", "Level"] == ""
    assert build_subdomain_triage(inventory([])).empty

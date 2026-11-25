"""Check API keys: one cheap request per service, read into ok / warning / failed / skipped (no real request)."""
import pytest

from integrations import key_check as kc
from integrations.http import FetchResult

PRODUCTS = [{"id": "iris-investigate", "per_month_limit": "1000", "usage": {"month": "10"}},
            {"id": "domain-history", "per_month_limit": "100", "usage": {"month": "100"}},
            {"id": "certificate-search"}, {"id": "certificate-events"}]


@pytest.fixture
def keys(monkeypatch):
    """Every service has a key; each test replaces the request it looks at."""
    for name in ("load_dnsdb_key", "load_vpndb_key", "load_bgpdb_host"):
        monkeypatch.setattr(kc, name, lambda: "set")
    monkeypatch.setattr(kc, "load_dtapi_credentials", lambda: ("user", "key"))
    monkeypatch.setattr(kc, "load_cert_api_key", lambda: "key")
    return monkeypatch


def test_domaintools_reads_products_quota_and_missing_ones(keys):
    keys.setattr(kc, "account_information", lambda refresh: (FetchResult(
        "Account Information", "account", data={"products": PRODUCTS[:2]}), 0))
    check = kc.check_domaintools()
    assert check.status == kc.WARNING and check.works and "2 product(s)" in check.text
    assert any("No Certificate search" in n for n in check.notes)
    assert any("Domain history: this month's quota is used up" in n for n in check.notes)
    keys.setattr(kc, "account_information", lambda refresh: (FetchResult(
        "Account Information", "account", data={"products": PRODUCTS}), 0))
    assert kc.check_domaintools().status == kc.WARNING   # Domain History used up is still a notice
    keys.setattr(kc, "account_information", lambda refresh: (FetchResult(
        "Account Information", "account", error="HTTP 403: forbidden"), 0))
    failed = kc.check_domaintools()
    assert failed.status == kc.FAILED and "403" in failed.text and not failed.works


def test_dnsdb_vpndb_bgpdb(keys):
    keys.setattr(kc, "fetch_dnsdb_rate_limit", lambda: FetchResult(
        "DNSDB rate limit", "key", data={"limit": 1000, "remaining": 900}))
    assert kc.check_dnsdb().text == "Works: 900 of 1,000 queries left."
    keys.setattr(kc.vpndb, "_get", lambda target, path: FetchResult("VPNDB", target, error="HTTP 401: Unauthorized"))
    assert kc.check_vpndb().status == kc.FAILED
    keys.setattr(kc.bgpdb, "_query", lambda command, argument: FetchResult(
        "BGPDB", argument, error="Connection timed out", extras={kc.bgpdb.UNREACHABLE: True}))
    bgp = kc.check_bgpdb()
    assert bgp.status == kc.FAILED and "DomainTools network or VPN" in bgp.text
    keys.setattr(kc.bgpdb, "_query", lambda command, argument: FetchResult(
        "BGPDB", argument, data=[{"asn": 13335}], record_count=1))
    assert kc.check_bgpdb().status == kc.OK


def test_no_key_is_skipped_and_summary(monkeypatch):
    for name in ("load_dtapi_credentials", "load_dnsdb_key", "load_vpndb_key", "load_bgpdb_host", "load_cert_api_key"):
        monkeypatch.setattr(kc, name, lambda: None)
    checks = kc.check_keys()
    assert [c.service for c in checks] == list(kc.CHECKED) and {c.status for c in checks} == {kc.SKIPPED}
    assert kc.summary(checks) == "No API keys to check yet."
    ok, bad = kc.KeyCheck(kc.DNSDB, kc.OK, "Works."), kc.KeyCheck(kc.VPNDB, kc.FAILED, "Not working: 401")
    assert kc.summary([ok, bad]) == "Not working: VPNDB. Working: DNSDB Scout."

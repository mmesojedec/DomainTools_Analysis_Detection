from unittest import mock

from core.account import (
    account_parts,
    endpoints,
    missing_app_products,
    nearest_expiry,
    product_name,
    products_frame,
)
from integrations import account as account_api

PAYLOAD = {"response": {
    "account": {"api_username": "user", "label": None, "active": True},
    "products": [
        {"id": "whois", "per_month_limit": "50000", "per_hour_limit": None, "per_minute_limit": "120",
         "usage": {"today": "0", "month": "0"}, "rest": {"month": "50000"}, "expiration_date": "2027-01-27"},
        {"id": "certificate-search", "per_month_limit": "10000", "per_hour_limit": None, "per_minute_limit": "20",
         "usage": {"today": "3", "month": "198"}, "rest": {"month": "9802"}, "expiration_date": None},
        {"id": "iris-detect-monitors", "per_month_limit": None, "per_hour_limit": "100", "per_minute_limit": "30",
         "usage": {"today": "0", "month": "0"}, "rest": {"month": ""}, "expiration_date": "2027-01-27"},
        {"id": "newly-observed-domains-feed-(api)", "per_month_limit": "100000", "per_hour_limit": None,
         "per_minute_limit": None, "usage": {"today": "0", "month": "26"}, "rest": {"month": "99974"},
         "expiration_date": None},
        {"id": "download-files", "per_month_limit": "100000", "per_hour_limit": "60", "per_minute_limit": "6",
         "usage": {"today": "0", "month": "5"}, "rest": {"month": "99995"}, "expiration_date": "2026-12-01",
         "endpoints": ["/daily_ip_risk", "/whois_daily"]},
    ],
}}


def test_product_names():
    assert product_name("iris-investigate-(api-only)") == "Iris investigate (API only)"
    assert product_name("newly-observed-domains-feed-(s3)") == "Newly observed domains feed (S3)"
    assert product_name("parsed-domain-rdap") == "Parsed domain RDAP"
    assert product_name("reverse-ip-whois") == "Reverse IP Whois"


def test_products_frame():
    account, products = account_parts(PAYLOAD)
    assert account["api_username"] == "user"
    frame = products_frame(products)
    assert sorted(frame["ID"]) == sorted(p["id"] for p in products)   # only what the response has
    assert frame["Used by this app"].sum() == 1   # certificate-search; the app's other products are not in it
    assert frame["ID"].iloc[0] == "certificate-search"   # used by this app, first
    cert = frame.iloc[0]
    assert (cert["Today"], cert["This month"], cert["Monthly limit"], cert["Left this month"]) == (3, 198, 10000, 9802)
    assert cert["Used %"] == 2.0
    monitors = frame.set_index("ID").loc["iris-detect-monitors"]
    assert monitors.isna()["Monthly limit"] and monitors.isna()["Left this month"] and monitors["Per hour"] == 100
    assert monitors.isna()["Used %"]


def test_expiry_and_endpoints():
    _, products = account_parts(PAYLOAD["response"])   # without the "response" wrapper too
    assert nearest_expiry(products) == "2026-12-01"
    assert endpoints(products) == {"download-files": ["/daily_ip_risk", "/whois_daily"]}
    assert products_frame([]).empty


def test_fetch_without_credentials_and_with():
    with mock.patch.object(account_api, "get_dt_api", return_value=None):
        assert not account_api.fetch_account_information().ok
    api = mock.Mock()
    api.account_information.return_value.data.return_value = PAYLOAD
    with mock.patch.object(account_api, "get_dt_api", return_value=api):
        result = account_api.fetch_account_information()
    assert result.ok and result.record_count == 5 and result.data["account"]["active"] is True


def test_missing_app_products():
    _, products = account_parts(PAYLOAD)
    missing = [feature for feature, _ in missing_app_products(products)]
    assert missing == ["Iris Investigate", "Domain History", "Risk evidence", "Certificate events"]
    either_iris = products + [{"id": "iris-investigate-(api-only)"}]   # either Iris product will do
    assert "Iris Investigate" not in [feature for feature, _ in missing_app_products(either_iris)]
    assert len(missing_app_products([])) == 5

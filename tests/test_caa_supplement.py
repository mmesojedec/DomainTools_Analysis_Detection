import pandas as pd

import integrations.collector as collector
from core.caa import caa_coverage_status
from core.cert_utils import publicly_trusted
from core.threat_detection import detect_threat_flags
from integrations.dnsdb import _lookup_urls
from integrations.http import FetchResult, StatusLog

BASE = 1704067200
CAA_EVENTS = pd.DataFrame([{"Domain": "nytimes.com", "RRName": "nytimes.com", "Date": pd.Timestamp("2024-01-01"),
                            "Field": "CAA", "Value": '0 issue "digicert.com"\n0 issue "letsencrypt.org"'}])


def cert(**overrides):
    base = {"Domain": "nytimes.com", "Hash": "fb7c2ffd", "Source": "DomainTools Cert API", "Common Name": "nytimes.com",
            "Issuer": "dedi1.eq2.co.uk", "Alt Names List": ["nytimes.com"]}
    base.update(overrides)
    return base


def types(result):
    return set(result.alerts["Threat Type"]) if not result.alerts.empty else set()


def test_publicly_trusted_classification():
    assert publicly_trusted(cert(**{"Has Embedded SCTs": True})) is True
    assert publicly_trusted(cert(**{"Certificate Policy": [{"policy_oid": "2.23.140.1.2.1"}]})) is True
    assert publicly_trusted(cert(**{"Validation Level": "ov"})) is True
    assert publicly_trusted(cert(Issuer="R11")) is True                                   # Let's Encrypt intermediate CN
    assert publicly_trusted(cert(Issuer="DigiCert Global G2 TLS RSA SHA256 2020 CA1")) is True
    assert publicly_trusted(cert(**{"Has Embedded SCTs": False})) is False                 # private CA evidence
    assert publicly_trusted(cert(Issuer="nytimes.com")) is False                           # self-signed
    assert publicly_trusted(cert(**{"Has Embedded SCTs": float("nan")})) is None           # unknown


def test_private_ca_is_not_a_caa_breach():
    ssl = pd.DataFrame([cert(**{"Has Embedded SCTs": False, "Validation Level": "unknown"})])
    found = types(detect_threat_flags(CAA_EVENTS, {"risk_score": 0}, ssl_df=ssl))
    assert "Unauthorized CA Certificate Issuance (CAA Breach)" not in found
    assert "Non-Public / Private CA Certificate" in found


def test_public_unauthorized_ca_is_a_breach():
    ssl = pd.DataFrame([cert(Issuer="GlobalSign GCC R6 AlphaSSL CA 2023", **{"Has Embedded SCTs": True})])
    assert "Unauthorized CA Certificate Issuance (CAA Breach)" in types(detect_threat_flags(CAA_EVENTS, {"risk_score": 0}, ssl_df=ssl))


def test_unverified_issuer_is_low_confidence_mismatch():
    ssl = pd.DataFrame([cert(Source="Domain History")])
    alerts = detect_threat_flags(CAA_EVENTS, {"risk_score": 0}, ssl_df=ssl).alerts.set_index("Threat Type")
    assert "Unauthorized CA Certificate Issuance (CAA Breach)" not in alerts.index
    assert alerts.loc["CAA Mismatch (CA Trust Unverified)", "Confidence"] == "Low"


def test_coverage_status():
    assert caa_coverage_status({"a.com": {"truncated": True, "caa_checked": True}}, "a.com") == "checked"
    assert caa_coverage_status({"a.com": {"truncated": False, "caa_checked": False}}, "a.com") == "complete"
    assert caa_coverage_status({"a.com": {"truncated": True, "caa_checked": False}}, "a.com") == "incomplete"
    assert caa_coverage_status({}, "a.com") == "incomplete"


def test_caa_lookup_is_apex_only():
    assert _lookup_urls("nytimes.com", "CAA", include_wildcard=False) == [
        "https://api.dnsdb.info/dnsdb/v2/lookup/rrset/name/nytimes.com/CAA"]


def test_caa_supplement_recovers_record_missing_from_truncated_main_query(monkeypatch):
    calls = []

    def fake_fetch(target, limit=5000, rrtype="ANY", include_wildcard=True):
        calls.append((rrtype, include_wildcard))
        if rrtype == "CAA":
            return FetchResult("DNSDB CAA Lookup", target, record_count=1, data=[
                {"rrname": "nytimes.com.", "rrtype": "CAA", "rdata": ['0 issue "digicert.com"'], "time_first": BASE, "time_last": BASE + 9e6}])
        # Main query hit the limit with only A records - the CAA record was cut off
        return FetchResult("DNSDB Scout", target, truncated=True, record_count=2000, data=[
            {"rrname": f"h{i}.nytimes.com.", "rrtype": "A", "rdata": ["151.101.1.164"], "time_first": BASE + i, "time_last": BASE + i} for i in range(5)])

    monkeypatch.setattr(collector, "fetch_dnsdb_history", fake_fetch)
    log = StatusLog()
    pdns, coverage = collector.collect_pdns(["nytimes.com"], "DNSDB Scout", 2000, log, caa_lookup=True)
    assert ("CAA", False) in calls
    assert (pdns["Field"] == "CAA").sum() == 1 and set(pdns.loc[pdns["Field"] == "CAA", "Collection"]) == {"CAA lookup"}
    assert coverage == {"nytimes.com": {"truncated": True, "caa_checked": True}}

    _, coverage_without = collector.collect_pdns(["nytimes.com"], "DNSDB Scout", 2000, StatusLog(), caa_lookup=False)
    assert caa_coverage_status(coverage_without, "nytimes.com") == "incomplete"

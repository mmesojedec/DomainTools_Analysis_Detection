import pandas as pd

from core.self_signed import self_signed_certificates

NOW = pd.Timestamp("2026-11-01")


def cert(**fields):
    base = {"Domain": "a.com", "Source": "DomainTools Cert API", "Hash": "h1", "Common Name": "a.com",
            "Issuer": "a.com", "Is Self Signed": True, "Not Before": "2026-01-01", "Not After": "2027-01-01",
            "Date": pd.Timestamp("2026-10-01")}
    return {**base, **fields}


def rate(*rows, domains=("a.com",)):
    return self_signed_certificates(pd.DataFrame(list(rows)), list(domains), now=NOW)


def test_only_self_signed_certificates_are_listed():
    table = rate(cert(), cert(Hash="h2", Issuer="R10", **{"Common Name": "b.a.com", "Is Self Signed": False}))
    assert table["Hash"].tolist() == ["h1"]


def test_a_self_signed_certificate_served_on_the_domain_now_is_critical():
    table = rate(cert(Source="Iris Investigate API"), cert())   # same hash seen live and in the Cert API
    assert table.loc[0, "Severity"] == "Critical" and len(table) == 1
    assert table.loc[0, "Sources"] == "DomainTools Cert API, Iris Investigate API"


def test_c2_defaults_stay_critical_even_when_expired():
    table = rate(cert(**{"Subject Org": "cobaltstrike", "Not After": "2025-01-01"}))
    assert table.loc[0, "Severity"] == "Critical" and table.loc[0, "Status"] == "Expired"


def test_plain_and_expired_self_signed_certificates():
    assert rate(cert()).loc[0, "Severity"] == "Medium"
    expired = rate(cert(**{"Not After": "2025-01-01"}))
    assert expired.loc[0, "Severity"] == "Low" and any("Expired" in r for r in expired.loc[0, "Reasons"])


def test_bare_ip_weak_key_and_long_validity_raise_the_severity():
    table = rate(cert(Hash="ip", **{"Common Name": "203.0.113.5", "Issuer": "203.0.113.5"}),
                 cert(Hash="weak", **{"Public Key Bits": 1024, "Public Key Algo": "RSA"}),
                 cert(Hash="long", **{"Not After": "2036-01-01"}))
    severity = dict(zip(table["Hash"], table["Severity"]))
    assert severity == {"ip": "High", "weak": "High", "long": "Medium"}
    assert table["Hash"].tolist()[-1] == "long"   # most severe first
    assert any("year(s)" in reason for reason in table.loc[2, "Reasons"]) and table.loc[2, "Validity (days)"] > 3000


def test_a_self_signed_certificate_claiming_a_public_ca_name_is_high():
    table = rate(cert(**{"Common Name": "edition.a.com", "Issuer": "edition.a.com",
                         "Issuer DN": "cn=edition.a.com,o=Google Trust Services LLC"}))
    assert table.loc[0, "Severity"] == "High" and "google trust services" in table.loc[0, "Reasons"][0]

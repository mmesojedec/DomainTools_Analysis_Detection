"""Breakdown figures of the IrisQL and CertsQL pages, from the result tables alone."""
import pandas as pd

from core.query_breakdown import (
    cert_summary,
    concentration,
    iris_summary,
    monthly,
    names_per_cert,
    risk_bands,
    san_ips,
    top_values,
    validity_classes,
)

NOW = pd.Timestamp("2026-06-01")


def domains():
    return pd.DataFrame({
        "Domain": ["a.com", "b.com", "c.net", "d.org"],
        "Risk Score": pd.array([95, 72, 10, None], dtype="Int64"),
        "Active": [True, False, True, None],
        "Create Date": ["2026-05-20", "2026-05-25", "2024-01-03", ""],
        "Expiration Date": ["2027-05-20", "2026-06-10", "2026-05-01", ""],
        "Registrar": ["NameCheap", "NameCheap", "GoDaddy", ""],
        "IPs": ["192.0.2.1", "192.0.2.1, 192.0.2.2", "198.51.100.9", ""],
        "Name Servers": ["ns1.x.com, ns2.x.com", "ns1.x.com", "ns.y.net", ""],
    })


def test_iris_summary_counts_risk_recent_and_spread():
    ips = pd.DataFrame({"ASN": pd.array([1, 1, 2], dtype="Int64"), "Country": ["US", "US", ""]})
    summary = iris_summary(domains(), ips, high_risk=70, now=NOW)
    assert summary["median_risk"] == 72 and summary["high_risk"] == 2
    assert (summary["new"], summary["expiring"]) == (2, 1)   # an expired domain is not "expiring"
    assert (summary["active"], summary["inactive"]) == (2, 1)   # unknown counts as neither
    assert (summary["registrars"], summary["asns"], summary["countries"]) == (2, 2, 1)


def test_bands_months_and_concentration():
    assert risk_bands(domains()["Risk Score"]) == {"0–39": 1, "40–69": 0, "70–89": 1, "90–100": 1}
    months = monthly(domains()["Create Date"], ["90–100", "70–89", "0–39", None])
    assert list(months["Month"]) == ["2024-01", "2026-05", "2026-05"] and months["Count"].sum() == 3
    assert top_values(domains()["Name Servers"]).to_dict() == {"ns1.x.com": 2, "ns2.x.com": 1, "ns.y.net": 1}
    share, leaders = concentration(domains()["IPs"], top=1)
    assert leaders == ["192.0.2.1"] and share == 0.5   # 2 of the 4 domains, the one without IPs included


def test_cert_summary_and_validity():
    certs = pd.DataFrame({
        "Use": [True, True, True, False],
        "Issuer": ["Let's Encrypt", "Let's Encrypt", "Sectigo", "X"],
        "Validation": ["DV", "DV", "OV", "EV"],
        "Not After": ["2026-05-01", "2026-06-20", "2027-01-01", "2026-06-02"],
        "Days": pd.array([7, 90, 365, 30], dtype="Int64"),
        "Self-signed": [False, False, True, False],
        "SANs": ["*.a.com, a.com", "b.com, 192.0.2.7", "c.com", "d.com"],
    })
    summary = cert_summary(certs, now=NOW)
    assert summary["used"] == 3 and summary["issuers"] == 2 and summary["median_days"] == 90
    assert summary["validation"] == {"DV": 2, "OV": 1}
    assert (summary["expired"], summary["expiring"], summary["short_lived"], summary["self_signed"]) == (1, 1, 1, 1)
    classes = validity_classes(certs["Days"])
    assert classes["≤ 10 days"] == 1 and classes["48–100 days"] == 1 and classes["201–398 days"] == 1
    names, wildcards = names_per_cert(certs["SANs"])
    assert list(names) == [2, 2, 1, 1] and wildcards == 1
    assert san_ips(certs["SANs"]).to_dict() == {"192.0.2.7": 1}

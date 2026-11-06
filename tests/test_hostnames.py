import pandas as pd

from core.dataset import build_dataset
from core.hostnames import (
    apply_certificate_focus,
    apply_focus,
    build_hostname_certificates,
    build_hostname_inventory,
    candidate_hostnames,
    certificate_in_focus,
    focus_from_hostnames,
    is_sensitive,
    name_in_focus,
)
from integrations.collector import CollectedData

FOCUS = {"domaintools.com": ["api.domaintools.com"]}


def test_focus_from_hostnames_groups_by_apex():
    assert focus_from_hostnames(["API.domaintools.com.", "*.domaintools.com", "x.example.co.uk"]) == {
        "domaintools.com": ["*.domaintools.com", "api.domaintools.com"], "example.co.uk": ["x.example.co.uk"]}


def test_name_and_certificate_matching():
    assert name_in_focus("api.domaintools.com", ["api.domaintools.com"])
    assert name_in_focus("_acme-challenge.api.domaintools.com", ["api.domaintools.com"])
    assert not name_in_focus("www.domaintools.com", ["api.domaintools.com"])
    assert name_in_focus("www.domaintools.com", ["*.domaintools.com"]) and not name_in_focus("domaintools.com", ["*.domaintools.com"])
    assert certificate_in_focus(["*.domaintools.com"], ["api.domaintools.com"])       # wildcard covers it
    assert certificate_in_focus(["x.api.domaintools.com"], ["api.domaintools.com"])
    assert not certificate_in_focus(["domaintools.com"], ["api.domaintools.com"])     # apex-only certificate
    assert not certificate_in_focus(["*.domaintools.com"], ["a.b.domaintools.com"])  # one label only


def test_apply_focus_keeps_other_domains():
    pdns = pd.DataFrame({"Domain": ["domaintools.com", "domaintools.com", "example.com"],
                         "RRName": ["api.domaintools.com", "www.domaintools.com", "www.example.com"]})
    assert list(apply_focus(pdns, FOCUS, "RRName")["RRName"]) == ["api.domaintools.com", "www.example.com"]
    assert apply_focus(pdns, {}, "RRName") is pdns
    ssl = pd.DataFrame({"Domain": ["domaintools.com"] * 3 + ["example.com"],
                        "SAN DNS": [["api.domaintools.com"], ["www.domaintools.com"], None, ["www.example.com"]],
                        "Common Name": ["", "www.domaintools.com", "", "www.example.com"]})
    assert apply_certificate_focus(ssl, FOCUS).index.tolist() == [0, 2, 3]   # nameless rows are kept


def test_candidate_hostnames_skip_service_labels_ips_and_other_domains():
    pdns = pd.DataFrame({"RRName": ["api.domaintools.com", "_dmarc.domaintools.com", "evil.net", "93.184.216.34"]})
    ssl = pd.DataFrame({"SAN DNS": ["www.domaintools.com, *.domaintools.com"], "Common Name": ["domaintools.com"]})
    events = pd.DataFrame({"Hostname": ["iris.domaintools.com"]})
    assert candidate_hostnames(pdns, ssl, events, ["domaintools.com"]) == [
        "*.domaintools.com", "api.domaintools.com", "domaintools.com", "iris.domaintools.com", "www.domaintools.com"]


def test_sensitive_names_look_below_the_registered_domain():
    assert is_sensitive("secure-login.domaintools.com") and is_sensitive("vpn2.domaintools.com")
    assert not is_sensitive("domaintools.com") and not is_sensitive("blog.domaintools.com")
    assert not is_sensitive("login.co.uk") and is_sensitive("sso.example.co.uk")


def test_inventory_flags():
    now = pd.Timestamp("2026-10-27")
    ssl = pd.DataFrame([
        {"Domain": "domaintools.com", "Hash": "c1", "SAN DNS": ["api.domaintools.com", "staged-login.domaintools.com"],
         "Common Name": "api.domaintools.com", "Not Before Date": pd.Timestamp("2026-10-20"), "Not After Date": pd.Timestamp("2027-01-18")},
        {"Domain": "domaintools.com", "Hash": "c2", "SAN DNS": ["*.domaintools.com"], "Common Name": "*.domaintools.com",
         "Not Before Date": pd.Timestamp("2025-01-01"), "Not After Date": pd.Timestamp("2026-01-01")},
    ])
    pdns = pd.DataFrame([
        {"Domain": "domaintools.com", "RRName": "api.domaintools.com", "Field": "A", "Value": "1.1.1.1",
         "First Seen": pd.Timestamp("2024-01-01"), "Last Seen": pd.Timestamp("2026-10-26")},
        {"Domain": "domaintools.com", "RRName": "old.domaintools.com", "Field": "CNAME", "Value": "x.cdn.net",
         "First Seen": pd.Timestamp("2020-01-01"), "Last Seen": pd.Timestamp("2021-01-01")},
        {"Domain": "domaintools.com", "RRName": "deep.a.domaintools.com", "Field": "A", "Value": "2.2.2.2",
         "First Seen": pd.Timestamp("2020-01-01"), "Last Seen": pd.Timestamp("2021-01-01")},
    ])
    inv = build_hostname_inventory(pdns, ssl, pd.DataFrame(), ["domaintools.com"], FOCUS, now=now).set_index("Hostname")
    assert inv.loc["api.domaintools.com", "Focus"] and inv.loc["api.domaintools.com", "Current Values"] == "1.1.1.1"
    assert inv.loc["staged-login.domaintools.com", "Flags"] == "Certificate, never resolved, New, Sensitive name"
    assert inv.loc["old.domaintools.com", "Flags"] == ""                          # covered by the wildcard certificate
    assert inv.loc["deep.a.domaintools.com", "Flags"] == "Resolves, no certificate"
    assert "Wildcard" in inv.loc["*.domaintools.com", "Flags"]
    assert inv.loc["api.domaintools.com", "Latest Certificate Hash"] == "c1"
    assert inv.loc["old.domaintools.com", "Latest Certificate Hash"] == ""   # no certificate names it
    capped = build_hostname_inventory(pdns, ssl, pd.DataFrame(), ["domaintools.com"], now=now,
                                      coverage={"domaintools.com": {"truncated": True}}).set_index("Hostname")
    assert "never resolved" not in capped.loc["staged-login.domaintools.com", "Flags"]


def test_build_dataset_applies_focus_after_the_inventory():
    collected = CollectedData(
        targets=["domaintools.com"], domain_targets=["domaintools.com"], pdns_provider="DNSDB Scout",
        pdns=pd.DataFrame([{"Domain": "domaintools.com", "RRName": name, "Field": "A", "Value": "1.1.1.1",
                            "Date": pd.Timestamp("2026-10-01"), "First Seen": pd.Timestamp("2026-10-01"),
                            "Last Seen": pd.Timestamp("2026-10-02")} for name in ("api.domaintools.com", "www.domaintools.com")]),
    )
    ds = build_dataset(collected, ["domaintools.com"], [], ["A"], "UTC", host_focus=FOCUS)
    assert set(ds.pdns_utc["RRName"]) == {"api.domaintools.com"} and ds.host_focus == FOCUS
    assert set(ds.hostname_inventory["Hostname"]) == {"api.domaintools.com", "www.domaintools.com"}
    assert set(build_dataset(collected, ["domaintools.com"], [], ["A"], "UTC").pdns_utc["RRName"]) == \
        {"api.domaintools.com", "www.domaintools.com"}


def test_hostnames_link_to_named_and_wildcard_certificates():
    sha_new, sha_old, sha1 = "aa" * 32, "BB" * 32, "cc" * 20
    ssl = pd.DataFrame([
        {"Domain": "domaintools.com", "Hash": sha_new, "SAN DNS": ["api.domaintools.com"], "Common Name": "api.domaintools.com",
         "Issuer": "R3", "Source": "DomainTools Cert API", "Not Before Date": pd.Timestamp("2026-10-01"),
         "Not After Date": pd.Timestamp("2026-12-30")},
        {"Domain": "domaintools.com", "Hash": sha_old, "SAN DNS": ["*.domaintools.com"], "Common Name": "*.domaintools.com",
         "Issuer": "R3", "Source": "DomainTools Cert API", "Not Before Date": pd.Timestamp("2025-01-01")},
        {"Domain": "domaintools.com", "Hash": sha1, "SAN DNS": ["domaintools.com"], "Common Name": "domaintools.com",
         "Source": "Domain History", "Not Before Date": pd.Timestamp("2024-01-01")},
        {"Domain": "domaintools.com", "Hash": "", "SAN DNS": ["api.domaintools.com"], "Common Name": ""},   # no hash
    ])
    links = build_hostname_certificates(ssl, ["api.domaintools.com", "domaintools.com", "a.b.domaintools.com"])
    assert list(zip(links["Hostname"], links["Match"], links["Certificate Hash"], links["Hash Type"])) == [
        ("api.domaintools.com", "Named", sha_new, "SHA-256"),          # newest first
        ("api.domaintools.com", "Wildcard", sha_old.lower(), "SHA-256"),
        ("domaintools.com", "Named", sha1, "SHA-1"),                    # *.domaintools.com does not cover the apex
    ]
    assert build_hostname_certificates(pd.DataFrame(), ["api.domaintools.com"]).empty


def test_coverage_lookup_matches_the_certificate_rule():
    from core.hostnames import _covered_names, _is_covered
    cert_sets = [["api.domaintools.com"], ["*.domaintools.com"], ["x.api.domaintools.com"], ["domaintools.com"],
                 ["*.a.domaintools.com", "mail.example.com"], ["*.b.domaintools.com"]]
    hosts = ["api.domaintools.com", "www.domaintools.com", "domaintools.com", "a.b.domaintools.com", "*.domaintools.com",
             "*.api.domaintools.com", "z.a.domaintools.com", "a.domaintools.com", "example.com", "*.example.com",
             "other.org", "b.domaintools.com"]
    for chosen in ([], *([c] for c in cert_sets), cert_sets):
        certs = [{"names": names} for names in chosen]
        names, parents = _covered_names(certs)
        for host in hosts:
            expected = any(certificate_in_focus(c["names"], [host]) for c in certs)
            assert _is_covered(host, names, parents) == expected, (chosen, host)

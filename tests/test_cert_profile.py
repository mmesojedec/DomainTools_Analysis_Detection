"""Certificate profile (core.cert_profile): certificates once each, flags, related certificates, field map, breakdown."""
import pandas as pd

from core import cert_profile as cp

NOW = pd.Timestamp("2026-11-20")


def _cert(**fields):
    base = {"Domain": "ex.com", "Source": "DomainTools Cert API", "Hash": "a" * 64, "Common Name": "www.ex.com",
            "Issuer": "R11", "Issuer Org": "Let's Encrypt", "Subject DN": "cn=www.ex.com", "Issuer DN": "cn=r11",
            "Not Before": NOW - pd.Timedelta(days=10), "Not After": NOW + pd.Timedelta(days=80), "Duration": 90,
            "Validation Level": "dv", "Public Key Algo": "RSA", "Public Key Bits": 2048, "Public Key SHA256": "k1",
            "SAN DNS": ["www.ex.com", "ex.com"], "SAN Count": 2, "Has Embedded SCTs": True, "Is Precertificate": False,
            "Is Self Signed": False, "Signature Algo": "sha256WithRSAEncryption",
            "JA4X": "aaaaaaaaaaaa_bbbbbbbbbbbb_cccccccccccc", "Key Usage": "Digital Signature",
            "Extended Key Usage": "Server Authentication", "Basic Constraints": "CA:FALSE"}
    return {**base, **fields}


def test_certificates_are_listed_once_with_their_domains_newest_first():
    ssl = pd.DataFrame([_cert(), _cert(Domain="ex.org"),
                        _cert(Hash="b" * 64, **{"Not Before": NOW - pd.Timedelta(days=1)})])
    certs = cp.certificates(ssl)
    assert list(certs["Hash"]) == ["b" * 64, "a" * 64]
    assert certs.iloc[1]["Domains"] == ["ex.com", "ex.org"]
    assert cp.label(certs.iloc[0]).startswith("www.ex.com · R11 · 2026-11-19 · bbbbbbbbbbbb")
    assert cp.certificates(pd.DataFrame()).empty


def test_a_clean_certificate_has_no_flags_and_a_bad_one_has_them_all():
    assert cp.flags(_cert(), now=NOW).empty
    aware = _cert(**{"Not Before": (NOW - pd.Timedelta(days=10)).tz_localize("UTC"),
                     "Not After": (NOW - pd.Timedelta(days=1)).tz_localize("UTC")})      # as the run stores them
    assert list(cp.flags(aware, now=NOW)["Field"]) == ["Not After"]
    assert cp.text(aware["Not After"]) == "2026-11-19 00:00"
    bad = _cert(**{"Is Self Signed": True, "Public Key Bits": 1024, "Signature Algo": "sha1WithRSAEncryption",
                   "Basic Constraints": "CA:TRUE", "Not After": NOW - pd.Timedelta(days=1),
                   "Not Before": NOW - pd.Timedelta(days=900), "SAN DNS": ["*.ex.com"],
                   "JA4X": "000000000000_4f24da86fad6_bf0f0589fc03", "Extended Key Usage": "Code Signing"})
    found = cp.flags(bad, now=NOW)
    text = " ".join(found["Finding"])
    for expected in ("Self-signed", "Weak key: RSA 1024", "Deprecated signature algorithm", "CA:TRUE", "Expired on",
                     "Wildcard SAN", "JA4X matches", "Code Signing"):
        assert expected in text, expected
    assert found.iloc[0]["Severity"] in ("Critical", "High")          # most severe first
    long_trusted = cp.flags(_cert(**{"Not Before": NOW - pd.Timedelta(days=10),
                                     "Not After": NOW + pd.Timedelta(days=500)}), now=NOW)
    assert "longer than the 398-day limit" in " ".join(long_trusted["Finding"])
    no_scts = cp.flags(_cert(**{"Has Embedded SCTs": False}), now=NOW)
    assert list(no_scts["Field"]) == ["Has Embedded SCTs"]


def test_related_certificates_and_key_reuse():
    certs = cp.certificates(pd.DataFrame([
        _cert(), _cert(Hash="b" * 64, Issuer="Other CA", **{"Common Name": "x.ex.com", "SAN DNS": ["x.ex.com"]}),
        _cert(Hash="c" * 64, **{"Public Key SHA256": "k2"}),
        _cert(Hash="d" * 64, **{"Public Key SHA256": "k3", "Common Name": "y.ex.com", "SAN DNS": ["y.ex.com"]})]))
    cert = certs[certs["Hash"] == "a" * 64].iloc[0].to_dict()
    related = cp.related_certificates(cert, certs)
    pairs = set(zip(related["Relation"], related["Hash"].str[0]))
    assert pairs == {("Same public key", "b"), ("Same SAN set", "c"), ("Same common name", "c")}
    assert "Same JA4X" not in set(related["Relation"])     # a CA's usual layout, shared by all: not a relation
    found = cp.flags(cert, now=NOW, related=related)
    assert "Public key reused by 1 other certificate(s)" in " ".join(found["Finding"])


def test_field_map_breakdown_and_citing_alerts():
    cert = _cert(**{"Is Self Signed": True})
    found = cp.flags(cert, now=NOW)
    dot = cp.field_map(cert, found)
    assert dot.startswith("digraph") and "Subject alternative names" in dot and "Issuer" in dot
    assert '<TD BGCOLOR="#ea580c" ALIGN="LEFT"><FONT COLOR="white">Self-signed' in dot   # flagged: the flag's colour
    assert '<TD BGCOLOR="#cbd5e1" ALIGN="LEFT"><FONT COLOR="#475569">Organization' in dot   # empty: grey
    assert '<TD COLSPAN="2" BGCOLOR="#ea580c"' in dot                   # so is its section's title
    assert "&lt;" in cp.field_map({**cert, "Issuer DN": "cn=<x>"})      # values are escaped
    certs = cp.certificates(pd.DataFrame([_cert(), _cert(Hash="b" * 64, **{"Issuer Org": "Odd CA"}),
                                          _cert(Hash="c" * 64)]))
    breakdown = cp.field_breakdown(certs).set_index("Field")
    assert "SHA-256" not in breakdown.index                              # unique per certificate: left out
    org = breakdown[breakdown["Section"] == "Issuer"].loc["Organization"]
    assert (org["Filled %"], org["Distinct"], org["Most common"], org["Rare values"]) == \
        (100, 2, "Let's Encrypt (2)", "Odd CA")
    alerts = pd.DataFrame([{"Severity": "High", "Domain": "ex.com", "Threat Type": "t",
                            "Triggering IOCs": f"cert {'a' * 16}", "Threat Logic": ""},
                           {"Severity": "Low", "Domain": "ex.com", "Threat Type": "u", "Triggering IOCs": "",
                            "Threat Logic": ""}])
    assert list(cp.citing_alerts("a" * 64, alerts)["Threat Type"]) == ["t"]
    seen = cp.where_seen("A" * 64, ctl=pd.DataFrame({"Hash": ["a" * 64, "z"], "Log Host": ["ct.example", "x"]}))
    assert list(seen) == ["CT logs"] and len(seen["CT logs"]) == 1

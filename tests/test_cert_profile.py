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


def test_breakdown_and_citing_alerts():
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


def test_dates_in_every_source_format_are_read_and_arrow_safe():
    assert cp.when(20261116) == pd.Timestamp("2026-11-16")              # Domain History: YYYYMMDD as a number
    assert cp.when("20261116") == pd.Timestamp("2026-11-16")            # Iris Investigate: as text
    assert cp.when("2026-11-16T05:04:25Z") == pd.Timestamp("2026-11-16 05:04:25")
    assert cp.when(1794787200) == pd.Timestamp("2026-11-16")            # epoch seconds
    assert pd.isna(cp.when("")) and pd.isna(cp.when(None)) and pd.isna(cp.when(123))
    ssl = pd.DataFrame([_cert(Source="Domain History", **{"Not Before": 20261001, "Not After": 20261230,
                                                          "Issuer Org": ""}),
                        _cert(**{"Not Before": "2026-10-01T05:00:00Z", "Not After": "2026-12-30T05:00:00Z"}),
                        _cert(Hash="b" * 64, Source="Domain History", **{"Not Before": 20261110,
                                                                          "Not After": 20270208})])
    certs = cp.certificates(ssl)
    assert list(certs["Hash"]) == ["b" * 64, "a" * 64]                  # newest first, not by raw number
    assert str(certs["Not Before"].dtype).startswith("datetime64")
    a = certs[certs["Hash"] == "a" * 64].iloc[0]
    assert a["Issuer Org"] == "Let's Encrypt" and a["Sources"] == ["Domain History", "DomainTools Cert API"]
    related = cp.related_certificates(a.to_dict(), certs)
    assert str(related["Not Before"].dtype).startswith("datetime64")
    import pyarrow as pa
    pa.Table.from_pandas(related)                                          # what st.dataframe does
    pa.Table.from_pandas(certs.drop(columns=[c for c in certs if certs[c].map(type).eq(list).any()]))


def test_most_relevant_is_the_valid_certificate_for_the_domain_itself():
    def cert(digest, names, start, end, source="DomainTools Cert API"):
        return _cert(Hash=digest * 64, Source=source, **{"Common Name": names[0], "SAN DNS": names,
                                                         "Not Before": NOW + pd.Timedelta(days=start),
                                                         "Not After": NOW + pd.Timedelta(days=end)})
    certs = cp.certificates(pd.DataFrame([
        cert("a", ["new.ex.com"], -1, 89),                      # newest, but a subdomain's
        cert("b", ["ex.com", "www.ex.com"], -30, 60),           # the domain's own
        cert("c", ["ex.com"], -200, -110),                      # the domain's own, expired
        cert("d", ["*.ex.com"], -20, 70),                       # wildcard
        cert("e", ["ex.com"], -40, 50, source="Iris Investigate API")]))   # the domain's own, served now
    order = cp.ranked(certs, "ex.com", now=NOW)
    assert list(order["Hash"].str[0]) == ["e", "b", "d", "a", "c"]
    assert list(order["Role"]) == ["Apex", "Apex", "Wildcard", "Subdomain", "Apex"]
    assert order.iloc[-1]["Status"] == "Expired" and bool(order.iloc[0]["Served"])
    assert cp.most_relevant(certs, "ex.com", now=NOW) == "e" * 64
    assert cp.label(order.iloc[0]).startswith("[Apex · Valid · served now] ex.com")
    assert list(cp.ranked(certs, "ex.com", "Newest issued", NOW)["Hash"].str[0])[0] == "a"
    assert list(cp.ranked(certs, "ex.com", "Expiring soonest", NOW)["Hash"].str[0]) == ["e", "b", "d", "a", "c"]


def test_anatomy_draws_every_section_flags_under_their_fields_and_filters():
    from core.cert_anatomy import anatomy_html, render_value
    cert = _cert(**{"Is Self Signed": True, "SAN DNS": ["www.ex.com", "ex.com", "*.other.net"],
                    "Issuer DN": "C=US, O=Let's Encrypt, CN=<R11>", "Public Key Bits": 1024})
    found = cp.flags(cert, now=NOW)
    page = anatomy_html(cert, found, domains=["ex.com"], now=NOW)
    for section in ("Subject", "Issuer", "Validity", "Public key", "Extensions", "Subject alternative names",
                    "Signature and fingerprints"):
        assert f">{section}<small>" in page, section
    assert "Self-signed: no certificate authority vouches for it" in page           # the flag under its field
    assert "Field fingerprint" in page and "Key strength" in page and "80-bit security · weak" in page
    assert "&lt;R11&gt;" in page and "<R11>" not in page                            # values are escaped
    assert '<span class="chip own">www.ex.com</span>' in page and '<span class="chip wild">*.other.net' in page
    assert "2 of the analyzed domain(s) · 1 other" in page
    assert "State / province" not in page.split('class="grid"')[1]                     # empty: left out ...
    every = anatomy_html(cert, found, only_filled=False, now=NOW)
    assert "State / province" in every.split('class="grid"')[1]                         # ... unless asked
    found_only = anatomy_html(cert, found, query="sha256WithRSA", now=NOW).split('class="grid"')[1]
    assert "Signature algorithm" in found_only and "Common name" not in found_only
    assert "No field, value or explanation matches" in anatomy_html(cert, found, query="zzz-nothing", now=NOW)
    by_name = anatomy_html({**cert, "Extension OIDs": ["1.3.6.1.5.5.7.1.1"]}, found, query="ocsp", now=NOW)
    assert "Extension OIDs" in by_name.split('class="grid"')[1]                # matches the OID's shown name
    assert render_value("JA4X", cert) == ('<span class="mono hex">' + "<i>_</i>".join(
        ["<span>aaaa</span>" * 3, "<span>bbbb</span>" * 3, "<span>cccc</span>" * 3]) + "</span>")
    assert render_value("Hash", cert).count("<span>") == 16                         # 64 hex in groups of four
    assert "398-day limit" in anatomy_html(_cert(**{"Not After": NOW + pd.Timedelta(days=600)}), now=NOW)


def test_anatomy_reads_the_certificate_apis_structured_extensions():
    from core.cert_anatomy import render_value
    api = _cert(**{"Basic Constraints": {"critical": True, "is_ca": True},
                   "Certificate Policy": [{"policy_oid": "2.23.140.1.2.1"}],
                   "Extension OIDs": ["2.5.29.15", "1.3.6.1.4.1.11129.2.4.3", "9.9.9"],
                   "Signed Certificate Timestamps": [{"log_id": "ab" * 32, "timestamp": "2026-11-10T00:05:00Z"}],
                   "Is Precertificate": True, "Has Embedded SCTs": False})
    assert "CA:TRUE" in " ".join(cp.flags(api, now=NOW)["Finding"])        # the dict form is flagged too
    assert "CA: yes, may issue certificates" in render_value("Basic Constraints", api)
    assert "Domain validated (CA/B Forum)" in render_value("Certificate Policy", api)
    oids = render_value("Extension OIDs", api)
    assert "<b>2</b>CT poison (precertificate)" in oids and "unknown" in oids
    assert "1 CT log(s) signed it" in render_value("Signed Certificate Timestamps", api)
    assert "expected" in render_value("Has Embedded SCTs", api)
    assert "CA: yes" in render_value("Basic Constraints", {"Basic Constraints": "{'critical': True, 'is_ca': True}"})

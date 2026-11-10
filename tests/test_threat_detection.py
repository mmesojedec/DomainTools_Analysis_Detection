import pandas as pd

from config import DEFAULT_THRESHOLDS
from core.risk_profile import generate_digital_risk_profile
from core.threat_detection import analyze_txt_fingerprints, detect_threat_flags


def ts(value):
    return pd.Timestamp(value)


def risk_frame(domain, score):
    return pd.DataFrame([{"Domain": domain, "Component": "Overall Risk", "Score": score, "Threats": "", "Evidence": "phishing"}])


def events(rows):
    df = pd.DataFrame(rows)
    df["Date"] = pd.to_datetime(df["Date"], format="mixed")
    return df


def types(result):
    return set(result.alerts["Threat Type"]) if not result.alerts.empty else set()


def test_unknown_risk_is_evaluated_not_skipped():
    # Regression: a failed risk lookup produced score 0 and silently skipped every domain
    ev = events([{"Domain": "a.com", "Date": "2024-01-01", "Field": "MX", "Value": "mx.yandex.ru"}])
    result = detect_threat_flags(ev, {"risk_score": 70}, risk_df=pd.DataFrame())
    assert result.unscored_domains == ["a.com"]
    assert result.skipped_domains == []
    assert "High-Risk Mail Provider" in types(result)


def test_known_low_risk_is_skipped():
    ev = events([{"Domain": "a.com", "Date": "2024-01-01", "Field": "MX", "Value": "mx.yandex.ru"}])
    result = detect_threat_flags(ev, {"risk_score": 70}, risk_df=risk_frame("a.com", 10))
    assert result.skipped_domains == ["a.com"]
    assert result.alerts.empty


def test_nan_flags_from_mixed_sources_do_not_alert():
    # Regression: Domain History rows lack Cert API columns -> NaN -> bool(NaN) == True
    cert_api = pd.DataFrame([{"Domain": "a.com", "Hash": "h1", "Source": "DomainTools Cert API", "Common Name": "a.com",
                              "Issuer": "DigiCert", "Is Precertificate": False, "Has Embedded SCTs": True,
                              "Alt Names List": ["a.com"], "Not Before Date": ts("2024-01-01"), "Not After Date": ts("2024-12-01")}])
    dh = pd.DataFrame([{"Domain": "a.com", "Hash": "h2", "Source": "Domain History", "Common Name": "a.com",
                        "Issuer": "DigiCert", "Alt Names List": ["a.com"], "Is Self Signed": False}])
    ssl = pd.concat([cert_api, dh], ignore_index=True)
    assert pd.isna(ssl.loc[1, "Is Precertificate"])
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl)
    assert "Pre-Certificate Staging (CT Log Only)" not in types(result)
    assert "CT Log Evasion / Missing SCTs" not in types(result)


def test_explicit_precert_and_missing_scts_alert():
    ssl = pd.DataFrame([{"Domain": "a.com", "Hash": "h1", "Source": "DomainTools Cert API", "Common Name": "a.com",
                         "Issuer": "DigiCert", "Is Precertificate": True, "Has Embedded SCTs": False, "Alt Names List": ["a.com"]}])
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl)
    assert {"Pre-Certificate Staging (CT Log Only)", "CT Log Evasion / Missing SCTs"} <= types(result)


def test_rapid_weaponization_cert_to_dns_gap():
    ev = events([{"Domain": "a.com", "Date": "2024-03-01 10:30", "Field": "A", "Value": "1.2.3.4"}])
    ssl = pd.DataFrame([{"Domain": "a.com", "Hash": "h1", "Source": "DomainTools Cert API", "Common Name": "a.com",
                         "Issuer": "Let's Encrypt R3", "Duration": 90, "Alt Names List": ["a.com"],
                         "Not Before Date": ts("2024-03-01 10:00"), "Not After Date": ts("2024-05-30 10:00")}])
    result = detect_threat_flags(ev, {"risk_score": 0}, ssl_df=ssl)
    assert "Rapid Weaponization (Cert-to-DNS Gap)" in types(result)
    assert "Short-Lived Certificate" not in types(result)   # 90-day certificates are normal


def _cert(hash_value, issued, days, names=("a.com",), issuer="Let's Encrypt E6", **extra):
    issued = ts(issued)
    return {"Domain": "a.com", "Hash": hash_value, "Source": "DomainTools Cert API", "Common Name": names[0], "Issuer": issuer,
            "Duration": days, "Alt Names List": list(names), "Not Before Date": issued,
            "Not After Date": issued + pd.Timedelta(days=days), **extra}


def test_short_lived_certificate_is_informational():
    ssl = pd.DataFrame([_cert("h1", "2026-10-01", 6.67)])
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl)
    row = result.alerts.set_index("Threat Type").loc["Short-Lived Certificate"]
    assert (row["Severity"], row["Confidence"]) == ("Low", "High")
    profiles = generate_digital_risk_profile(["a.com"], result.alerts, pd.DataFrame(), ssl, pd.DataFrame(), {})
    assert profiles.loc[0, "Certificate Trust"] == 0   # not scored


def test_scheduled_short_lived_renewals_are_not_churn():
    # 6-day certificates renewed every 4 days: the previous one has a third of its validity left each time
    ssl = pd.DataFrame([_cert(f"h{i}", pd.Timestamp("2026-10-01") + pd.Timedelta(days=4 * i), 6.67) for i in range(8)])
    assert "Certificate Churn (Ephemeral SSL)" not in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl))


def test_early_replacements_are_churn():
    # 90-day certificates replaced after 5 days, three times in a row
    ssl = pd.DataFrame([_cert(f"h{i}", pd.Timestamp("2026-10-01") + pd.Timedelta(days=5 * i), 90) for i in range(4)])
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 0, "ssl_churn_count": 2}, ssl_df=ssl)
    row = result.alerts.set_index("Threat Type").loc["Certificate Churn (Ephemeral SSL)"]
    assert "replaced early" in row["Threat Logic"]
    assert [r["Field"] for r in row["Evidence"]] == ["Early replacement"] * 3


def test_parallel_issuance_and_different_names_are_not_churn():
    ssl = pd.DataFrame([_cert("h1", "2026-10-01 00:00", 90), _cert("h2", "2026-10-01 02:00", 90, issuer="Google Trust Services"),
                        _cert("h3", "2026-10-03", 90, names=("b.a.com",)), _cert("h4", "2026-10-05", 90, names=("c.a.com",))])
    assert "Certificate Churn (Ephemeral SSL)" not in types(
        detect_threat_flags(pd.DataFrame(), {"risk_score": 0, "ssl_churn_count": 1}, ssl_df=ssl))


def test_cabf_validity_limit_follows_issue_date():
    def flagged(issued, days):
        ssl = pd.DataFrame([_cert("h", issued, days, issuer="DigiCert", **{"Has Embedded SCTs": True})])
        return "Non-Compliant Validity Window" in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl))
    assert not flagged("2025-06-01", 397) and flagged("2025-06-01", 400)
    assert not flagged("2026-04-01", 199) and flagged("2026-04-01", 250)
    assert flagged("2027-04-01", 150) and not flagged("2027-04-01", 90)
    assert flagged("2029-04-01", 90) and not flagged("2029-04-01", 45)


def test_private_ca_long_validity_is_not_cabf_violation():
    ssl = pd.DataFrame([_cert("h", "2026-06-01", 730, issuer="Internal Corp CA", **{"Has Embedded SCTs": False})])
    assert "Non-Compliant Validity Window" not in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=ssl))


def test_threat_text_is_not_html_escaped():
    ev = events([{"Domain": "a.com", "Date": "2024-01-01", "Field": "MX", "Value": "mx.yandex.ru"}])
    enrichment = {"a.com": {"website_title": {"value": "Xtream IPTV Server's Panel"}, "website_response": 200}}
    result = detect_threat_flags(ev, {"risk_score": 0}, enrichment_data=enrichment)
    logic = result.alerts.set_index("Threat Type").loc["Live Pirate Streaming Panel Detected", "Threat Logic"]
    assert "Server's" in logic and "&#x27;" not in logic


def test_fast_flux_counts_multi_value_rrsets():
    ev = events([
        {"Domain": "a.com", "Date": "2024-01-01", "Field": "A", "Value": "1.1.1.1\n2.2.2.2"},
        {"Domain": "a.com", "Date": "2024-01-03", "Field": "A", "Value": "3.3.3.3\n4.4.4.4"},
        {"Domain": "a.com", "Date": "2024-01-05", "Field": "A", "Value": "5.5.5.5"},
        {"Domain": "a.com", "Date": "2024-02-20", "Field": "A", "Value": "6.6.6.6"},
    ])
    result = detect_threat_flags(ev, {"risk_score": 0, "flux_ips": 5})
    assert "Rapid IP Rotation (Fast-Flux)" in types(result)
    no_flux = detect_threat_flags(ev, {"risk_score": 0, "flux_ips": 6})
    assert "Rapid IP Rotation (Fast-Flux)" not in types(no_flux)


def test_parked_to_weaponized_uses_gaps_recomputed_after_merge():
    # DH and pDNS each have small internal gaps; only the merged timeline shows the long dormancy
    dh = events([
        {"Domain": "a.com", "Date": "2023-01-01", "Field": "NS", "Value": "ns1", "Days Since Previous Event": 0},
        {"Domain": "a.com", "Date": "2024-01-01 00:00", "Field": "NS", "Value": "ns2", "Days Since Previous Event": 365},
    ])
    pdns = events([
        {"Domain": "a.com", "Date": "2024-01-01 06:00", "Field": "A", "Value": "1.1.1.1", "Days Since Previous Event": 0},
        {"Domain": "a.com", "Date": "2024-01-01 12:00", "Field": "MX", "Value": "mx", "Days Since Previous Event": 0.25},
        {"Domain": "a.com", "Date": "2024-01-01 18:00", "Field": "TXT", "Value": "v=spf1 -all", "Days Since Previous Event": 0.25},
    ])
    merged = pd.concat([dh, pdns], ignore_index=True)
    result = detect_threat_flags(merged, {"risk_score": 0, "parked_days": 180})
    assert "Parked-to-Weaponized" in types(result)


def test_bare_ip_rules_for_ip_targets():
    base = {"Source": "DomainTools Cert API", "Issuer": "ZeroSSL", "Hash": "h1", "Common Name": "203.0.113.5"}
    only_target = pd.DataFrame([{**base, "Domain": "203.0.113.5", "Alt Names List": ["203.0.113.5"]}])
    assert not ({"Bare-IP Certificate (C2 / Proxy Node)", "SSL Common Name (CN) Mismatch"} & types(
        detect_threat_flags(pd.DataFrame(), {}, ssl_df=only_target)))
    multi = pd.DataFrame([{**base, "Domain": "203.0.113.5", "Alt Names List": ["203.0.113.5", "2001:db8::7"]}])
    assert "Multi-IP Certificate (Shared C2 / Proxy Cluster)" in types(detect_threat_flags(pd.DataFrame(), {}, ssl_df=multi))
    on_domain = pd.DataFrame([{**base, "Domain": "a.com", "Common Name": "a.com", "Alt Names List": ["a.com", "2001:db8::7"]}])
    assert "Bare-IP Certificate (C2 / Proxy Node)" in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=on_domain))


def test_public_short_lived_ip_certificate_is_downgraded():
    base = {"Domain": "a.com", "Hash": "h1", "Source": "DomainTools Cert API", "Common Name": "a.com",
            "Alt Names List": ["a.com", "203.0.113.5"]}
    public = pd.DataFrame([{**base, "Issuer": "Let's Encrypt E6", "Duration": 6.67, "Has Embedded SCTs": True}])
    row = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=public).alerts.set_index("Threat Type")
    assert tuple(row.loc["Bare-IP Certificate (C2 / Proxy Node)", ["Severity", "Confidence"]]) == ("Medium-High", "Low")
    private = pd.DataFrame([{**base, "Issuer": "a.com", "Duration": 6.67}])   # self-signed
    row = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=private).alerts.set_index("Threat Type")
    assert row.loc["Bare-IP Certificate (C2 / Proxy Node)", "Severity"] == "Critical"


def test_weak_key_respects_algorithm():
    def certs(bits, algo):
        return pd.DataFrame([{"Domain": "a.com", "Hash": "h", "Source": "DomainTools Cert API", "Common Name": "a.com",
                              "Issuer": "DigiCert", "Public Key Bits": bits, "Public Key Algo": algo, "Alt Names List": ["a.com"]}])
    assert "Weak Cryptographic Key Material" not in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=certs(256, "ECDSA")))
    assert "Weak Cryptographic Key Material" in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=certs(1024, "RSA")))


def test_mega_san_uses_registrable_domains():
    sans = ["a.example.co.uk", "b.example.co.uk", "www.other.co.uk"]
    ssl = pd.DataFrame([{"Domain": "example.co.uk", "Hash": "h", "Source": "DomainTools Cert API", "Common Name": "a.example.co.uk",
                         "Issuer": "DigiCert", "Alt Names List": sans}])
    # co.uk would previously count as one "root domain" for all three; correct count is 2
    assert "Mega-SAN Cluster (Bulk Infrastructure)" not in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0, "ssl_san": 3}, ssl_df=ssl))
    assert "Mega-SAN Cluster (Bulk Infrastructure)" in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0, "ssl_san": 2}, ssl_df=ssl))


def test_caa_breach_detected_end_to_end():
    ev = events([{"Domain": "a.com", "RRName": "a.com", "Date": "2024-01-01", "Field": "CAA", "Value": '0 issue "digicert.com"\n0 issuewild ";"'}])
    ssl = pd.DataFrame([{"Domain": "a.com", "Hash": "h", "Source": "DomainTools Cert API", "Common Name": "*.a.com",
                         "Issuer": "Let's Encrypt R3", "Has Wildcard SAN": True, "Alt Names List": ["*.a.com"]}])
    assert "Wildcard Issuance Forbidden by CAA Policy" in types(detect_threat_flags(ev, {"risk_score": 0}, ssl_df=ssl))


def _wildcard_cert(sans, has_flag=True):
    return pd.DataFrame([{"Domain": "zedxion.com", "Hash": "h", "Source": "DomainTools Cert API", "Common Name": sans[0],
                          "Issuer": "Amazon RSA 2048 M04", "Has Wildcard SAN": has_flag, "Alt Names List": sans,
                          "SAN Count": len(sans)}])


def test_wildcard_certificate_flagged_low():
    alerts = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=_wildcard_cert(["*.zedxion.com", "zedxion.com"]))
    match = [a for a in alerts.alerts.to_dict("records") if a["Threat Type"] == "Wildcard Certificate Observed"]
    assert len(match) == 1 and match[0]["Severity"] == "Low" and match[0]["Category"] == "Certificates"
    assert "*.zedxion.com" in match[0]["Triggering IOCs"]


def test_wildcard_detected_from_san_without_api_flag():
    alerts = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=_wildcard_cert(["zedxion.com", "*.zedxion.com"], has_flag=False))
    assert "Wildcard Certificate Observed" in types(alerts)


def test_wildcard_sprawl_replaces_low_observation():
    sans = ["*.zedxion.com"] + [f"h{i}.zedxion.com" for i in range(5)]
    found = types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=_wildcard_cert(sans)))
    assert "Wildcard Infrastructure Sprawl" in found and "Wildcard Certificate Observed" not in found


def test_plain_certificate_not_flagged_as_wildcard():
    found = types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=_wildcard_cert(["zedxion.com"], has_flag=False)))
    assert "Wildcard Certificate Observed" not in found


def test_old_long_validity_cert_not_flagged():
    def cert(not_before):
        return pd.DataFrame([{"Domain": "a.com", "Hash": "h", "Source": "DomainTools Cert API", "Common Name": "a.com",
                              "Issuer": "DigiCert", "Duration": 730, "Not Before Date": ts(not_before), "Alt Names List": ["a.com"]}])
    assert "Non-Compliant Validity Window" not in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=cert("2019-06-01")))
    assert "Non-Compliant Validity Window" in types(detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=cert("2023-06-01")))


def test_thresholds_default_when_missing():
    result = detect_threat_flags(pd.DataFrame(), None)
    assert result.alerts.empty and set(DEFAULT_THRESHOLDS) >= {"gap_hours", "short_lived_days"}


def test_txt_fingerprints():
    df = pd.DataFrame([{"Domain": "a.com", "Field": "pDNS: TXT", "Source": "", "Value": '"v=spf1 -all"\n"' + "A" * 40 + '"',
                        "Date": ts("2024-01-01")}])
    apps = analyze_txt_fingerprints(df)
    assert list(apps["Application / Tag"]) == ["SPF", "Suspicious Base64 Payload"]


def test_txt_fingerprint_yahoo_verification():
    df = pd.DataFrame([{"Domain": "a.com", "Field": "TXT", "Source": "", "Date": ts("2024-01-01"),
                        "Value": '"yahoo-verification-key=5bF6siWgzdkfub3ZLp8cnSL2ps44ipYuy28vgoM7qDA="'}])
    assert analyze_txt_fingerprints(df)["Application / Tag"].tolist() == ["Yahoo"]


def test_txt_fingerprint_bimi():
    df = pd.DataFrame([{"Domain": "a.com", "Field": "TXT", "Source": "", "Date": ts("2024-01-01"),
                        "Value": '"v=BIMI1; l=https://www.reuters.com/static/email/bimi_logo.svg"'}])
    assert analyze_txt_fingerprints(df)["Application / Tag"].tolist() == ["BIMI (Brand Logo)"]


def test_new_txt_fingerprints():
    values = {"globalsign-domain-verification=31A4E2C60CF20D90F4A4D4681EA87DC3": "GlobalSign SSL",
              "_globalsign-domain-verification=nPcGMc5MexVHi5gaiJ3TNZjT3fI_seEOQWXPUSMmWm": "GlobalSign SSL",
              "canva-site-verification=C8ADd96ykBUHF3wyVjPyXQ": "Canva",
              "mongodb-site-verification=mtrxHeW3jOzWtwEwnOLpeQo9NXh6Lqas": "MongoDB Atlas",
              "cisco-ci-domain-verification=4a1c92ef69fe42f8125c3ca9ce0696dcf6cc16fa80243257de578af593d19548":
                  "Cisco Common Identity (Webex / Duo)",
              "spf2.0/pra include:cust-senderid.exacttarget.com -all": "Sender ID (SPF 2.0)"}
    df = pd.DataFrame([{"Domain": "a.com", "Field": "TXT", "Source": "", "Value": f'"{value}"', "Date": ts("2024-01-01")}
                       for value in values])
    assert analyze_txt_fingerprints(df)["Application / Tag"].tolist() == list(values.values())

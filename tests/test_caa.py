import pandas as pd

from core.caa import extract_domain_caa_policy, is_issuer_authorized_by_caa, parse_caa_entry


def caa_frame(value, domain="x.com", rrname=None):
    return pd.DataFrame([{"Domain": domain, "RRName": rrname or domain, "Field": "CAA", "Value": value}])


LE_WILDCARD = {"Has Wildcard SAN": True, "Issuer": "Let's Encrypt R3", "Common Name": "*.x.com"}
LE_PLAIN = {"Has Wildcard SAN": False, "Issuer": "Let's Encrypt R3", "Common Name": "x.com"}
DIGICERT = {"Has Wildcard SAN": False, "Issuer": "DigiCert Global G2 TLS RSA SHA256 2020 CA1", "Common Name": "x.com"}


def test_parse_caa_entry():
    assert parse_caa_entry('0 issue "letsencrypt.org"') == {"flag": 0, "tag": "issue", "value": "letsencrypt.org"}
    assert parse_caa_entry('0 issuewild ";"')["value"] == ";"
    assert parse_caa_entry("garbage") is None


def test_issuewild_semicolon_forbids_wildcards():
    # Regression: ";" used to become an empty CA string that authorized every issuer
    policy = extract_domain_caa_policy(caa_frame('0 issue "digicert.com"\n0 issuewild ";"'), "x.com")
    assert policy.auth_issue == {"digicert.com"}
    assert policy.auth_wild == set()
    assert policy.wild_forbidden
    is_auth, reason, _ = is_issuer_authorized_by_caa(LE_WILDCARD, policy)
    assert not is_auth and "Wildcard" in reason


def test_issue_semicolon_forbids_all_issuance():
    policy = extract_domain_caa_policy(caa_frame('0 issue ";"'), "x.com")
    assert policy.issue_forbidden and policy.wild_forbidden
    assert not is_issuer_authorized_by_caa(LE_PLAIN, policy)[0]
    assert not is_issuer_authorized_by_caa(DIGICERT, policy)[0]


def test_authorized_and_unauthorized_issuers():
    policy = extract_domain_caa_policy(caa_frame('0 issue "digicert.com"'), "x.com")
    assert is_issuer_authorized_by_caa(DIGICERT, policy)[0]
    assert not is_issuer_authorized_by_caa(LE_PLAIN, policy)[0]
    # Without issuewild, wildcard issuance falls back to the issue list
    assert not is_issuer_authorized_by_caa(LE_WILDCARD, policy)[0]


def test_issue_with_parameters_and_alias():
    policy = extract_domain_caa_policy(caa_frame('0 issue "letsencrypt.org; validationmethods=dns-01"'), "x.com")
    assert policy.auth_issue == {"letsencrypt.org"}
    assert is_issuer_authorized_by_caa(LE_PLAIN, policy)[0]


def test_no_policy_is_unrestricted():
    policy = extract_domain_caa_policy(pd.DataFrame(), "x.com")
    assert not policy.has_policy
    assert is_issuer_authorized_by_caa(LE_WILDCARD, policy)[0]


def test_subdomain_caa_does_not_change_apex_policy():
    frame = caa_frame('0 issue ";"', rrname="sub.x.com")
    assert not extract_domain_caa_policy(frame, "x.com").has_policy


def test_nan_wildcard_flag_is_not_a_wildcard():
    policy = extract_domain_caa_policy(caa_frame('0 issue "letsencrypt.org"\n0 issuewild ";"'), "x.com")
    cert = {"Has Wildcard SAN": float("nan"), "Issuer": "Let's Encrypt R3", "Common Name": "x.com"}
    assert is_issuer_authorized_by_caa(cert, policy)[0]


def test_iodef_and_prefixed_fields():
    frame = pd.DataFrame([{"Domain": "x.com", "Field": "pDNS: CAA", "Value": '0 iodef "mailto:sec@x.com"\n0 issue "pki.goog"'}])
    policy = extract_domain_caa_policy(frame, "x.com")
    assert policy.iodef_contacts == ["mailto:sec@x.com"]
    assert policy.auth_issue == {"pki.goog"}

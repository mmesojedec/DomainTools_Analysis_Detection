import math

import numpy as np
import pandas as pd
import pytest

from core.helpers import (
    calculate_shannon_entropy,
    classify_targets,
    domain_core_label,
    extract_ip_addresses,
    hostname_matches,
    ip_network_bucket,
    md_escape,
    normalize_to_apex,
    optional_bool,
    parse_raw_domain_inputs,
    refang_domain,
    registrable_domain,
    safe_bool,
)


@pytest.mark.parametrize("raw, expected", [
    ("hxxps://evil[.]com/path?q=1", "evil.com"),
    ("http://user@Example.COM:8443/x", "example.com"),
    ("evil(dot)com.", "evil.com"),
    ("hxxp[:]//bad{.}org", "bad.org"),
    ("2001:db8::1", "2001:db8::1"),
    ("", ""),
])
def test_refang_domain(raw, expected):
    assert refang_domain(raw) == expected


def test_parse_raw_inputs_dedupes_and_splits():
    assert parse_raw_domain_inputs("a.com, b.com\nA.com; 1.2.3.4") == ["a.com", "b.com", "1.2.3.4"]


def test_normalize_to_apex_converts_subdomains_and_dedupes():
    targets = parse_raw_domain_inputs(
        "vpn.designsolu[.]xyz\nhyperiptv[.]net\nunity-gaming[.]net\ndesignsolu.xyz\nwww.example.co.uk\n1.2.3.4\n2001:db8::1"
    )
    normalized, conversions = normalize_to_apex(targets)
    assert normalized == ["designsolu.xyz", "hyperiptv.net", "unity-gaming.net", "example.co.uk", "1.2.3.4", "2001:db8::1"]
    assert conversions == [("vpn.designsolu.xyz", "designsolu.xyz"), ("www.example.co.uk", "example.co.uk")]


def test_normalize_to_apex_leaves_apex_inputs_untouched():
    assert normalize_to_apex(["a.com", "b.org"]) == (["a.com", "b.org"], [])
    assert normalize_to_apex([]) == ([], [])


def test_classify_targets():
    result = classify_targets(["a.com", "1.2.3.4", "2001:db8::1", "a.com", "104.21.59.7/24", "2a00:1450::/32"])
    assert result == {"domains": ["a.com"], "ipv4": ["1.2.3.4"], "ipv6": ["2001:db8::1"],
                      "cidrs": ["104.21.59.0/24", "2a00:1450::/32"]}


@pytest.mark.parametrize("value, expected", [
    (float("nan"), None), (None, None), (pd.NaT, None), (np.nan, None),
    (True, True), (False, False), (np.True_, True), ("false", False), ("True", True), (1, True), (0, False),
])
def test_optional_bool(value, expected):
    assert optional_bool(value) is expected


def test_safe_bool_treats_nan_as_default():
    # Regression: bool(NaN) is True, which produced false precertificate/wildcard alerts
    assert bool(float("nan")) is True
    assert safe_bool(float("nan")) is False
    assert safe_bool(float("nan"), default=True) is True


@pytest.mark.parametrize("host, expected", [
    ("www.example.co.uk", "example.co.uk"),
    ("a.b.example.com", "example.com"),
    ("*.example.com.au", "example.com.au"),
    ("example.com", "example.com"),
    ("10.0.0.1", "10.0.0.1"),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


def test_domain_core_label_uses_registrable_label():
    # Regression: the entropy rule used to score "www" for www.example.com
    assert domain_core_label("www.example.co.uk") == "example"
    assert domain_core_label("login.xkq7zp2vw9.com") == "xkq7zp2vw9"


def test_extract_ip_addresses_handles_ipv4_and_ipv6():
    text = "1.2.3.4\n2001:db8::1 999.1.1.1 1.2.3.4"
    assert extract_ip_addresses(text) == ["1.2.3.4", "2001:db8::1"]


def test_ip_network_bucket():
    assert ip_network_bucket("192.168.10.77") == "192.168.10.0/24"
    assert ip_network_bucket("2001:db8:abcd:12::1") == "2001:db8:abcd::/48"
    assert ip_network_bucket("nope") == "Unknown"


@pytest.mark.parametrize("target, name, expected", [
    ("www.example.com", "example.com", True),
    ("example.com", "*.example.com", True),
    ("example.com", "other.com", False),
    ("example.com", "com", False),
    ("example.com", "localhost", False),
])
def test_hostname_matches(target, name, expected):
    assert hostname_matches(target, name) is expected


def test_md_escape_neutralizes_markdown_and_latex():
    escaped = md_escape("cost $5 *bold* [link](x)")
    assert "\\$" in escaped and "\\*" in escaped and "\\[" in escaped
    assert "&" not in md_escape("it's")  # no HTML entities


def test_entropy():
    assert calculate_shannon_entropy("") == 0
    assert math.isclose(calculate_shannon_entropy("abcd"), 2.0)

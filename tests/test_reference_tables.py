import re
from pathlib import Path

import pandas as pd

from core.intel_data import RULE_METADATA
from core.risk_profile import decode_dif, decode_profiles, generate_digital_risk_profile
from core.rule_catalog import RULE_CATALOG, rule_catalog_frame
from core.threat_detection.intel_rules import LOOKALIKE_SEVERITY

RULE_DIR = Path(__file__).resolve().parent.parent / "core" / "threat_detection"
ADD_CALL = re.compile(r'ctx\.add\(\s*"([^"]+)",\s*("[^"]+"|[^,]+),\s*"([^"]+)"')


def emitted_rules():
    """(threat type, severity expression, ATT&CK) for every ctx.add call with a literal threat type."""
    return [m.groups() for path in RULE_DIR.glob("*.py") for m in ADD_CALL.finditer(path.read_text())]


def test_catalog_covers_every_rule():
    emitted = {threat_type for threat_type, _, _ in emitted_rules()} | set(LOOKALIKE_SEVERITY)
    assert emitted == set(RULE_METADATA) == set(RULE_CATALOG)


def test_catalog_matches_rule_severity_and_attack():
    for threat_type, severity_expr, mitre in emitted_rules():
        catalog_severity, catalog_mitre, _, _ = RULE_CATALOG[threat_type]
        assert catalog_mitre == mitre, threat_type
        for level in re.findall(r'"([^"]+)"', severity_expr):   # every level the rule can assign
            assert level in catalog_severity, (threat_type, level)
    for threat_type, (severity, mitre) in LOOKALIKE_SEVERITY.items():
        assert RULE_CATALOG[threat_type][0].startswith(severity) and RULE_CATALOG[threat_type][1] == mitre


def test_catalog_frame_lists_fired_rules_first():
    alerts = pd.DataFrame({"Threat Type": ["Wildcard Certificate Observed", "Wildcard Certificate Observed", "Newly Registered Domain"]})
    frame = rule_catalog_frame(alerts)
    assert list(frame["Threat Type"][:2]) == ["Wildcard Certificate Observed", "Newly Registered Domain"]
    assert list(frame["In This Run"][:3]) == [2, 1, 0]
    assert frame.iloc[2]["Severity"].startswith("Critical")   # unfired rules by severity
    assert frame.set_index("Threat Type").loc["Bare-IP Certificate (C2 / Proxy Node)", "Tactic"] == "Command and Control"


def test_decode_dif_segments():
    decoded = decode_dif("F-CF_DVLE-R2048_EM_3fa91c")
    assert decoded == {"Hosting": "Dynamic / fast-flux (3+ IPs) on Cloudflare",
                       "TLS": "Domain Validated, Let's Encrypt, RSA 2048-bit",
                       "Identity & Apps": "SPF email routing (checked first)", "Config Hash": "3fa91c"}
    assert decode_dif("P-UN_NOCERT_NO_abcdef")["TLS"] == "No certificate"
    assert decode_dif("S-NX_UNUN-U_GW_123456")["TLS"] == "Unknown validation, Other / unknown CA, unknown key"
    assert decode_dif("F-UN_NAZS-U_NO_6dad83")["TLS"] == "Validation not reported, ZeroSSL, unknown key"
    assert decode_dif("garbage")["Config Hash"] == "garbage"


def test_decode_dif_from_earlier_versions_keeps_validity():
    assert decode_dif("F-CF_DVLE90-R2048_EM_3fa91c")["TLS"] == "Domain Validated, Let's Encrypt, 90-day validity, RSA 2048-bit"
    assert decode_dif("F-UN_NAZSU-U_NO_6dad83")["TLS"] == "Validation not reported, ZeroSSL, unknown validity, unknown key"


def test_dif_is_stable_across_renewals_and_lifetimes():
    def fingerprint(cert_hash, days):
        ssl = pd.DataFrame({"Domain": ["a.com"], "Hash": [cert_hash], "Validation Level": ["dv"], "Issuer": ["Let's Encrypt"],
                            "Duration": [days], "Public Key Bits": [256], "Public Key Algo": ["EC"], "Alt Names List": [["a.com"]]})
        return generate_digital_risk_profile(["a.com"], pd.DataFrame(), pd.DataFrame(), ssl, pd.DataFrame(), {}).iloc[0]
    renewed, short_lived = fingerprint("h1", 90), fingerprint("h2", 6)
    assert renewed["DIF Fingerprint"] == short_lived["DIF Fingerprint"]
    assert "90-day validity" in renewed["DIF Breakdown"] and "6-day validity" in short_lived["DIF Breakdown"]


def test_generated_fingerprints_decode_and_show_shared_dif():
    pdns = pd.DataFrame({"Domain": ["a.com", "b.com"], "Field": ["A", "A"], "Value": ["1.1.1.1", "1.1.1.1"]})
    ssl = pd.DataFrame({"Domain": ["a.com", "b.com"], "Hash": ["h1", "h1"], "Validation Level": ["dv", "dv"],
                        "Issuer": ["Let's Encrypt", "Let's Encrypt"], "Duration": [90, 90],
                        "Public Key Bits": [2048, 2048], "Public Key Algo": ["RSA", "RSA"]})
    profiles = generate_digital_risk_profile(["a.com", "b.com", "c.com"], pd.DataFrame(), pd.DataFrame(), ssl, pdns, {})
    decoded = decode_profiles(profiles).set_index("Domain")
    assert decoded.loc["a.com", "TLS"] == "Domain Validated, Let's Encrypt, RSA 2048-bit"
    assert decoded.loc["a.com", "Hosting"].startswith("Static host (1-2 IPs)")
    assert decoded.loc["a.com", "Same DIF As"] == "b.com" and decoded.loc["c.com", "Same DIF As"] == ""
    assert decoded.loc["c.com", "TLS"] == "No certificate"

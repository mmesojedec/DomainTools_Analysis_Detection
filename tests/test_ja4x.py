from types import SimpleNamespace

import pandas as pd

import core.persistence as persistence
from core import certsql, ja4x
from core.intel_data import DUAL_USE_JA4X, KNOWN_JA4X
from core.rule_catalog import RULE_CATALOG
from core.run_history import diff_artifacts
from core.threat_detection.ssl_rules import PER_CERT_RULES, rule_known_ja4x
from integrations.certificates import parse_domaintools_certs

COBALT = "2166164053c1_2166164053c1_30d204a01551"
SLIVER = "000000000000_4f24da86fad6_bf0f0589fc03"
SOFTETHER = "d55f458d5a6c_d55f458d5a6c_0fc8c171b6ae"
LETS_ENCRYPT = "a373a9f83c6b_7022c563de38_ad47b0d2c4bf"   # stands in for a common CA layout


class _Ctx:
    def __init__(self):
        self.alerts = []

    def add(self, threat_type, severity, mitre, logic, iocs, flag=None, confidence=None, evidence=None):
        self.alerts.append({"Threat Type": threat_type, "Severity": severity, "MITRE": mitre, "Logic": logic,
                            "IOCs": iocs, "Confidence": confidence})


def _info(self_signed=True):
    return {"cn": "Major Cobalt Strike", "issuer": "Major Cobalt Strike", "self_signed": self_signed}


def test_built_in_lists_are_valid_ja4x_values_and_documented():
    for value in [*KNOWN_JA4X, *DUAL_USE_JA4X]:
        assert ja4x.normalize(value) == value
    assert not set(KNOWN_JA4X) & set(DUAL_USE_JA4X)
    for name in ("Known C2 Certificate Fingerprint (JA4X)", "Dual-Use Tool Certificate Fingerprint (JA4X)"):
        assert name in RULE_CATALOG
    assert rule_known_ja4x in PER_CERT_RULES


def test_normalize_known_and_layout():
    assert ja4x.normalize(" 2166164053C1_2166164053c1_30d204a01551 ") == COBALT
    assert ja4x.normalize("abc") == "" and ja4x.normalize(None) == "" and ja4x.normalize(float("nan")) == ""
    assert ja4x.known_ja4x(COBALT) == ("Cobalt Strike (default certificate)", "c2")
    assert ja4x.known_ja4x(SOFTETHER) == ("SoftEther VPN", "dual-use")
    assert ja4x.known_ja4x(LETS_ENCRYPT) is None
    assert ja4x.layout_note(COBALT) == "issuer = subject layout"
    assert ja4x.layout_note(SLIVER) == "empty issuer"
    assert ja4x.layout_note("2bab15409345_af684594efb4_e3b0c44298fc") == "no extensions"
    assert ja4x.rarity(3) == "Rare" and ja4x.rarity(400) == "Uncommon" and ja4x.rarity(5000) == "Common (CA or platform default)"
    assert ja4x.rarity(10000, "gte").startswith("Common") and ja4x.rarity(None) == ""


def test_search_query_passes_the_certsql_check():
    query = certsql.normalize(ja4x.search_query(COBALT.upper()))
    assert query.endswith(f'ja4x equals "{COBALT}"') and certsql.problems(query) == []


def test_rule_raises_c2_and_dual_use_alerts_only_for_listed_values():
    ctx = _Ctx()
    rule_known_ja4x(ctx, pd.Series({"JA4X": COBALT, "Hash": "h1"}), _info())
    rule_known_ja4x(ctx, pd.Series({"JA4X": SOFTETHER, "Hash": "h2"}), _info(self_signed=False))
    rule_known_ja4x(ctx, pd.Series({"JA4X": LETS_ENCRYPT, "Hash": "h3"}), _info())
    rule_known_ja4x(ctx, pd.Series({"Hash": "h4"}), _info())   # certificates collected before the API had ja4x
    c2, dual = ctx.alerts
    assert len(ctx.alerts) == 2
    assert c2["Threat Type"] == "Known C2 Certificate Fingerprint (JA4X)" and c2["Severity"] == "High"
    assert c2["Confidence"] == "High" and "Cobalt Strike" in c2["Logic"] and COBALT in c2["IOCs"]
    assert dual["Threat Type"] == "Dual-Use Tool Certificate Fingerprint (JA4X)" and dual["Confidence"] is None


def test_certificates_carry_ja4x_into_the_summary_and_the_run_artifacts():
    hits = [{"sha256": "h1", "san_dns": ["a.com"], "ja4x": COBALT, "is_self_signed": True},
            {"sha256": "h2", "san_dns": ["b.com"], "ja4x": COBALT},
            {"sha256": "h3", "san_dns": ["b.com"], "ja4x": LETS_ENCRYPT, "issuer_common_name": "R11"},
            {"sha256": "h4", "san_dns": ["a.com"]}]
    ssl = parse_domaintools_certs(hits, ["a.com", "b.com"])
    assert list(ssl["JA4X"]) == [COBALT, COBALT, LETS_ENCRYPT, ""]
    summary = ja4x.summary(ssl)
    assert list(summary.columns) == ja4x.SUMMARY_COLUMNS
    first = summary.iloc[0]
    assert first["JA4X"] == COBALT and first["Known As"].startswith("Cobalt") and first["Domain Count"] == 2
    assert first["Domains"] == "a.com, b.com" and first["Self-signed"]
    assert summary.iloc[1]["Issuers"] == "R11" and len(summary) == 2
    assert ja4x.summary(ssl.drop(columns="JA4X")).empty and ja4x.summary(pd.DataFrame()).empty

    collected = SimpleNamespace(pdns=pd.DataFrame(), dh=pd.DataFrame(), enrichment={}, ssl=ssl, ssl_active=pd.DataFrame())
    artifacts = persistence.collect_run_artifacts(collected)
    assert artifacts["b.com"]["JA4X"] == sorted([COBALT, LETS_ENCRYPT]) and artifacts["a.com"]["JA4X"] == [COBALT]


def test_diff_shows_a_ja4x_change_but_not_against_snapshots_without_ja4x():
    before = {"a.com": {"Certificate": ["h1"], "JA4X": [LETS_ENCRYPT]}}
    after = {"a.com": {"Certificate": ["h2"], "JA4X": [COBALT]}}
    rows = diff_artifacts(before, after)
    assert set(zip(rows["Artifact"], rows["Value"], rows["Change"])) >= {("JA4X", COBALT, "Added"), ("JA4X", LETS_ENCRYPT, "Removed")}
    older = diff_artifacts({"a.com": {"Certificate": ["h1"]}}, after)
    assert "JA4X" not in set(older["Artifact"])

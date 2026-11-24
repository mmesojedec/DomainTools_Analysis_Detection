"""Certificate shape and families (core.cert_shape), anomalies (core.cert_anomalies) and their alerts."""
import pandas as pd

from core import cert_anomalies as ca
from core import cert_profile as cp
from core import cert_shape as shape
from core import certsql
from core.cert_anatomy import anatomy_html
from core.threat_detection.engine import detect_threat_flags

NOW = pd.Timestamp("2026-11-20")
EXTENSIONS = ["2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.35", "1.3.6.1.5.5.7.1.1", "2.5.29.17", "2.5.29.32"]
POISON, SCT_LIST = "1.3.6.1.4.1.11129.2.4.3", "1.3.6.1.4.1.11129.2.4.2"


def _cert(n=0, **fields):
    """A Let's Encrypt-like Certificate API record; `n` varies the hash, serial, names and issue minute."""
    start = NOW - pd.Timedelta(days=10) + pd.Timedelta(minutes=n * 37, seconds=13)
    base = {"Domain": f"site{n}.com", "Source": "DomainTools Cert API", "Hash": f"{n:064x}", "SHA1": f"{n:040x}",
            "Common Name": f"site{n}.com", "Issuer": "YE2", "Issuer Org": "Let's Encrypt",
            "Issuer DN": "cn=YE2,o=Let's Encrypt,c=US", "Subject DN": f"cn=site{n}.com",
            "Not Before": start, "Not After": start + pd.Timedelta(days=90), "Validation Level": "dv",
            "Public Key Algo": "ecdsa", "Public Key Bits": 256, "Public Key SHA256": f"k{n}",
            "Signature Algo": "ecdsa_with_sha384", "Serial Number": f"05{n:034x}"[:36],
            "Authority Key ID": "b959f28ecf22f086d33748ff761418ba82d85587",
            "Extension OIDs": EXTENSIONS + [SCT_LIST], "Extended Key Usage OIDs": ["1.3.6.1.5.5.7.3.1"],
            "Certificate Policy": [{"policy_oid": "2.23.140.1.2.1"}], "SAN DNS": [f"site{n}.com"], "SAN Count": 1,
            "Has Wildcard SAN": False, "Is Self Signed": False, "Is Precertificate": False, "Has Embedded SCTs": True,
            "Signed Certificate Timestamps": [
                {"version": 0, "log_id": "aa", "timestamp": (start + pd.Timedelta(hours=1)).isoformat() + "Z"},
                {"version": 0, "log_id": "bb", "timestamp": (start + pd.Timedelta(hours=1)).isoformat() + "Z"}]}
    return {**base, **fields}


def _certs(*rows):
    return cp.certificates(pd.DataFrame(list(rows)))


def _codes(frame, digest=None):
    rows = frame if digest is None else frame[frame["Hash"] == digest]
    return set(rows["Code"])


def test_precertificate_and_final_share_a_shape_and_serials_ignore_the_sign_byte():
    final = shape.traits(_cert())
    pre = shape.traits(_cert(**{"Extension OIDs": EXTENSIONS + [POISON], "Is Precertificate": True,
                                "Signed Certificate Timestamps": [], "Has Embedded SCTs": False}))
    assert shape.shape_id(final) == shape.shape_id(pre) and shape.shape_id(final).startswith("S-")
    assert shape.serial_bytes("009865ccc09bfb73a60be46866c83f75ba") == shape.serial_bytes(
        "44d4f057fc49d0360edb55579f2ea77f") == 16
    assert final["validity"] == "48–100 d" and shape.traits(_cert(**{"Not After": NOW - pd.Timedelta(days=4)}))["validity"] == "≤7 d"
    assert shape.shape_label(final) == "YE2 · ecdsa 256 · 48–100 d · 7 ext + CT · 1 name"


def test_sparse_records_get_no_shape_and_are_never_compared():
    sparse = {"Hash": "d" * 40, "Issuer": "YE2", "Common Name": "a.com", "Alt Names List": "['a.com']",
              "Not Before": "2026-11-13 00:00:00", "Not After": "2027-02-11 00:00:00", "Is Self Signed": "False",
              "Source": "Domain History"}
    found = shape.traits(sparse)
    assert shape.shape_id(found) is None
    assert shape.similarity(found, shape.traits(dict(sparse, Hash="e" * 40))) == (None, [])


def test_families_near_shapes_and_the_certsql_query():
    rows = [_cert(n) for n in range(4)] + [_cert(9, **{"Not After": NOW - pd.Timedelta(days=4)})]
    certs = _certs(*rows)
    families = shape.families(certs)
    assert list(families["Certificates"]) == [4, 1] and families["Domain count"].iloc[0] == 4
    same = shape.shape_relations(rows[0], certs)
    assert list(same["Relation"]).count("Same shape") == 3
    odd = next(r for r in certs.to_dict("records") if r["Hash"] == rows[-1]["Hash"])
    near = shape.shape_relations(odd, certs)
    assert len(near) == 4 and near["Relation"].iloc[0].startswith("Near shape (")
    assert "validity" in near["Relation"].iloc[0]
    query = shape.shape_query(rows[0], today=NOW)
    assert certsql.problems(query) == [] and 'issuer_common_name equals "YE2"' in query
    assert "validity_duration_days between [48, 100]" in query


def test_domain_history_copies_of_a_certificate_are_merged_by_their_sha1():
    api = _cert(1)
    history = {"Domain": "other.com", "Hash": api["SHA1"], "Issuer": "YE2", "Source": "Domain History",
               "Not Before": "20261110", "Not After": "20270208"}
    merged = shape.distinct(_certs(api, history))
    assert len(merged) == 1 and merged.iloc[0]["Domains"] == ["other.com", "site1.com"]


def test_issuer_baseline_finds_a_foreign_signing_key_and_an_odd_key():
    rows = [_cert(n) for n in range(6)]
    rows.append(_cert(7, **{"Authority Key ID": "ffff" * 10}))
    rows.append(_cert(8, **{"Public Key Algo": "rsa", "Public Key Bits": 1024}))
    rows += [_cert(n) for n in range(10, 14)]
    found = ca.anomalies(_certs(*rows), now=NOW)
    assert _codes(found, rows[6]["Hash"]) == {"issuer_aki"}
    assert found[found["Code"] == "issuer_aki"]["Severity"].iloc[0] == "High"
    assert "issuer_key" in _codes(found, rows[7]["Hash"])
    assert not _codes(found, rows[0]["Hash"])
    run = ca.Run(_certs(*rows))
    against = ca.against_issuer(rows[6], run).set_index("Trait")
    assert against.loc["Signing key (AKI)", "Verdict"] == "rare"
    assert against.loc["Key (48–100 d profile)", "Verdict"] == "usual"
    small = ca.against_issuer(rows[0], ca.Run(_certs(*rows[:2])))
    assert set(small["Verdict"]) <= {"too few", "usual"}


def test_known_issuer_norms_and_dv_with_an_organization():
    short = [_cert(n, **{"Not After": NOW - pd.Timedelta(days=4)}) for n in range(8)]
    long_ = _cert(20)                                    # Let's Encrypt issues 90-day and 6-day certificates
    too_long = _cert(21, **{"Not After": NOW + pd.Timedelta(days=360)})
    org = _cert(22, **{"Subject Org": "PayPal Inc"})
    ev = _cert(23, **{"Certificate Policy": [{"policy_oid": "2.23.140.1.1"}]})
    found = ca.anomalies(_certs(*short, long_, too_long, org, ev), now=NOW)
    assert not _codes(found, long_["Hash"])
    assert "issuer_norm_days" in _codes(found, too_long["Hash"])
    assert "dv_subject_org" in _codes(found, org["Hash"])
    assert "issuer_norm_level" in _codes(found, ev["Hash"])


def test_certificate_transparency_checks():
    late = _cert(1, **{"Signed Certificate Timestamps": [
        {"log_id": "aa", "timestamp": "2026-11-15T00:00:00Z"}, {"log_id": "bb", "timestamp": "2026-11-15T00:00:00Z"}]})
    one_log = _cert(2, **{"Signed Certificate Timestamps": [{"log_id": "aa", "timestamp": "2026-11-10T02:00:00Z"}]})
    orphan = _cert(3, **{"Is Precertificate": True, "Signed Certificate Timestamps": [], "Has Embedded SCTs": False,
                         "Extension OIDs": EXTENSIONS + [POISON]})
    never = _cert(4, **{"Signed Certificate Timestamps": [], "Has Embedded SCTs": False,
                        "Extension OIDs": EXTENSIONS})
    pre = _cert(5, **{"Hash": "p" * 64, "Is Precertificate": True, "Signed Certificate Timestamps": [],
                      "Has Embedded SCTs": False, "Extension OIDs": EXTENSIONS + [POISON]})
    final = _cert(5)                                     # pairs with `pre`: same issuer and serial
    logged_late = _cert(6, **{"Signed Certificate Timestamps": [], "Has Embedded SCTs": False})
    ctl = pd.DataFrame([{"Hash": logged_late["Hash"], "Log Host": "log.example", "Timestamp": "2026-11-18T00:00:00"}])
    found = ca.anomalies(_certs(late, one_log, orphan, never, pre, final, logged_late), ctl=ctl, now=NOW)
    assert "ct_late" in _codes(found, late["Hash"])
    assert "sct_count" in _codes(found, one_log["Hash"])
    assert "ct_orphan_pre" in _codes(found, orphan["Hash"])
    assert "ct_never" in _codes(found, never["Hash"])
    assert not _codes(found, pre["Hash"]) and not _codes(found, final["Hash"])
    assert "ct_late" in _codes(found, logged_late["Hash"])
    assert "ct_never" not in _codes(found, logged_late["Hash"])


def test_bursts_round_times_tool_validity_and_name_templates():
    burst = [_cert(n, **{"Not Before": NOW + pd.Timedelta(minutes=n, seconds=7),
                         "Not After": NOW + pd.Timedelta(days=90)}) for n in range(5)]
    round_time = [_cert(n) for n in range(10, 16)] + [_cert(16, **{"Not Before": NOW - pd.Timedelta(days=3)})]
    tool = _cert(30, **{"Issuer": "My CA", "Issuer Org": "", "Is Self Signed": True, "Has Embedded SCTs": False,
                        "Validation Level": "", "Certificate Policy": [], "Not Before": NOW,
                        "Not After": NOW + pd.Timedelta(days=365)})
    template = [_cert(40 + n, **{"SAN DNS": [f"login{n}{n}x7.cdn.net", f"mailbx{n}{n}{n}9.cdn.net"]})
                for n in range(3)]
    found = ca.anomalies(_certs(*burst, *round_time, tool, *template), now=NOW)
    assert all("burst" in _codes(found, c["Hash"]) for c in burst)
    assert "issuer_round" in _codes(found, round_time[-1]["Hash"])
    assert "tool_days" in _codes(found, tool["Hash"])
    finding = found[(found["Hash"] == template[0]["Hash"]) & (found["Code"] == "name_template")]["Finding"].iloc[0]
    assert "template" in finding


def test_profile_combines_flags_anomalies_shape_and_the_anatomy_strip():
    rows = [_cert(n) for n in range(6)] + [_cert(7, **{"Authority Key ID": "ffff" * 10})]
    certs = _certs(*rows)
    parts = ca.profile(rows[6], certs)
    assert {"Certificate", "Issuer baseline"} >= set(parts["found"]["Check"]) and "Issuer baseline" in set(
        parts["found"]["Check"])
    assert parts["family"]["id"] and len(parts["family"]["members"]) == 7
    assert "Same shape" in set(parts["related"]["Relation"])
    page = anatomy_html(rows[6], parts["found"], family=parts["family"], against=parts["against"], now=NOW)
    assert "Shape and issuer baseline" in page and parts["family"]["id"] in page and "rare" in page


def test_alerts_for_a_foreign_signing_key_and_too_few_scts():
    rows = [_cert(n, Domain="a.com") for n in range(6)]
    rows.append(_cert(7, Domain="a.com", **{"Authority Key ID": "ffff" * 10}))
    rows.append(_cert(8, Domain="b.com", **{"Signed Certificate Timestamps": [
        {"log_id": "aa", "timestamp": "2026-11-10T02:00:00Z"}]}))
    result = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=pd.DataFrame(rows))
    alerts = result.alerts
    a = set(alerts.loc[alerts["Domain"] == "a.com", "Threat Type"])
    b = set(alerts.loc[alerts["Domain"] == "b.com", "Threat Type"])
    assert "Issuer Key Mismatch (Impersonated CA)" in a and "Insufficient SCTs (CT Policy)" in b
    late = detect_threat_flags(pd.DataFrame(), {"risk_score": 0}, ssl_df=pd.DataFrame([_cert(
        1, Domain="c.com", **{"Signed Certificate Timestamps": [], "Has Embedded SCTs": False})]),
        ct_logs=pd.DataFrame([{"Hash": f"{1:064x}", "Timestamp": "2026-11-18T00:00:00"}]))
    assert "Backdated Certificate" in set(late.alerts["Threat Type"])

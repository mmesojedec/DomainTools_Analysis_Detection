"""
Certificate anomalies across the run (core.cert_anomalies) that are strong enough to alert on: a foreign signing key
under an issuer's name, logging long after Not Before, and fewer SCTs than the CT policy asks. The other anomalies
(unusual traits for the issuer, bursts, round times, name templates ...) stay as context on the Certificate profile and
the Certificates page's Families & anomalies tab.
"""
import pandas as pd

from core.cert_anomalies import cached_run
from core.cert_profile import _values, certificates
from core.threat_detection.ssl_rules import cert_evidence

ALERTING = ("issuer_aki", "ct_late", "sct_count")


def _iocs(cert):
    return (f"Common Name: {cert.get('Common Name') or 'N/A'}\nIssuer: {cert.get('Issuer') or 'N/A'}\n"
            f"Authority Key ID: {cert.get('Authority Key ID') or 'N/A'}\nNot Before: {cert.get('Not Before')}\n"
            f"Cert Hash: {cert.get('Hash')}")


def _alert(ctx, code, cert, finding):
    evidence = [cert_evidence(pd.Series(cert))]
    if code == "issuer_aki":
        ctx.add("Issuer Key Mismatch (Impersonated CA)", "High", "T1587.003 (Develop Capabilities: Digital Certificates)",
                finding + ".", _iocs(cert), confidence="Medium", evidence=evidence)
    elif code == "ct_late":
        ctx.add("Backdated Certificate", "Medium", "T1588.004 (Obtain Digital Certificates)",
                finding + ".", _iocs(cert), flag="backdated_cert", evidence=evidence)
    elif code == "sct_count":
        ctx.add("Insufficient SCTs (CT Policy)", "Medium", "T1588.004 (Obtain Digital Certificates)",
                finding + ".", _iocs(cert), evidence=evidence)


def certificate_anomaly_alerts(contexts, ssl_df, ct_logs=None):
    """Alerts of the run's certificate anomalies in ALERTING, on each analyzed domain the certificate is listed for."""
    if not contexts or ssl_df is None or ssl_df.empty or "Hash" not in ssl_df.columns:
        return
    certs = certificates(ssl_df)
    run = cached_run(certs, ct_logs)
    found = run.anomalies()
    if found.empty:
        return
    for row in found[found["Code"].isin(ALERTING)].to_dict("records"):
        cert = run.by_hash.get(row["Hash"])
        for domain in _values(cert.get("Domains")) if cert else []:
            if domain in contexts:
                _alert(contexts[domain], row["Code"], cert, row["Finding"])

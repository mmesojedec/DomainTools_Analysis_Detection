"""SSL/TLS certificate detection rules (per-certificate and per-domain)."""

import pandas as pd

from core.caa import cert_is_wildcard, is_issuer_authorized_by_caa
from core.cert_utils import (
    cert_alt_names,
    cert_duration_days,
    cert_flag,
    cert_ip_names,
    cert_is_self_signed,
    is_weak_public_key,
    publicly_trusted,
)
from core.helpers import hostname_matches, is_ip_address, registrable_domain
from core.ja4x import cert_ja4x, known_ja4x, layout_note
from core.network_intel import explode_ip_events
from core.self_signed import assess as assess_self_signed
from core.threat_detection.context import by_host, evidence_record, fmt_ts

SHA1_SUNSET = pd.Timestamp("2017-01-01")
BACKDATE_HOURS = 48          # Not Before this much earlier than the first CT log timestamp: backdated
STAGING_MIN_HOURS = 24       # certificate issued at least this long before its hostname first resolved ...
STAGING_MAX_DAYS = 30        # ... and at most this long: prepared in advance, not an old certificate
TINY_SERIAL_HEX = 4          # serial numbers of 2 bytes or less are made by tools, never by public CAs (16+ bytes)
DEFAULT_SUBJECT_MARKERS = ("internet widgits", "some-state", "default company", "acme co", "my company")     # public CAs stopped issuing SHA-1 certificates by then
# Issuer / CN fragments of certificates that bundle unrelated customers by design (CDN SNI, shared hosting)
SHARED_HOSTING_CERT_MARKERS = ("cloudflare", "sni.cloudflaressl", "cpanel", "incapsula", "imperva", "fastly", "akamai")
CABF_VALIDITY_CUTOFF = pd.Timestamp("2020-09-01")
# CA/B Forum maximum validity by issuance date (ballot SC-081 from 2026); newest first
CABF_VALIDITY_LIMITS = (
    (pd.Timestamp("2029-03-15"), 47),
    (pd.Timestamp("2027-03-15"), 100),
    (pd.Timestamp("2026-03-15"), 200),
    (CABF_VALIDITY_CUTOFF, 398),
)
EARLY_REPLACEMENT_REMAINING = 0.5            # previous certificate still had more than this share of its validity left
PARALLEL_ISSUANCE = pd.Timedelta(days=1)    # certificates issued this close together are parallel, not replacements


def cabf_max_validity(issued):
    """Maximum validity in days for a publicly trusted certificate issued at `issued` (None before 2020-09-01)."""
    if pd.isna(issued):
        return CABF_VALIDITY_LIMITS[-1][1]
    return next((days for start, days in CABF_VALIDITY_LIMITS if issued >= start), None)


def _cert_date(cert, *keys):
    for key in keys:
        value = pd.to_datetime(cert.get(key), errors="coerce", utc=True)
        if pd.notna(value):
            return value.tz_localize(None)
    return pd.NaT


def cert_evidence(cert, info=None):
    """Evidence record for one certificate: issuance time, CN / issuer, and the hash as the pivot artifact."""
    info = info or {}
    cn = info.get("cn", str(cert.get("Common Name") or "").strip())
    issuer = info.get("issuer", str(cert.get("Issuer") or "").strip())
    issued = info.get("not_before", _cert_date(cert, "Not Before Date", "Not Before"))
    hash_value = cert.get("Hash")
    return evidence_record(issued, "Certificate", f"CN={cn or 'N/A'} | Issuer={issuer or 'N/A'}",
                           artifact=str(hash_value) if pd.notna(hash_value) and str(hash_value).strip() else None)


# ---------------------------------------------------------------------------
# Domain-level pre-pass (must run before per-cert compound rules)
# ---------------------------------------------------------------------------

def first_resolution(ctx):
    """{hostname: first time it resolved to an address} from the domain's A / AAAA events (each host apart)."""
    if ctx.events.empty:
        return {}
    ip_rows = explode_ip_events(ctx.events)
    return {host: rows["Date"].min() for host, rows in by_host(ip_rows, ctx.domain) if pd.notna(rows["Date"].min())}


def _cert_hosts(cert, ctx):
    """The certificate's hostnames under the domain (wildcards as their parent name), the domain itself first."""
    names = [str(n).lower().rstrip(".").removeprefix("*.") for n in cert_alt_names(cert)]
    names = [n for n in dict.fromkeys(names) if n == ctx.domain or n.endswith("." + ctx.domain)]
    return names or [ctx.domain]


def rule_rapid_weaponization(ctx, certs, first_seen):
    """A certificate issued within `gap_hours` of the first resolution of a hostname it names (each host apart)."""
    if not first_seen:
        return
    gap_limit = float(ctx.thresholds["gap_hours"])
    best = None
    for _, cert in certs.iterrows():
        issued = _cert_date(cert, "Not Before Date", "Not Before")
        if pd.isna(issued):
            continue
        for host in _cert_hosts(cert, ctx):
            first_dns = first_seen.get(host)
            if first_dns is None:
                continue
            signed_gap = (issued - first_dns).total_seconds() / 3600
            if abs(signed_gap) <= gap_limit and (best is None or abs(signed_gap) < best[0]):
                best = (abs(signed_gap), cert, signed_gap, issued, host, first_dns)
    if best is None:
        return
    _, cert, signed_gap, issued, host, first_dns = best
    order = "after" if signed_gap >= 0 else "before"
    ctx.add(
        "Rapid Weaponization (Cert-to-DNS Gap)", "High", "T1588.004 (Obtain Digital Certificates)",
        f"SSL cert issued {abs(signed_gap) * 60:.0f} mins {order} {host} first resolved.",
        f"Hostname: {host}\nCert Issued: {fmt_ts(issued)}\nFirst Resolution: {fmt_ts(first_dns)}\n"
        f"Cert Hash: {str(cert.get('Hash'))[:16]}...",
        flag="rapid_weaponization",
        evidence=[cert_evidence(cert), evidence_record(first_dns, "First Resolution", host)],
    )


def rule_certificate_staging(ctx, certs, first_seen):
    """A certificate issued 1-30 days before the hostname it names first resolved: infrastructure prepared ahead."""
    if not first_seen:
        return
    for _, cert in certs.iterrows():
        issued = _cert_date(cert, "Not Before Date", "Not Before")
        if pd.isna(issued) or cert_flag(cert, "Is Precertificate") is True:
            continue
        for host in _cert_hosts(cert, ctx):
            first_dns = first_seen.get(host)
            if first_dns is None:
                continue
            lead = (first_dns - issued).total_seconds() / 3600
            if STAGING_MIN_HOURS <= lead <= STAGING_MAX_DAYS * 24:
                ctx.add(
                    "Certificate Staged Before DNS", "Medium", "T1608.003 (Stage Capabilities: Install Digital Certificate)",
                    f"Certificate for {host} issued {lead / 24:.1f} days before the hostname first resolved: the "
                    "infrastructure was prepared before it went live.",
                    f"Hostname: {host}\nCert Issued: {fmt_ts(issued)}\nFirst Resolution: {fmt_ts(first_dns)}\n"
                    f"Cert Hash: {cert.get('Hash')}",
                    flag="cert_staging",
                    evidence=[cert_evidence(cert), evidence_record(first_dns, "First Resolution", host)],
                )
                return


# ---------------------------------------------------------------------------
# Per-certificate rules: signature rule(ctx, cert, info) where info carries derived values
# ---------------------------------------------------------------------------

def rule_self_signed(ctx, cert, info):
    """Graded like the Certificates page (core.self_signed.assess): a C2 framework's default is Critical, an expired
    lab certificate Low."""
    if info["self_signed"]:
        sources = set(ctx.ssl.loc[ctx.ssl["Hash"] == cert.get("Hash"), "Source"].astype(str)) \
            if {"Hash", "Source"} <= set(ctx.ssl.columns) else set()
        severity, reasons, _ = assess_self_signed(cert, [ctx.domain], sources, ctx.now)
        ctx.add(
            "Self-Signed Certificate Detected", severity, "T1573.002 (Encrypted Channel)",
            "Domain utilizes a self-signed certificate (Subject matches Issuer): " + "; ".join(reasons[:2]) + ".",
            f"Common Name: {info['cn'] or 'N/A'}\nIssuer: {info['issuer'] or 'N/A'}\nCert Hash: {cert.get('Hash', 'N/A')}"
            + "".join(f"\n- {reason}" for reason in reasons),
            confidence="High" if severity == "Critical" else None,
        )


def rule_backdated(ctx, cert, info):
    """Not Before far earlier than the certificate's first CT log timestamp (embedded SCTs)."""
    scts = cert.get("Signed Certificate Timestamps")
    if not isinstance(scts, list) or not scts or pd.isna(info["not_before"]):
        return
    stamps = [pd.to_datetime(s.get("timestamp"), errors="coerce", utc=True) for s in scts if isinstance(s, dict)]
    stamps = [t.tz_localize(None) for t in stamps if pd.notna(t)]
    if not stamps:
        return
    logged = min(stamps)
    hours = (logged - info["not_before"]).total_seconds() / 3600
    if hours > BACKDATE_HOURS:
        ctx.add(
            "Backdated Certificate", "Medium", "T1588.004 (Obtain Digital Certificates)",
            f"Certificate claims validity from {fmt_ts(info['not_before'])}, {hours / 24:.1f} days before it was first "
            "logged in CT: backdating hides when it was really made (CAs backdate by an hour at most).",
            f"Not Before: {fmt_ts(info['not_before'])}\nFirst SCT: {fmt_ts(logged)}\nCert Hash: {cert.get('Hash')}",
            flag="backdated_cert",
        )


def rule_unusual_fields(ctx, cert, info):
    """CA-issued certificate fields that tools set and CAs never do: tiny serial, no serverAuth, default subject."""
    if info["self_signed"]:
        return   # graded by the self-signed rule
    reasons = []
    serial = str(cert.get("Serial Number") or "").strip().lower().removeprefix("0x").replace(":", "").lstrip("0")
    if cert.get("Serial Number") not in (None, "") and len(serial) <= TINY_SERIAL_HEX:
        reasons.append(f"serial number {cert.get('Serial Number')!s} (public CAs use 16+ random bytes)")
    eku = [str(e).lower() for e in (cert.get("Extended Key Usage") or []) if str(e).strip()] \
        if isinstance(cert.get("Extended Key Usage"), list) else []
    if eku and not any("server" in e for e in eku):
        reasons.append(f"no server authentication usage ({', '.join(eku[:3])}) on a certificate naming a website")
    subject = " ".join(str(cert.get(k) or "") for k in ("Subject DN", "Subject Org")).lower()
    marker = next((m for m in DEFAULT_SUBJECT_MARKERS if m in subject), None)
    if marker:
        reasons.append(f"default subject '{marker}' (filled in by OpenSSL or a tool, not a person)")
    if reasons:
        ctx.add(
            "Unusual Certificate Fields", "Medium", "T1587.003 (Develop Capabilities: Digital Certificates)",
            "Certificate has fields that certificate tools set and public CAs never do: " + "; ".join(reasons) + ".",
            f"Issuer: {info['issuer'] or 'N/A'}\nCert Hash: {cert.get('Hash')}\n" + "\n".join(f"- {r}" for r in reasons),
        )


def rule_short_lived(ctx, cert, info):
    """Informational: short lifetimes are normal for automated renewal, so this is excluded from risk scores and DIF."""
    duration = info["duration"]
    if duration is None or duration > ctx.thresholds["short_lived_days"]:
        return
    ctx.add(
        "Short-Lived Certificate", "Low", "T1588.004 (Obtain Digital Certificates)",
        f"Certificate is valid for {duration:g} days (threshold <= {int(ctx.thresholds['short_lived_days'])}). Short lifetimes, such as "
        "Let's Encrypt's 6-day profile, are normal for automated renewal; informational only, not used in risk scores or DIF.",
        f"Issuer: {info['issuer'] or 'N/A'}\nDuration: {duration:g} days\nCommon Name: {info['cn'] or 'N/A'}\nHash: {cert.get('Hash', 'N/A')}",
    )


def rule_mega_san(ctx, cert, info):
    roots = {registrable_domain(name) for name in info["sans"] if not is_ip_address(name)}
    roots.discard("")
    threshold = ctx.thresholds["ssl_san"]
    if len(roots) >= threshold:
        # CDN and hosting platforms bundle unrelated customers on purpose (Cloudflare SNI, cPanel, ...): context only
        shared_host = any(marker in str(info["issuer"]).lower() or marker in str(info["cn"]).lower()
                          for marker in SHARED_HOSTING_CERT_MARKERS)
        ctx.add(
            "Mega-SAN Cluster (Bulk Infrastructure)", "High", "T1583.001 (Acquire Infrastructure)",
            f"Certificate bundles {len(roots)} registrable domains (threshold >= {int(threshold)}).",
            f"Cert Hash: {str(cert.get('Hash'))[:12]}...\nRoot Domains: {', '.join(sorted(roots)[:5])}{'...' if len(roots) > 5 else ''}",
            confidence="Low" if shared_host else None,
        )


def rule_bare_ip_certificate(ctx, cert, info):
    ip_names = info["ip_names"]
    if not ip_names:
        return
    if ctx.is_ip:
        # Certificates found by pivoting on an IP contain that IP by construction; only flag extra IPs
        other_ips = [ip for ip in ip_names if ip != ctx.domain]
        if not other_ips:
            return
        ctx.add(
            "Multi-IP Certificate (Shared C2 / Proxy Cluster)", "High", "T1008 (Fallback Channels)",
            "Certificate issued to this IP also covers other raw IP addresses.",
            f"Target IP: {ctx.domain}\nOther IPs: {', '.join(other_ips)}\nHash: {cert.get('Hash', 'N/A')}",
        )
        return
    # Public CAs now issue short-lived IP certificates (e.g. Let's Encrypt), so those are a weaker signal
    public_short_lived = info["public_trust"] is True and info["duration"] is not None \
        and info["duration"] <= ctx.thresholds["short_lived_days"]
    severity = "Medium-High" if public_short_lived else "Critical"
    note = (" Issued by a public CA as a short-lived IP certificate, which public CAs now offer, so confidence is low."
            if public_short_lived else "")
    ctx.add(
        "Bare-IP Certificate (C2 / Proxy Node)", severity, "T1008 (Fallback Channels)",
        f"Certificate Common Name or SAN contains a raw IP address (IPv4 or IPv6).{note}",
        f"Common Name: {info['cn'] or 'N/A'}\nIP Names: {', '.join(ip_names)}\nIssuer: {info['issuer'] or 'N/A'}\n"
        f"Hash: {cert.get('Hash', 'N/A')}",
        confidence="Low" if public_short_lived else None,
    )


def rule_cn_mismatch(ctx, cert, info):
    cn = info["cn"]
    if ctx.is_ip or not cn or is_ip_address(cn):
        return
    if hostname_matches(ctx.domain, cn) or any(hostname_matches(ctx.domain, s) for s in info["sans"]):
        return
    ctx.add(
        "SSL Common Name (CN) Mismatch", "Medium-High", "T1071.001 (Web Protocols / Shared C2)",
        f"Serving certificate issued to a different entity ({cn}).",
        f"Target Domain: {ctx.domain}\nCertificate CN: {cn}",
    )


def rule_precertificate(ctx, cert, info):
    if cert_flag(cert, "Is Precertificate") is True:
        ctx.add(
            "Pre-Certificate Staging (CT Log Only)", "Low", "T1588.004 (Obtain Digital Certificates)",
            "Certificate observed in CT logs before active deployment (is_precertificate = true).",
            f"Hash: {cert.get('Hash')}\nIssuer: {info['issuer']}",
        )


def rule_missing_scts(ctx, cert, info):
    # Only a certificate with other evidence of a public CA (policy OID, validation level, known issuer) is expected
    # to embed SCTs; a precertificate never carries them, and private CAs are covered by Non-Public CA
    if cert_flag(cert, "Has Embedded SCTs") is False and info["public_trust"] is True \
            and cert_flag(cert, "Is Precertificate") is not True:
        ctx.add(
            "CT Log Evasion / Missing SCTs", "Medium-High", "T1588.004 (Obtain Capabilities: Digital Certificates)",
            "Publicly trusted certificate lacks embedded Signed Certificate Timestamps (SCT evasion/proxy appliance).",
            f"Issuer: {info['issuer']}\nHas SCTs: False",
        )


def rule_rogue_ca(ctx, cert, info):
    constraints = cert.get("Basic Constraints")
    if isinstance(constraints, dict) and constraints.get("is_ca") is True and not info["self_signed"]:
        ctx.add(
            "Rogue Certificate Authority", "Critical", "T1553.004 (Subvert Trust Controls: Install Root Certificate)",
            "Target endpoint is serving a certificate possessing CA signing capabilities.",
            f"Basic Constraints: CA=True\nIssuer: {info['issuer']}",
        )


def rule_validity_window(ctx, cert, info):
    """Validity above the CA/B Forum limit in force on the issue date (publicly trusted certificates only)."""
    duration = info["duration"]
    issued = info["not_before"]
    max_days = cabf_max_validity(issued)
    if duration is None or max_days is None or duration <= max_days or info["public_trust"] is False:
        return
    when = f"issued {fmt_ts(issued, '%Y-%m-%d')}" if pd.notna(issued) else "with an unknown issue date"
    ctx.add(
        "Non-Compliant Validity Window", "Medium", "T1588.004 (Obtain Digital Certificates)",
        f"Certificate duration ({int(duration)} days) exceeds the CA/B Forum limit of {max_days} days for certificates {when}.",
        f"Duration: {int(duration)} days\nNot Before: {fmt_ts(issued, '%Y-%m-%d')}\nNot After: {cert.get('Not After')}",
    )


def rule_deprecated_signature(ctx, cert, info):
    sig_algo = str(cert.get("Signature Algo") or "").lower()
    if "md5" in sig_algo or "sha1" in sig_algo:
        # public CAs stopped SHA-1 in 2016: an older certificate is history, a newer one was made outside the rules
        issued = info["not_before"]
        historic = pd.notna(issued) and issued < SHA1_SUNSET
        ctx.add(
            "Deprecated Signature Algorithm", "Medium" if historic else "High", "T1588 (Obtain Capabilities)",
            f"Certificate signed using deprecated cryptographic hash algorithm ({sig_algo}).",
            f"Signature Algorithm: {cert.get('Signature Algo')}\nNot Before: {fmt_ts(issued, '%Y-%m-%d')}",
            confidence="Low" if historic else None,
        )


def rule_non_public_ca(ctx, cert, info):
    """Certificate naming the domain from a CA with explicit signs of not being publicly trusted (not self-signed)."""
    if info["self_signed"] or info["public_trust"] is not False:
        return
    ctx.add(
        "Non-Public / Private CA Certificate", "Medium", "T1588.004 (Obtain Digital Certificates)",
        f"Certificate for this name was issued by a CA that does not appear publicly trusted ({info['issuer'] or 'Unknown'}): "
        "no embedded SCTs, no CA/B Forum policy, and an unrecognized issuer. Browsers would not trust it; typical of internal "
        "CAs, interception proxies, or attacker-run infrastructure. CAA policies do not apply to such CAs.",
        f"Issuer: {info['issuer'] or 'N/A'}\nIssuer DN: {cert.get('Issuer DN') or 'N/A'}\nCommon Name: {info['cn'] or 'N/A'}\n"
        f"Cert Hash: {cert.get('Hash', 'N/A')}",
    )


def rule_caa_policy(ctx, cert, info):
    """CAA only binds publicly trusted CAs: breaches require public trust; unverified issuers get a low-confidence mismatch."""
    policy = ctx.caa_policy
    if not policy.has_policy or info["self_signed"]:
        return
    is_auth, reason, _ = is_issuer_authorized_by_caa(cert, policy)
    if is_auth or info["public_trust"] is False:
        return
    if info["public_trust"] is None:
        ctx.add(
            "CAA Mismatch (CA Trust Unverified)", "Medium", "T1588.004 (Obtain Digital Certificates)",
            f"Issuer ({info['issuer'] or 'Unknown'}) is not authorized by the domain's CAA policy, but the source does not show whether "
            "the CA is publicly trusted, so this cannot be confirmed as a CAA breach.",
            f"Issuer: {info['issuer'] or 'N/A'}\nSource: {cert.get('Source', 'N/A')}\nCert Hash: {cert.get('Hash', 'N/A')}\nPolicy Detail: {reason}",
        )
        return
    if "Wildcard" in reason:
        ctx.add(
            "Wildcard Issuance Forbidden by CAA Policy", "Critical", "T1588.004 (Obtain Digital Certificates)",
            "Certificate covers wildcard names while the domain's CAA policy prohibits wildcard issuance.",
            f"Common Name: {info['cn'] or 'N/A'}\nHash: {cert.get('Hash', 'N/A')}\nPolicy Reason: {reason}",
        )
    else:
        allowed = sorted(policy.auth_issue | policy.auth_wild) or ["none (issuance prohibited)"]
        ctx.add(
            "Unauthorized CA Certificate Issuance (CAA Breach)", "Critical", "T1588.004 (Obtain Digital Certificates)",
            f"Certificate was provisioned by an unauthorized Certificate Authority ({info['issuer'] or 'Unknown'}) in violation of the domain's CAA policy.",
            f"Issuer: {info['issuer'] or 'N/A'}\nAuthorized CAs: {', '.join(allowed)}\nCert Hash: {cert.get('Hash', 'N/A')}\nViolation Detail: {reason}",
        )

    # CAA stripping: unauthorized cert issued shortly after the CAA record was last observed
    issued = info["not_before"]
    caa_last_seen = info["caa_last_seen"]
    if pd.notna(issued) and pd.notna(caa_last_seen) and issued > caa_last_seen:
        days_gap = (issued - caa_last_seen).total_seconds() / 86400.0
        if 0 < days_gap <= 90:
            ctx.add(
                "Suspicious CAA Stripping / Evasion", "High", "T1562.001 (Disable or Modify Tools)",
                f"Certificate issued {int(days_gap)} days after historical CAA protection records lapsed or were withdrawn from DNS.",
                f"Cert Issued: {fmt_ts(issued, '%Y-%m-%d')}\nLast Observed CAA: {fmt_ts(caa_last_seen, '%Y-%m-%d')}\nGap: {int(days_gap)} days",
            )


def _san_count(cert, info):
    san_count = pd.to_numeric(cert.get("SAN Count"), errors="coerce")
    return len(info["sans"]) if pd.isna(san_count) else san_count


def rule_wildcard_sprawl(ctx, cert, info):
    san_count = _san_count(cert, info)
    if info["wildcard"] and san_count >= 5:
        ctx.add(
            "Wildcard Infrastructure Sprawl", "Medium", "T1584.001 (Compromise Infrastructure: Domains)",
            f"Wildcard SAN bundling {int(san_count)} alternative names.",
            f"Wildcard Active: True\nSAN Count: {int(san_count)}\nIssuer: {info['issuer']}",
        )


def rule_wildcard_observed(ctx, cert, info):
    """Low-severity observation for wildcard certificates below the sprawl threshold (which raises its own alert)."""
    san_count = _san_count(cert, info)
    if info["wildcard"] and san_count < 5:
        wildcard_names = [s for s in info["sans"] if s.startswith("*.")] or [info["cn"]]
        ctx.add(
            "Wildcard Certificate Observed", "Low", "T1588.004 (Obtain Digital Certificates)",
            "Wildcard certificate covers any subdomain without per-host issuance, so new hostnames never appear in CT logs. "
            "Common for legitimate hosting; worth noting when subdomains rotate for phishing or C2.",
            f"Wildcard Names: {', '.join(wildcard_names)}\nSAN Count: {int(san_count)}\nIssuer: {info['issuer'] or 'N/A'}\n"
            f"Hash: {cert.get('Hash')}",
        )


def rule_suspicious_dv(ctx, cert, info):
    if str(cert.get("Validation Level") or "").lower() == "dv" and ctx.risk_known \
            and ctx.numeric_risk > ctx.thresholds["dv_risk_score"]:
        ctx.add(
            "Suspicious Domain Validation (DV)", "Medium", "T1588.004 (Obtain Digital Certificates)",
            f"High-risk domain (Score: {ctx.numeric_risk}) provisioned basic DV cert.",
            f"Validation Level: DV\nCommon Name: {info['cn'] or 'N/A'}",
        )


def rule_weak_key(ctx, cert, info):
    bits = cert.get("Public Key Bits")
    algo = cert.get("Public Key Algo")
    if is_weak_public_key(bits, algo):
        ctx.add(
            "Weak Cryptographic Key Material", "High", "T1588 (Obtain Capabilities)",
            f"Public key size ({int(float(bits))}-bit {algo or 'RSA'}) is below current minimums (RSA 2048 / EC 224).",
            f"Public Key Bits: {int(float(bits))}\nAlgorithm: {algo or 'N/A'}\nHash: {cert.get('Hash')}",
        )


def rule_known_ja4x(ctx, cert, info):
    """The certificate's JA4X is a known C2 / malware or dual-use tool fingerprint (built-in lists in intel_data)."""
    value = cert_ja4x(cert)
    match = known_ja4x(value)
    if not match:
        return
    name, kind = match
    note = layout_note(value)
    iocs = (f"JA4X: {value} ({name})\nCommon Name: {info['cn'] or 'N/A'}\nIssuer: {info['issuer'] or 'N/A'}\n"
            f"Self-signed: {'yes' if info['self_signed'] else 'no'}\nCert Hash: {cert.get('Hash', 'N/A')}")
    if kind == "c2":
        ctx.add("Known C2 Certificate Fingerprint (JA4X)", "High", "T1588.002 (Obtain Capabilities: Tool)",
                f"The certificate's JA4X matches {name}: it was generated the way that tool generates its own"
                + (f" ({note})" if note else "") + ". Other certificates built with the same fields match too, so "
                "confirm with the certificate itself.", iocs,
                confidence="High" if info["self_signed"] else None)
    else:
        ctx.add("Dual-Use Tool Certificate Fingerprint (JA4X)", "Medium", "T1572 (Protocol Tunneling)",
                f"The certificate's JA4X matches {name}, legitimate software that attackers also run for tunnels "
                "and remote access.", iocs)


PER_CERT_RULES = (
    rule_self_signed,
    rule_backdated,
    rule_unusual_fields,
    rule_known_ja4x,
    rule_short_lived,
    rule_mega_san,
    rule_bare_ip_certificate,
    rule_cn_mismatch,
    rule_precertificate,
    rule_missing_scts,
    rule_rogue_ca,
    rule_validity_window,
    rule_deprecated_signature,
    rule_non_public_ca,
    rule_caa_policy,
    rule_wildcard_sprawl,
    rule_wildcard_observed,
    rule_suspicious_dv,
    rule_weak_key,
)


# ---------------------------------------------------------------------------
# Domain-level post-pass
# ---------------------------------------------------------------------------

def _churn_timeline(certs):
    """(issued, expires, names, hash, cert) per certificate with known dates, in issue order."""
    rows = []
    for _, cert in certs.iterrows():
        issued = _cert_date(cert, "Not Before Date", "Not Before")
        expires = _cert_date(cert, "Not After Date", "Not After")
        duration = cert_duration_days(cert)
        if pd.isna(expires) and pd.notna(issued) and duration:
            expires = issued + pd.Timedelta(days=duration)
        names = {n.lower() for n in cert_alt_names(cert)} | {str(cert.get("Common Name") or "").strip().lower()} - {""}
        if pd.notna(issued) and pd.notna(expires) and expires > issued and names:
            rows.append((issued, expires, names, str(cert.get("Hash")), cert))
    return sorted(rows, key=lambda row: row[0])


def rule_certificate_churn(ctx, certs):
    """
    Early replacements: a new certificate for the same names while the previous one still had more than half its
    validity left. Scheduled renewals (6-, 45- or 90-day certificates renewed near expiry) do not count.
    """
    timeline = _churn_timeline(certs)
    early = []
    for i, (issued, _, names, cert_hash, cert) in enumerate(timeline):
        previous = [row for row in timeline[:i]
                    if row[2] & names and row[0] + PARALLEL_ISSUANCE <= issued < row[1]]
        if not previous:
            continue
        prev_issued, prev_expires, _, prev_hash, _ = max(previous, key=lambda row: row[0])
        remaining = (prev_expires - issued) / (prev_expires - prev_issued)
        if remaining > EARLY_REPLACEMENT_REMAINING:
            early.append((issued, cert_hash, prev_hash, remaining, cert))
    if not early:
        return
    window = pd.Timedelta(days=ctx.thresholds["ssl_churn_days"])
    threshold = ctx.thresholds["ssl_churn_count"]
    for i, (start, *_rest) in enumerate(early):
        burst = [row for row in early[i:] if row[0] <= start + window]
        if len(burst) >= threshold:
            ctx.add(
                "Certificate Churn (Ephemeral SSL)", "High", "T1588.004 (Obtain Digital Certificates)",
                f"{len(burst)} certificate(s) replaced early within {int(ctx.thresholds['ssl_churn_days'])} days: reissued for the "
                "same names while the previous certificate still had over half its validity left.",
                "\n".join(f"[{fmt_ts(when, '%Y-%m-%d %H:%M')}] {new[:16]}... replaced {old[:16]}... with {left:.0%} validity left"
                          for when, new, old, left, _ in burst),
                evidence=[evidence_record(when, "Early replacement", f"replaced {old[:16]}... with {left:.0%} validity left",
                                          artifact=new) for when, new, old, left, _ in burst],
            )
            return


def run_ssl_rules(ctx):
    certs = ctx.ssl
    if certs.empty:
        return
    unique_certs = certs.drop_duplicates(subset=["Hash"]) if "Hash" in certs.columns else certs

    first_seen = first_resolution(ctx)
    rule_rapid_weaponization(ctx, unique_certs, first_seen)
    rule_certificate_staging(ctx, unique_certs, first_seen)

    caa_dates = []
    for record in ctx.caa_policy.records:
        value = pd.to_datetime(record.get("Last Seen"), errors="coerce", utc=True)
        if pd.notna(value):
            caa_dates.append(value.tz_localize(None))
    caa_last_seen = max(caa_dates) if caa_dates else pd.NaT

    for _, cert in unique_certs.iterrows():
        info = {
            "cn": str(cert.get("Common Name") or "").strip(),
            "issuer": str(cert.get("Issuer") or "").strip(),
            "sans": cert_alt_names(cert),
            "ip_names": cert_ip_names(cert),
            "self_signed": cert_is_self_signed(cert),
            "wildcard": cert_is_wildcard(cert),
            "duration": cert_duration_days(cert),
            "not_before": _cert_date(cert, "Not Before Date", "Not Before"),
            "public_trust": publicly_trusted(cert),
            "caa_last_seen": caa_last_seen,
        }
        ctx.evidence_scope = [cert_evidence(cert, info)]
        try:
            for rule in PER_CERT_RULES:
                rule(ctx, cert, info)
        finally:
            ctx.evidence_scope = None

    rule_certificate_churn(ctx, unique_certs)

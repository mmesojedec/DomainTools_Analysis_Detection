"""DNS, passive DNS, and Domain History behavioral detection rules."""
import re
from collections import Counter

import numpy as np
import pandas as pd

from core.helpers import calculate_shannon_entropy, domain_core_label
from core.network_intel import cdn_for_ip
from core.threat_detection.context import (
    IP_FIELDS,
    MAX_EVIDENCE,
    MAX_IOC_LINES,
    NS_FIELDS,
    event_line,
    event_record,
    evidence_record,
    fmt_ts,
    upper_fields,
)

SINKHOLE_REGEX = r"(?<![\d.])(?:127\.0\.0\.1|0\.0\.0\.0)(?![\d.])|sinkhole|block\.opendns|blackhole"
SUSPICIOUS_NS_REGEX = re.compile(
    r"(duckdns\.org|afraid\.org|freenom\.com|ddns\.net|no-ip\.com|njalla|tonidomain|flokinet|alexhost|offshorify)",
    re.IGNORECASE,
)
SUSPICIOUS_MX_REGEX = re.compile(r"(yandex\.ru|mail\.ru|cock\.li|protonmail|tempmail|guerrillamail)", re.IGNORECASE)
IPTV_SUBDOMAIN_REGEX = r"^(?:m3u|playlist|live|stream|get|xtream|stalker|ott|panel|restream|ts-|hls)\."


def rule_dga_entropy(ctx):
    if ctx.is_ip:
        return
    core_name = domain_core_label(ctx.domain)
    ctx.entropy = calculate_shannon_entropy(core_name)
    if len(core_name) >= 10 and ctx.entropy > ctx.thresholds["entropy"]:
        ctx.add(
            "DGA / High Entropy Domain", "Medium-High", "T1568.002 (Dynamic Resolution: DGA)",
            f"Domain label '{core_name}' exhibits high Shannon Entropy ({round(ctx.entropy, 2)}).",
            f"Domain: {ctx.domain}\nScored Label: {core_name}\nCalculated Entropy: {round(ctx.entropy, 2)}",
            flag="dga",
        )


def rule_parked_to_weaponized(ctx):
    ev = ctx.events
    if len(ev) < 4:
        return
    gaps = ev["Days Since Previous Event"].to_numpy(dtype=float)
    dates = ev["Date"].to_numpy()
    burst_hours = (dates[3:] - dates[:-3]) / np.timedelta64(1, "h")
    hits = np.flatnonzero((gaps[:-3] > ctx.thresholds["parked_days"]) & (burst_hours <= 48))
    if hits.size == 0:
        return
    i = int(hits[0])
    rapid = ev.iloc[i:i + 4]
    ctx.add(
        "Parked-to-Weaponized", "Critical", "T1583.001 (Acquire Infrastructure)",
        f"Domain dormant for {int(gaps[i])} days, followed by 3+ rapid changes within 48 hours.",
        "\n".join(event_line(row, max_len=80) for _, row in rapid.iterrows()),
        flag="parked_to_weaponized",
        evidence=[event_record(row, max_len=80) for _, row in rapid.iterrows()],
    )


def _explode_values(records):
    """Splits multi-line rdata (one rrset holding several IPs) into one row per value."""
    exploded = records.assign(_val=records["Value"].astype(str).str.split("\n")).explode("_val")
    exploded["_val"] = exploded["_val"].str.strip()
    return exploded[exploded["_val"] != ""]


def rule_fast_flux(ctx):
    ev = ctx.events
    ip_records = ev[upper_fields(ev).isin(IP_FIELDS)]
    if ip_records.empty:
        return
    ip_records = _explode_values(ip_records).sort_values("Date", kind="stable").reset_index(drop=True)
    dates = ip_records["Date"].tolist()
    values = ip_records["_val"].tolist()
    threshold = ctx.thresholds["flux_ips"]
    window = pd.Timedelta(days=7)

    # Two-pointer sliding window: O(n) instead of re-filtering the frame for every start row
    counts, j = Counter(), 0
    for i in range(len(dates)):
        while j < len(dates) and dates[j] <= dates[i] + window:
            counts[values[j]] += 1
            j += 1
        if len(counts) >= threshold:
            rows = ip_records.iloc[i:j]
            lines = [f"[{fmt_ts(r['Date'])}] {r['Field']} ➔ {r['_val']}" for _, r in rows.head(MAX_IOC_LINES).iterrows()]
            if len(rows) > MAX_IOC_LINES:
                lines.append(f"... {len(rows) - MAX_IOC_LINES} more observations")
            cdns = {cdn_for_ip(ip, ctx.ip_intel) for ip in counts}
            all_cdn = None not in cdns
            note = f" All IPs belong to {', '.join(sorted(cdns))} (CDN anycast rotation is normal)." if all_cdn else ""
            ctx.add(
                "Rapid IP Rotation (Fast-Flux)", "High", "T1568.001 (Fast Flux DNS)",
                f"{len(counts)} distinct IP addresses assigned within a single 7-day window (threshold >= {threshold}).{note}",
                "\n".join(lines),
                flag=None if all_cdn else "fast_flux",
                confidence="Low" if all_cdn else None,
                evidence=[evidence_record(r["Date"], r["Field"], r["_val"], artifact=r["_val"]) for _, r in rows.iterrows()],
            )
            return
        counts[values[i]] -= 1
        if counts[values[i]] == 0:
            del counts[values[i]]


def rule_sinkhole(ctx):
    ev = ctx.events
    candidates = ev[upper_fields(ev).isin(IP_FIELDS | NS_FIELDS)]
    hits = candidates[candidates["Value"].astype(str).str.contains(SINKHOLE_REGEX, regex=True, case=False, na=False)]
    if hits.empty:
        return
    ctx.add(
        "Sinkhole / Loopback Resolution", "Medium", "T1568.001 (Dynamic Resolution)",
        "Record resolves to a local loopback or known security vendor sinkhole.",
        event_line(hits.iloc[0]),
        evidence=[event_record(hits.iloc[0])],
    )


def _first_regex_hit(records, pattern):
    for _, row in records.iterrows():
        if pattern.search(str(row["Value"])):
            return row
    return None


def rule_suspicious_nameserver(ctx):
    ev = ctx.events
    row = _first_regex_hit(ev[upper_fields(ev).isin(NS_FIELDS)], SUSPICIOUS_NS_REGEX)
    if row is None:
        return
    ctx.add(
        "Suspicious / Offshore Name Server", "Medium-High", "T1583.001 (Acquire Infrastructure)",
        "Domain utilizes a dynamic, free, or bulletproof DNS provider.",
        event_line(row),
        flag="suspicious_ns",
        evidence=[event_record(row)],
    )


def rule_high_risk_mail_provider(ctx):
    ev = ctx.events
    row = _first_regex_hit(ev[upper_fields(ev) == "MX"], SUSPICIOUS_MX_REGEX)
    if row is None:
        return
    ctx.add(
        "High-Risk Mail Provider", "Medium", "T1585.002 (Acquire Email Accounts)",
        "MX records point to an offshore, anonymous, or temporary email provider.",
        event_line(row, label="MX"),
        evidence=[event_record(row, label="MX")],
    )


def rule_phishing_prep(ctx):
    ev = ctx.events
    mail_records = ev[upper_fields(ev).isin({"MX", "TXT", "SPF"})]
    dormant = mail_records[mail_records["Days Since Previous Event"] > ctx.thresholds["phish_days"]]
    if dormant.empty:
        return
    row = dormant.iloc[0]
    ctx.add(
        "Phishing/Spam Prep", "Medium-High", "T1583.001 (Acquire Infrastructure)",
        f"Sudden configuration of {row['Field']} records after {int(row['Days Since Previous Event'])} days of dormancy.",
        event_line(row), evidence=[event_record(row)],
    )


def rule_spf_policy(ctx):
    ev = ctx.events
    malformed_reported = False
    for _, row in ev[upper_fields(ev).isin({"TXT", "SPF"})].iterrows():
        val_str = str(row["Value"]).strip().lower()
        if "spf1" not in val_str:
            continue
        # Iris pDNS source "A" strips the "v" prefix from rdata, so it is not evidence of a malformed record
        if not malformed_reported and "v=spf1" not in val_str and "=spf1" in val_str and str(row.get("Source", "")) != "A":
            ctx.add(
                "Invalid/Malformed SPF", "Low", "T1583.001 (Acquire Infrastructure)",
                "SPF record missing required 'v=' prefix.", event_line(row), evidence=[event_record(row)],
            )
            malformed_reported = True
        if re.search(r"(?<![\w-])\+all\b", val_str):
            ctx.add(
                "Highly Permissive SPF (+all)", "High", "T1583.001 (Acquire Infrastructure)",
                "SPF allows ANY IP address (+all) to pass authorization.", event_line(row), evidence=[event_record(row)],
            )
            return


def rule_anomalous_txt(ctx):
    ev = ctx.events
    for _, row in ev[upper_fields(ev) == "TXT"].iterrows():
        val_str = str(row["Value"])
        if len(val_str) > ctx.thresholds["txt_len"] and val_str.count(" ") < 3:
            ctx.add(
                "Anomalous TXT Payload", "High", "T1071.004 (DNS C2)",
                f"Detected unusually long TXT record ({len(val_str)} chars).",
                f"[{fmt_ts(row['Date'])}] TXT PAYLOAD ➔ {val_str[:150]}...",
                evidence=[evidence_record(row["Date"], "TXT", val_str)],
            )
            return


def rule_burst_campaign(ctx):
    ev = ctx.events
    if "Count" not in ev.columns or "Lifespan Days" not in ev.columns:
        return
    counts = pd.to_numeric(ev["Count"], errors="coerce")
    lifespans = pd.to_numeric(ev["Lifespan Days"], errors="coerce").clip(lower=0.1)
    density = counts / lifespans
    hits = ev[(density > ctx.thresholds["burst_density"]) & (counts > 1000) & (lifespans <= 7)]
    if hits.empty:
        return
    row = hits.iloc[0]
    row_density = density.loc[hits.index[0]]
    ctx.add(
        "Flash/Burst Campaign", "Critical", "T1071.004 (App Layer Protocol: DNS)",
        f"Extreme query density detected: {int(row_density)} queries/day.",
        f"{event_line(row, max_len=100)}\nTotal Queries: {int(counts.loc[hits.index[0]])}\nDensity: {int(row_density)} queries/day",
        evidence=[event_record(row, max_len=100),
                  evidence_record(row["Date"], "Query Density", f"{int(counts.loc[hits.index[0]])} queries, {int(row_density)}/day")],
    )


def rule_subdomain_patterns(ctx):
    """IPTV endpoints, ACME challenge sprawl, and deeply nested (shadowed) subdomains from pDNS RRNames."""
    ev = ctx.events
    if "RRName" not in ev.columns:
        return
    rrnames = ev["RRName"].astype(str)

    iptv = ev[rrnames.str.contains(IPTV_SUBDOMAIN_REGEX, regex=True, na=False, case=False)]
    if not iptv.empty:
        row = iptv.iloc[0]
        ctx.add(
            "IPTV / Stream Distribution Endpoint", "High", "T1584.001 (Compromise Infrastructure)",
            f"Detected streaming endpoint prefix '{row['RRName']}'.",
            f"[{fmt_ts(row['Date'])}] {row['Field']} ➔ {row['RRName']}",
            evidence=[event_record(row, value_col="RRName")],
        )

    if ctx.is_ip:
        return

    acme_count = int(rrnames.str.contains("_acme-challenge", case=False, na=False).sum())
    if acme_count > 3:
        ctx.add(
            "ACME Certificate Sprawl", "Medium-High", "T1588.004 (Obtain Digital Certificates)",
            f"Detected {acme_count} automated ACME challenges.",
            f"Domain: {ctx.domain}\nChallenge Count: {acme_count}",
        )

    nested = ev[(rrnames.str.count(r"\.") - ctx.domain.count(".") >= 3) & ev["RRName"].notna()]
    if not nested.empty:
        row = nested.iloc[0]
        ctx.add(
            "Deeply Nested Subdomains", "High", "T1584.001 (Compromise Infrastructure)",
            "Detected highly fragmented subdomains (Domain Shadowing).",
            f"[{fmt_ts(row['Date'])}] {row['Field']} ➔ {row['RRName']}",
            evidence=[event_record(r, value_col="RRName") for _, r in nested.head(MAX_EVIDENCE).iterrows()],
        )


DNS_RULES = (
    rule_parked_to_weaponized,
    rule_fast_flux,
    rule_sinkhole,
    rule_suspicious_nameserver,
    rule_high_risk_mail_provider,
    rule_phishing_prep,
    rule_spf_policy,
    rule_anomalous_txt,
    rule_burst_campaign,
    rule_subdomain_patterns,
)

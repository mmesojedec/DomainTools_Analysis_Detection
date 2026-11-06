"""Exports: IOC lists (CSV/JSON), STIX 2.1 bundles, and analyst evidence reports (Markdown/HTML)."""
import html
import json
import re
import uuid
from datetime import datetime, timezone

import pandas as pd

from core.anonymizers import ANONYMIZER_CATEGORIES, by_ip, shared_exit
from core.helpers import extract_ip_addresses, is_ip_address
from core.network_intel import cdn_for_ip, record_types
from integrations.enrichment import extract_iris_profile

STIX_NAMESPACE = uuid.UUID("5b4b8f5e-6f1f-4d7e-9a6c-3c1f2d9e8a10")
IOC_COLUMNS = ["Type", "Value", "Domain", "Source", "First Seen", "Last Seen", "Note"]


def _ts(value):
    parsed = pd.to_datetime(value, errors="coerce")
    return parsed.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(parsed) else ""


def dataset_iocs(ds):
    """collect_iocs() for a dataset, built once and kept with it (the dataset is reused across reruns)."""
    if "iocs" not in ds.derived:
        ds.derived["iocs"] = collect_iocs(ds, ds.ip_intel)
    return ds.derived["iocs"]


def collect_iocs(ds, ip_intel=None):
    """Domains, IPs, certificate hashes, and name servers observed for the selected targets."""
    rows = []
    for domain in ds.selected_domains:
        kind = ("ipv6-addr" if ":" in domain else "ipv4-addr") if is_ip_address(domain) else "domain-name"
        rows.append({"Type": kind, "Value": domain, "Domain": domain, "Source": "Target"})
    events = ds.events_utc
    if events is not None and not events.empty:
        types = record_types(events)
        last_seen = events["Last Seen"] if "Last Seen" in events.columns else pd.Series(pd.NaT, index=events.index)
        for idx, (domain, rtype, value) in enumerate(zip(events["Domain"], types, events["Value"].astype(str))):
            first, last = events["Date"].iloc[idx], last_seen.iloc[idx]
            source = events["Source"].iloc[idx] if "Source" in events.columns and pd.notna(events["Source"].iloc[idx]) else "Domain History"
            if rtype in ("A", "AAAA", "IP", "A RECORD"):
                for ip in extract_ip_addresses(value):
                    cdn = cdn_for_ip(ip, ip_intel)
                    rows.append({"Type": "ipv6-addr" if ":" in ip else "ipv4-addr", "Value": ip, "Domain": domain, "Source": source,
                                 "First Seen": first, "Last Seen": last, "Note": f"CDN: {cdn}" if cdn else ""})
            elif rtype in ("NS", "NAME_SERVER"):
                for host in value.split("\n"):
                    host = host.strip().lower().rstrip(".")
                    if host:
                        rows.append({"Type": "domain-name", "Value": host, "Domain": domain, "Source": source,
                                     "First Seen": first, "Last Seen": last, "Note": "Name server"})
    for domain, obj in (ds.enrichment or {}).items():
        for entry in extract_iris_profile(obj)["ips"]:
            rows.append({"Type": "ipv6-addr" if ":" in entry["ip"] else "ipv4-addr", "Value": entry["ip"], "Domain": domain,
                         "Source": "Iris Investigate", "Note": f"AS{entry['asn']} {entry['isp']}".strip() if entry["asn"] else entry["isp"]})
    if ds.ssl_utc is not None and not ds.ssl_utc.empty:
        for _, cert in ds.ssl_utc.iterrows():
            value = str(cert.get("Hash") or "").strip()
            if value:
                kind = "x509-sha256" if len(value) == 64 else "x509-sha1"
                rows.append({"Type": kind, "Value": value.lower(), "Domain": cert["Domain"], "Source": cert.get("Source", ""),
                             "First Seen": cert.get("Not Before Date"), "Last Seen": cert.get("Not After Date"),
                             "Note": f"CN={cert.get('Common Name', '')}; Issuer={cert.get('Issuer', '')}"})
    if not rows:
        return pd.DataFrame(columns=IOC_COLUMNS)
    iocs = pd.DataFrame(rows, columns=IOC_COLUMNS)
    iocs["First Seen"] = pd.to_datetime(iocs["First Seen"], errors="coerce")
    iocs["Last Seen"] = pd.to_datetime(iocs["Last Seen"], errors="coerce")
    grouped = iocs.groupby(["Type", "Value"], as_index=False).agg(
        Domain=("Domain", lambda x: ", ".join(sorted(set(map(str, x))))),
        Source=("Source", lambda x: ", ".join(sorted({str(s) for s in x if str(s)}))),
        **{"First Seen": ("First Seen", "min"), "Last Seen": ("Last Seen", "max")},
        Note=("Note", lambda x: "; ".join(sorted({str(n) for n in x if str(n) and str(n) != "nan"}))[:300]),
    )
    grouped["First Seen"] = grouped["First Seen"].map(_ts)
    grouped["Last Seen"] = grouped["Last Seen"].map(_ts)
    return grouped[IOC_COLUMNS].sort_values(["Type", "Value"]).reset_index(drop=True)


MISP_TYPES = {"domain-name": "domain", "ipv4-addr": "ip-dst", "ipv6-addr": "ip-dst",
              "x509-sha256": "x509-fingerprint-sha256", "x509-sha1": "x509-fingerprint-sha1"}
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def ioc_type(value):
    """IOC type (as collect_iocs names them) of a bare value: IP, certificate hash or domain name; None otherwise."""
    value = str(value or "").strip().lower()
    if is_ip_address(value):
        return "ipv6-addr" if ":" in value else "ipv4-addr"
    if _HEX_RE.match(value) and len(value) in (40, 64):
        return "x509-sha256" if len(value) == 64 else "x509-sha1"
    if "." in value and " " not in value and "/" not in value:
        return "domain-name"
    return None


def confirmed_indicators(iocs, alerts, verdicts, anonymizers=None):
    """
    Indicators of what the analyst marked Malicious: every IOC of a domain with a Malicious verdict or a Malicious
    alert, plus the artifacts in those alerts' evidence. IOC_COLUMNS plus Reason, VPNDB (the IP's anonymizer verdict)
    and Shared Exit (VPNDB rates the IP a shared exit: it identifies the service, not the actor).
    """
    alerts = alerts if alerts is not None else pd.DataFrame()
    marked = alerts[alerts["Status"] == "Malicious"] if "Status" in alerts else alerts.iloc[0:0]
    domains = {d for d, status in (verdicts or {}).items() if status == "Malicious"} | set(marked.get("Domain", []))
    columns = IOC_COLUMNS + ["Reason", "VPNDB", "Shared Exit"]
    if not domains:
        return pd.DataFrame(columns=columns)
    rows = []
    if iocs is not None and not iocs.empty:
        hits = iocs[iocs["Domain"].map(lambda value: bool(domains & {d.strip() for d in str(value).split(",")}))]
        rows += [{**row, "Reason": "Indicator of a domain marked Malicious"} for row in hits.to_dict("records")]
    for _, alert in marked.iterrows():
        for record in alert.get("Evidence") if isinstance(alert.get("Evidence"), list) else []:
            kind = ioc_type(record.get("Artifact"))
            if kind:
                rows.append({"Type": kind, "Value": str(record["Artifact"]).strip().lower(), "Domain": alert["Domain"],
                             "Source": "Alert evidence", "Note": str(record.get("Field") or ""),
                             "Reason": f"Evidence of the Malicious alert '{alert['Threat Type']}'"})
    if not rows:
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame(rows).reindex(columns=columns)
    verdicts_by_ip = by_ip(anonymizers)
    flagged = {ip: row for ip, row in verdicts_by_ip.items() if row["Category"] in ANONYMIZER_CATEGORIES}
    frame["VPNDB"] = frame["Value"].map(lambda v: " · ".join(p for p in (flagged[v]["Category"], flagged[v]["Provider"],
                                                                          flagged[v]["Tor"]) if p) if v in flagged else "")
    frame["Shared Exit"] = frame["Value"].map(lambda v: v in flagged and shared_exit(flagged[v]))
    return frame.drop_duplicates(subset=["Type", "Value"]).sort_values(["Type", "Value"]).reset_index(drop=True)


def to_misp_event(indicators, info="DomainTools Analytics & Detection: confirmed indicators"):
    """A MISP event (JSON import format) with one attribute per indicator."""
    attributes = []
    for _, row in indicators.iterrows():
        kind = MISP_TYPES.get(row["Type"])
        if not kind:
            continue
        shared = bool(row.get("Shared Exit"))   # a shared VPN / proxy exit: context, not a detection indicator
        attributes.append({"type": kind, "category": "Network activity", "value": row["Value"], "to_ids": not shared,
                           "comment": "; ".join(str(part) for part in (row.get("Domain"), row.get("Reason"),
                                                                       f"VPNDB: {row['VPNDB']}" if row.get("VPNDB") else "",
                                                                       "shared exit" if shared else "")
                                                if part and str(part) != "nan")})
    event = {"info": info, "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "threat_level_id": "2",
             "analysis": "1", "distribution": "0", "Attribute": attributes}
    return json.dumps({"Event": event}, indent=2)


def _stix_id(kind, value):
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, f'{kind}:{value}')}"


def _stix_pattern(ioc_type, value):
    escaped = str(value).replace("\\", "\\\\").replace("'", "\\'")
    if ioc_type == "domain-name":
        return f"[domain-name:value = '{escaped}']"
    if ioc_type == "ipv4-addr":
        return f"[ipv4-addr:value = '{escaped}']"
    if ioc_type == "ipv6-addr":
        return f"[ipv6-addr:value = '{escaped}']"
    if ioc_type == "x509-sha256":
        return f"[x509-certificate:hashes.'SHA-256' = '{escaped}']"
    if ioc_type == "x509-sha1":
        return f"[x509-certificate:hashes.'SHA-1' = '{escaped}']"
    return None


def to_stix_bundle(iocs, alerts, producer="DT Analytics & Detection"):
    """STIX 2.1 bundle: an identity, one indicator per IOC (annotated with alert types), and a report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity = {"type": "identity", "spec_version": "2.1", "id": _stix_id("identity", producer), "created": now, "modified": now,
                "name": producer, "identity_class": "system"}
    threats_by_domain = {}
    if alerts is not None and not alerts.empty:
        for domain, group in alerts.groupby("Domain"):
            threats_by_domain[domain] = sorted(set(group["Threat Type"]))
    objects = [identity]
    for _, ioc in iocs.iterrows():
        pattern = _stix_pattern(ioc["Type"], ioc["Value"])
        if not pattern:
            continue
        related_threats = sorted({t for d in str(ioc["Domain"]).split(", ") for t in threats_by_domain.get(d, [])})
        indicator = {
            "type": "indicator", "spec_version": "2.1", "id": _stix_id("indicator", f"{ioc['Type']}:{ioc['Value']}"),
            "created": now, "modified": now, "created_by_ref": identity["id"],
            "name": f"{ioc['Type']}: {ioc['Value']}", "pattern": pattern, "pattern_type": "stix", "valid_from": now,
            "indicator_types": ["malicious-activity"] if related_threats else ["unknown"],
            "description": f"Related targets: {ioc['Domain']}. Sources: {ioc['Source']}."
                           + (f" Detections: {', '.join(related_threats)}." if related_threats else "")
                           + (f" Note: {ioc['Note']}" if ioc["Note"] else ""),
        }
        objects.append(indicator)
    if len(objects) > 1:
        objects.append({
            "type": "report", "spec_version": "2.1", "id": _stix_id("report", now), "created": now, "modified": now,
            "created_by_ref": identity["id"], "name": "DomainTools Analytics & Detection export", "published": now,
            "report_types": ["threat-report"], "object_refs": [o["id"] for o in objects[1:]],
        })
    return json.dumps({"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}, indent=2)


def _md_table(df, max_rows=200):
    if df is None or df.empty:
        return "_None_\n"
    df = df.head(max_rows).astype(str).replace({"nan": "", "NaT": ""})

    def cells(row):
        return "| " + " | ".join(str(v).replace("|", "\\|").replace("\n", "<br>") for v in row) + " |"

    lines = [cells(df.columns), "| " + " | ".join("---" for _ in df.columns) + " |"] + [cells(r) for r in df.itertuples(index=False)]
    return "\n".join(lines) + "\n"


def build_report_markdown(ds, alerts, profiles, iocs, correlation=None):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    parts = [f"# DomainTools Analytics & Detection Report\n\nGenerated {now} for {len(ds.selected_domains)} target(s): "
             f"{', '.join(ds.selected_domains)}\n\nAnalysis window: {ds.window.describe(ds.timezone)}\n"]
    if profiles is not None and not profiles.empty:
        parts.append("## Risk Overview\n" + _md_table(profiles[["Domain", "Unified Risk", "Base Domain Risk Score", "DIF Fingerprint"]]))
    if alerts is not None and not alerts.empty:
        sev = alerts["Severity"].value_counts().to_dict()
        parts.append(f"## Detections ({len(alerts)})\n\nBy severity: " + ", ".join(f"{k}: {v}" for k, v in sev.items()) + "\n\n"
                     + _md_table(alerts[["Domain", "Severity", "Confidence", "Threat Type", "MITRE ATT&CK", "Threat Logic"]]))
    if correlation is not None and correlation.clusters:
        rows = [{"Cluster": c["Cluster"], "Strength": c["Strength"], "Domains": ", ".join(c["Domains"]),
                 "Shared": "; ".join(f"{k} ({len(v)})" for k, v in c["Shared Artifacts"].items())} for c in correlation.clusters]
        parts.append("## Infrastructure Clusters\n" + _md_table(pd.DataFrame(rows)))
    parts.append(f"## Indicators ({len(iocs)})\n" + _md_table(iocs, max_rows=500))
    if alerts is not None and not alerts.empty:
        parts.append("## Evidence\n")
        for _, row in alerts.iterrows():
            parts.append(f"### [{row['Severity']}] {row['Threat Type']} — {row['Domain']}\n\n{row['Threat Logic']}\n\n```\n{row['Triggering IOCs']}\n```\n")
    return "\n".join(parts)


def build_report_html(ds, alerts, profiles, iocs, correlation=None):
    def table(df, max_rows=500):
        if df is None or df.empty:
            return "<p><em>None</em></p>"
        return df.head(max_rows).to_html(index=False, escape=True, na_rep="", classes="t")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = [f"<h1>DomainTools Analytics &amp; Detection Report</h1><p>Generated {now} for "
                f"{html.escape(', '.join(ds.selected_domains))}<br>Analysis window: {html.escape(ds.window.describe(ds.timezone))}</p>"]
    if profiles is not None and not profiles.empty:
        sections.append("<h2>Risk Overview</h2>" + table(profiles[["Domain", "Unified Risk", "Base Domain Risk Score", "DIF Fingerprint", "DIF Breakdown"]]))
    if alerts is not None and not alerts.empty:
        sections.append(f"<h2>Detections ({len(alerts)})</h2>"
                        + table(alerts[["Domain", "Severity", "Confidence", "Category", "Threat Type", "MITRE ATT&CK", "Threat Logic"]]))
    if correlation is not None and correlation.clusters:
        rows = [{"Cluster": c["Cluster"], "Strength": c["Strength"], "Domains": ", ".join(c["Domains"]),
                 "Shared": "; ".join(f"{k}: {', '.join(v[:5])}" for k, v in c["Shared Artifacts"].items())} for c in correlation.clusters]
        sections.append("<h2>Infrastructure Clusters</h2>" + table(pd.DataFrame(rows)))
    sections.append(f"<h2>Indicators ({len(iocs)})</h2>" + table(iocs, max_rows=2000))
    if alerts is not None and not alerts.empty:
        sections.append("<h2>Evidence</h2>" + "".join(
            f"<h3>[{html.escape(str(r['Severity']))}] {html.escape(str(r['Threat Type']))} — {html.escape(str(r['Domain']))}</h3>"
            f"<p>{html.escape(str(r['Threat Logic']))}</p><pre>{html.escape(str(r['Triggering IOCs']))}</pre>"
            for _, r in alerts.iterrows()))
    style = ("body{font-family:system-ui,sans-serif;margin:24px;color:#1b1f29}table.t{border-collapse:collapse;font-size:12px;margin:8px 0}"
             "table.t th,table.t td{border:1px solid #ccd;padding:4px 6px;text-align:left;vertical-align:top}"
             "table.t th{background:#eef}pre{background:#f5f6f8;padding:8px;white-space:pre-wrap}")
    return f"<!doctype html><html><head><meta charset='utf-8'><title>DT Detection Report</title><style>{style}</style></head><body>{''.join(sections)}</body></html>"

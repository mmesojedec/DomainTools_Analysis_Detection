"""Exports: IOC lists (CSV/JSON), STIX 2.1 bundles, and analyst evidence reports (Markdown/HTML)."""
import html
import json
import re
import uuid
from datetime import datetime, timezone

import pandas as pd

from core import bgp
from core.anonymizers import ANONYMIZER_CATEGORIES, by_ip, shared_exit
from core.helpers import extract_ip_addresses, is_ip_address
from core.intel_data import INFORMATIONAL_RULES
from core.network_intel import cdn_for_ip, record_types
from core.rule_catalog import RULE_CATALOG
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


ROUTING_TYPES = ("autonomous-system", "ipv4-prefix", "ipv6-prefix")   # context: never to_ids, never malicious alone
ROUTING_FINDING = "Routing finding: "


def routing_iocs(ds):
    """
    IOC rows for the BGP routing of the selected domains (BGPDB): each usual origin network (autonomous-system) and
    announced prefix, plus the networks named by a routing finding (an unauthorized origin, for one). Context for
    pivoting and blocking decisions, marked as such; a finding naming the value is added to its Note.
    """
    origins = getattr(ds, "bgp_origins", None)
    if origins is None or origins.empty:
        return []
    found = bgp.findings(origins, getattr(ds, "bgp_asns", None), getattr(ds, "bgp_routes", None))
    by_value = {}
    for _, row in found.iterrows():
        for value in (row["ASN"], row["Prefix"]):
            if value:
                by_value.setdefault(str(value), set()).add(row["Finding"])
    rows, selected = [], set(ds.selected_domains)

    def add(kind, value, domains, first, last, note):
        findings = by_value.get(value)
        for domain in sorted({d.strip() for d in str(domains).split(",") if d.strip()} & selected):
            rows.append({"Type": kind, "Value": value, "Domain": domain, "Source": "BGPDB", "First Seen": first,
                         "Last Seen": last, "Note": note + (f"; {ROUTING_FINDING}{', '.join(sorted(findings))}"
                                                            if findings else "")})

    for _, row in bgp.main_origins(origins).iterrows():
        add("autonomous-system", str(row["Origin"]).upper(), row["Domains"], row["First Seen"], row["Last Seen"],
            f"Context: origin network of {row['IP']} ({row['AS Name']})".replace(" ()", ""))
        prefix = str(row["Prefix"]).rstrip("+")
        add("ipv6-prefix" if ":" in prefix else "ipv4-prefix", prefix, row["Domains"], row["First Seen"],
            row["Last Seen"], f"Context: announced prefix of {row['IP']} by {row['Origin']}")
    flagged = found[found["Finding"].isin((bgp.CONFLICT, bgp.UNAUTHORIZED_ORIGIN, bgp.TOR_ORIGIN))]
    for _, row in flagged.iterrows():
        if row["ASN"]:
            add("autonomous-system", str(row["ASN"]).upper(), row["Domains"], row["First Seen"], row["Last Seen"],
                f"Announced {row['Prefix']} without authorization")
    return rows


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
    rows += routing_iocs(ds)
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
              "x509-sha256": "x509-fingerprint-sha256", "x509-sha1": "x509-fingerprint-sha1",
              "autonomous-system": "AS", "ipv4-prefix": "ip-dst", "ipv6-prefix": "ip-dst"}
_ASN_RE = re.compile(r"^as\d+$")
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def ioc_type(value):
    """IOC type (as collect_iocs names them) of a bare value: IP, certificate hash or domain name; None otherwise."""
    value = str(value or "").strip().lower()
    if is_ip_address(value):
        return "ipv6-addr" if ":" in value else "ipv4-addr"
    if _ASN_RE.match(value):
        return "autonomous-system"
    if "/" in value and is_ip_address(value.split("/")[0]) and value.split("/")[1].isdigit():
        return "ipv6-prefix" if ":" in value else "ipv4-prefix"
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


def _reason_rule(reason):
    """The rule named in a confirmed indicator's reason (`... alert 'Threat Type'`), else ""."""
    match = re.search(r"'([^']+)'", str(reason or ""))
    return match.group(1) if match else ""


def to_misp_event(indicators, info="DomainTools Analytics & Detection: confirmed indicators"):
    """A MISP event (JSON import format) with one attribute per indicator."""
    attributes = []
    for _, row in indicators.iterrows():
        kind = MISP_TYPES.get(row["Type"])
        if not kind:
            continue
        # a shared VPN / proxy exit, a network or a prefix: context, not a detection indicator
        shared = bool(row.get("Shared Exit")) or row["Type"] in ROUTING_TYPES
        technique = _technique(RULE_CATALOG.get(_reason_rule(row.get("Reason")), ("", ""))[1])
        tags = [{"name": f'misp-galaxy:mitre-attack-pattern="{technique[1]} - {technique[0]}"'}] if technique else []
        value = str(row["Value"]).upper().removeprefix("AS") if kind == "AS" else row["Value"]
        attributes.append({"type": kind, "category": "Network activity", "value": value, "to_ids": not shared,
                           "Tag": tags,
                           "comment": "; ".join(str(part) for part in (row.get("Domain"), row.get("Reason"),
                                                                       f"VPNDB: {row['VPNDB']}" if row.get("VPNDB") else "",
                                                                       "context (network / prefix)" if row["Type"] in ROUTING_TYPES
                                                                       else "shared exit" if shared else "")
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
    if ioc_type == "autonomous-system" and escaped.upper().removeprefix("AS").isdigit():
        return f"[autonomous-system:number = {int(escaped.upper().removeprefix('AS'))}]"
    if ioc_type in ("ipv4-prefix", "ipv6-prefix"):
        return f"[{ioc_type[:4]}-addr:value = '{escaped}']"
    return None


STIX_CONFIDENCE = {"High": 85, "Medium": 60, "Low": 30}


def _technique(mitre):
    """("T1583.001", "Acquire Infrastructure: Domains") from an alert's MITRE ATT&CK text, else None."""
    match = re.match(r"^(T\d{4}(?:\.\d{3})?)\s*(?:\((.*)\))?", str(mitre or "").strip())
    return (match.group(1), match.group(2) or match.group(1)) if match else None


def _malicious(group):
    """Alerts that justify calling an indicator malicious: not informational, not Low, at least Medium confidence."""
    if group is None or group.empty:
        return group
    keep = ~group["Threat Type"].isin(INFORMATIONAL_RULES)
    if "Severity" in group.columns:
        keep &= group["Severity"] != "Low"
    if "Confidence" in group.columns:
        keep &= group["Confidence"].isin(["High", "Medium"])
    return group[keep]


def to_stix_bundle(iocs, alerts, producer="DT Analytics & Detection", correlation=None):
    """
    STIX 2.1 bundle: an identity; one indicator per IOC, `malicious-activity` only when a Medium+ confidence,
    non-Low alert backs it (else `anomalous-activity`), with a confidence; an attack-pattern per ATT&CK technique of
    those alerts and an `indicates` relationship; an infrastructure object per infrastructure cluster; and a report.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity = {"type": "identity", "spec_version": "2.1", "id": _stix_id("identity", producer), "created": now, "modified": now,
                "name": producer, "identity_class": "system"}
    alerts_by_domain = {domain: group for domain, group in alerts.groupby("Domain")} \
        if alerts is not None and not alerts.empty else {}
    objects, patterns, relationships = [identity], {}, []
    for _, ioc in iocs.iterrows():
        pattern = _stix_pattern(ioc["Type"], ioc["Value"])
        routing = ioc["Type"] in ROUTING_TYPES
        if not pattern or (routing and ROUTING_FINDING not in str(ioc["Note"])):
            continue   # a network or prefix only as an indicator of a routing finding
        related = [alerts_by_domain[d] for d in str(ioc["Domain"]).split(", ") if d in alerts_by_domain]
        related = pd.concat(related) if related else pd.DataFrame(columns=["Threat Type", "Severity"])
        backing = _malicious(related) if not routing else related.iloc[0:0]   # a network is never malicious alone
        threats = sorted(set(related["Threat Type"]))
        best = backing["Confidence"].map(STIX_CONFIDENCE).max() if not backing.empty and "Confidence" in backing else None
        indicator = {
            "type": "indicator", "spec_version": "2.1", "id": _stix_id("indicator", f"{ioc['Type']}:{ioc['Value']}"),
            "created": now, "modified": now, "created_by_ref": identity["id"],
            "name": f"{ioc['Type']}: {ioc['Value']}", "pattern": pattern, "pattern_type": "stix", "valid_from": now,
            "indicator_types": ["malicious-activity"] if not backing.empty else
                               (["anomalous-activity"] if threats else ["unknown"]),
            "description": f"Related targets: {ioc['Domain']}. Sources: {ioc['Source']}."
                           + (f" Detections: {', '.join(threats)}." if threats else "")
                           + (f" Note: {ioc['Note']}" if ioc["Note"] else ""),
        }
        if best is not None and pd.notna(best):
            indicator["confidence"] = int(best)
        objects.append(indicator)
        for mitre in sorted(set(backing.get("MITRE ATT&CK", pd.Series(dtype=str)).astype(str))):
            technique = _technique(mitre)
            if not technique:
                continue
            if technique[0] not in patterns:
                patterns[technique[0]] = {
                    "type": "attack-pattern", "spec_version": "2.1", "id": _stix_id("attack-pattern", technique[0]),
                    "created": now, "modified": now, "name": technique[1],
                    "external_references": [{"source_name": "mitre-attack", "external_id": technique[0],
                                             "url": f"https://attack.mitre.org/techniques/{technique[0].replace('.', '/')}/"}],
                }
            relationships.append({
                "type": "relationship", "spec_version": "2.1",
                "id": _stix_id("relationship", f"{indicator['id']}>{technique[0]}"), "created": now, "modified": now,
                "relationship_type": "indicates", "source_ref": indicator["id"],
                "target_ref": patterns[technique[0]]["id"]})
    for cluster in (correlation.clusters if correlation is not None else []):
        objects.append({
            "type": "infrastructure", "spec_version": "2.1",
            "id": _stix_id("infrastructure", ",".join(cluster["Domains"])), "created": now, "modified": now,
            "created_by_ref": identity["id"], "name": f"Cluster {cluster['Cluster']}: {', '.join(cluster['Domains'][:5])}"
            + (" ..." if len(cluster["Domains"]) > 5 else ""), "infrastructure_types": ["unknown"],
            "description": f"{cluster['Strength']} cluster of {cluster['Size']} domains sharing "
                           + "; ".join(f"{kind} ({len(values)})" for kind, values in cluster["Shared Artifacts"].items()),
        })
    objects += list(patterns.values()) + relationships
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

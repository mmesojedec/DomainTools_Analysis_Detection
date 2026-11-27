"""
Data export for sharing with other teams: IOCs, the tables the lenses show and the raw collected records, as CSV or
NDJSON files (one file per table, zipped when there is more than one). No charts; timestamps are UTC.
"""
import io
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone

import pandas as pd

from core.cname import dataset_cname_map
from core.export import dataset_iocs
from core.lookup_queries import build_lookup_queries


@dataclass(frozen=True)
class ExportSet:
    key: str       # file name without extension
    group: str     # "IOCs", "Tables" or "Raw data"
    label: str
    help: str
    build: object  # (ExportContext) -> DataFrame | list of dicts (raw JSON records, NDJSON only)
    default: bool = False


@dataclass
class ExportContext:
    ds: object
    collected: object
    alerts: pd.DataFrame
    profiles: pd.DataFrame
    created: str = None


def _frame(value):
    return value if isinstance(value, pd.DataFrame) else pd.DataFrame()


def _cert_profiles(ds):
    from core import cert_anomalies as ca
    from core import cert_profile as cp
    certs = cp.certificates(ds.ssl)
    if certs.empty:
        return certs
    run = ca.cached_run(certs, getattr(ds, "ctl", None))
    found = run.anomalies()
    table = run.shapes()
    shapes = dict(zip(table["Hash"], table["Shape"]))
    rows = []
    for cert in certs.to_dict("records"):
        flags = cp.flags(cert, related=cp.related_certificates(cert, certs))
        own = ca.for_certificate(cert["Hash"], found)
        rows.append({"Domains": cp.text(cert.get("Domains")),
                     **{f"{section}: {label}": cp.text(cert.get(column)) for section, label, column in cp.FIELDS},
                     "Shape": shapes.get(cert["Hash"]) or "",
                     "Flags": " | ".join(f"{s}: {f}" for s, f in zip(flags["Severity"], flags["Finding"])),
                     "Anomalies": " | ".join(f"{s} ({c}): {f}" for s, c, f in
                                             zip(own["Severity"], own["Check"], own["Finding"]))})
    return pd.DataFrame(rows)


def _cert_families(ds):
    from core import cert_anomalies as ca
    from core import cert_profile as cp
    from core import cert_shape as shape
    certs = cp.certificates(ds.ssl)
    if certs.empty:
        return certs
    run = ca.cached_run(certs, getattr(ds, "ctl", None))
    families = shape.families(certs, run.anomalies(), run.shapes())
    return families.assign(Hashes=families["Hashes"].map(", ".join))


def _resolution(ds):
    from core import resolver
    return resolver.display(resolver.dataset_tree(ds)[0])


def _resolved_routing(ds):
    from core import resolver
    tree, _, routing = resolver.dataset_tree(ds)
    return resolver.resolved_routing(tree, routing, getattr(ds, "bgp_origins", None))


EXPORT_SETS = [
    ExportSet("iocs", "IOCs", "Indicators", "Domains, IPs, name servers and certificate hashes, with source and dates",
              lambda c: dataset_iocs(c.ds), default=True),
    ExportSet("certificate_hashes", "IOCs", "Certificate hashes by hostname",
              "Every certificate hash linked to a hostname (Hostname Inventory links)",
              lambda c: _frame(c.ds.hostname_certificates), default=True),
    ExportSet("detections", "Tables", "Detections", "Active alerts for the current filters (suppressed ones left out), "
              "with their structured evidence", lambda c: _frame(c.alerts), default=True),
    ExportSet("risk_profiles", "Tables", "Risk profiles", "Unified Risk, risk vectors and DIF per domain",
              lambda c: _frame(c.profiles)),
    ExportSet("hostname_inventory", "Tables", "Hostname inventory", "Every hostname with its flags, certificate and "
              "passive DNS dates, full history", lambda c: _frame(c.ds.hostname_inventory), default=True),
    ExportSet("cname_chains", "Tables", "CNAME chains", "Every CNAME in the analysis window with its target service, "
              "full chain and where it ends", lambda c: dataset_cname_map(c.ds)),
    ExportSet("certificate_profiles", "Tables", "Certificate profiles", "Every certificate once, every X.509 field "
              "(subject, issuer, validity, key, extensions, SANs, fingerprints), its shape, what stands out (flags) "
              "and its anomalies against the run's other certificates", lambda c: _cert_profiles(c.ds)),
    ExportSet("certificate_families", "Tables", "Certificate families", "Certificates of one shape (how they were "
              "made: issuer, key, validity band, extension layout, policy, serial length, SAN profile) with the "
              "analyzed domains they cover and their anomalies", lambda c: _cert_families(c.ds)),
    ExportSet("dns_resolution", "Tables", "DNS resolution", "Every current record of the DNS tree resolved to IP "
              "addresses, with its status, dangling targets and warnings (DNS resolution lens)",
              lambda c: _resolution(c.ds)),
    ExportSet("bgp_resolved", "Tables", "BGP routing of resolved addresses (BGPDB)", "Prefix, origin, RPKI / IRR and "
              "route collectors of the addresses the DNS resolution reached beyond the hosting IPs, with the records "
              "that reach them", lambda c: _resolved_routing(c.ds)),
    ExportSet("cname_reverse", "Tables", "Reverse CNAME", "Every name DNSDB saw pointing to a looked-up CNAME target "
              "(CNAME Chains lens)", lambda c: _frame(c.ds.cname_rdata)),
    ExportSet("vpndb_verdicts", "Tables", "VPN / proxy / Tor (VPNDB)", "VPNDB's verdict for every hosting IP it "
              "checked: category, provider, confidence, Tor role, sharing and IOC value", lambda c: _frame(c.ds.anonymizers)),
    ExportSet("vpndb_ranges", "Tables", "CIDR ranges (VPNDB)", "VPNDB's verdict for each CIDR target: providers and "
              "their shares, known exits, coverage, ASN, countries", lambda c: _frame(c.ds.prefixes)),
    ExportSet("vpndb_range_addresses", "Tables", "CIDR addresses (VPNDB)", "Addresses VPNDB reached in each CIDR target "
              "in the last 30 days, with their providers, pool and protocol", lambda c: _frame(c.ds.prefix_addresses)),
    ExportSet("vpndb_range_ips", "Tables", "CIDR IPs (VPNDB)", "Every address of the CIDR targets VPNDB knows exits "
              "in, one row per IP: category, provider, confidence, method, ASN, country, lists",
              lambda c: _frame(c.ds.range_ips)),
    ExportSet("vpndb_exit_weeks", "Tables", "Exit history (VPNDB)", "The weeks VPNDB holds evidence each exit was one "
              "(probe, scan, interpolated), with the provider", lambda c: _frame(c.ds.exit_weeks)),
    ExportSet("vpndb_neighbours", "Tables", "Neighbouring ranges (VPNDB)", "VPNDB's verdict on the /24 around each "
              "hosting IP that is not an exit: known exits, providers, coverage", lambda c: _frame(c.ds.neighbour_ranges)),
    ExportSet("vpndb_networks", "Tables", "Hosting networks (VPNDB)", "The VPN / proxy providers VPNDB knows on each "
              "Iris hosting ASN", lambda c: _frame(c.ds.hosting_asns)),
    ExportSet("vpndb_exit_neighbours", "Tables", "Other domains on dedicated exits", "Every name DNSDB saw on an exit "
              "VPNDB rates dedicated, and whether it is one of the run's domains", lambda c: _frame(c.ds.exit_neighbours)),
    ExportSet("bgp_ips", "Tables", "BGP routing per IP (BGPDB / RIPEstat)", "Each hosting IP's announced prefix, usual origin "
              "network, RPKI / IRR status, RIR, upstream and routing findings", lambda c: _bgp(c.ds, "ips")),
    ExportSet("bgp_findings", "Tables", "BGP routing findings (BGPDB / RIPEstat)", "Origin conflicts, unauthorized origins, new "
              "prefixes, young networks and thin routes, with their evidence", lambda c: _bgp(c.ds, "findings")),
    ExportSet("bgp_origins", "Tables", "BGP origins (BGPDB / RIPEstat)", "Every prefix and origin network BGPDB or RIPE RIS saw announcing "
              "the hosting IPs, with dates, collectors, RPKI, IRR and RIR", lambda c: _frame(c.ds.bgp_origins)),
    ExportSet("bgp_routes", "Tables", "AS paths (BGPDB / RIPEstat)", "Every AS path seen towards the run's prefixes",
              lambda c: _frame(c.ds.bgp_routes)),
    ExportSet("bgp_networks", "Tables", "BGP networks (BGPDB / RIPEstat)", "The origin and upstream networks: RIR registration, "
              "visibility, upstream and downstream counts", lambda c: _frame(c.ds.bgp_asns)),
    ExportSet("bgp_neighbours", "Tables", "More-specific prefixes (BGPDB / RIPEstat)", "Prefixes announced inside the run's "
              "prefixes and CIDR targets, and whether one of the run's own networks announces them", lambda c: _frame(c.ds.bgp_neighbours)),
    ExportSet("bgp_registration", "Tables", "IP registration (RIPEstat)", "Registry network object (net name, "
              "organisation, type, country, registration date) and abuse contact of each hosting IP",
              lambda c: _frame(c.ds.bgp_registration)),
    ExportSet("data_source_status", "Tables", "Data source status", "Outcome of every lookup (OK / Partial / Error)",
              lambda c: pd.DataFrame(getattr(c.collected, "statuses", []) or []).drop(columns="Request",
                                                                                   errors="ignore")),
    ExportSet("lookup_queries", "Tables", "Lookup queries", "Every lookup as a query, domaintools CLI or curl command",
              lambda c: build_lookup_queries(c.collected, c.created)),
    ExportSet("passive_dns", "Raw data", "Passive DNS records", "Raw passive DNS records in the analysis window",
              lambda c: _frame(c.ds.pdns_utc)),
    ExportSet("domain_history", "Raw data", "Domain History changes", "Registration, DNS and hosting changes in the "
              "analysis window", lambda c: _frame(c.ds.dh_utc)),
    ExportSet("certificates", "Raw data", "Certificates", "Certificate details (hashes, names, issuer, validity) in the "
              "analysis window", lambda c: _frame(c.ds.ssl_utc)),
    ExportSet("certificate_events", "Raw data", "Certificate events", "Hostnames and IPs where certificates were observed",
              lambda c: _frame(c.ds.cert_hostnames)),
    ExportSet("ct_logs", "Raw data", "CT log events", "Certificate Transparency log submissions", lambda c: _frame(c.ds.ctl)),
    ExportSet("certificate_cooccurrence", "Raw data", "Certificate co-occurrence",
              "Other domains, hostnames and IPs seen presenting the same certificates",
              lambda c: _frame(c.ds.cert_observations)),
    ExportSet("iris_investigate", "Raw data", "Iris Investigate responses", "The raw Iris Investigate record per domain "
              "(nested JSON: NDJSON only)", lambda c: [{"domain": d, **(r if isinstance(r, dict) else {"record": r})}
                                                       for d, r in (c.ds.enrichment or {}).items()]),
    ExportSet("vpndb_responses", "Raw data", "VPNDB responses", "Every VPNDB answer as received, with the request that "
              "got it (nested JSON: NDJSON only)", lambda c: _vpndb_responses(c.ds.vpndb_raw)),
]
def _bgp(ds, table):
    """The BGP page's computed tables (core.bgp): "ips" or "findings"."""
    from core import bgp
    origins = getattr(ds, "bgp_origins", None)
    if origins is None or origins.empty:
        return pd.DataFrame()
    found = bgp.findings(origins, ds.bgp_asns, ds.bgp_routes)
    return found if table == "findings" else bgp.ip_table(origins, ds.bgp_routes, found, ds.enrichment)


def _vpndb_responses(raw):
    """One record per VPNDB lookup (Raw Records → VPNDB Responses): endpoint, target, status, request and answer."""
    if raw is None or raw.empty:
        return []
    return [{"endpoint": row["Endpoint"], "target": row["Target"], "status": row["Status"],
             "request": json.loads(row["Request"] or "null"), "response": json.loads(row["Response"] or "null")}
            for row in raw.to_dict("records")]


SETS_BY_KEY = {s.key: s for s in EXPORT_SETS}
GROUPS = ["IOCs", "Tables", "Raw data"]


def _plain(value):
    """JSON-safe scalar: timestamps as ISO strings, missing values as None, numpy numbers as Python numbers."""
    if isinstance(value, (list, tuple, set)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, (pd.Timestamp, datetime)):
        return None if pd.isna(value) else value.isoformat()
    if value is None or (not isinstance(value, (str, bytes)) and pd.api.types.is_scalar(value) and pd.isna(value)):
        return None
    if hasattr(value, "item"):   # numpy scalar
        return value.item()
    return value


def records(data):
    if isinstance(data, pd.DataFrame):
        return [{str(k): _plain(v) for k, v in row.items()} for row in data.to_dict(orient="records")]
    return [_plain(row) for row in data]


def to_ndjson(data):
    return "".join(json.dumps(row, ensure_ascii=False, default=str) + "\n" for row in records(data))


def to_csv(frame):
    """CSV with lists and nested values written as JSON, so nothing is lost or split across columns."""
    out = frame.copy()
    for col in out.columns:
        if out[col].map(lambda v: isinstance(v, (list, tuple, dict, set))).any():
            out[col] = out[col].map(lambda v: json.dumps(_plain(v), ensure_ascii=False, default=str)
                                    if isinstance(v, (list, tuple, dict, set)) else v)
        elif pd.api.types.is_datetime64_any_dtype(out[col]):
            out[col] = out[col].map(lambda v: v.isoformat() if pd.notna(v) else "")
    return out.to_csv(index=False)


def _chosen_data(context, keys, fmt):
    """(file name, data) for the chosen sets that have rows; nested raw records are always NDJSON."""
    for key in keys:
        data = SETS_BY_KEY[key].build(context)
        if data is None or len(data) == 0:
            continue
        yield (f"{key}.csv" if fmt == "csv" and isinstance(data, pd.DataFrame) else f"{key}.ndjson"), data


def export_counts(context, keys, fmt):
    """{file name: rows} without formatting anything, for the preview before downloading."""
    return {name: len(data) for name, data in _chosen_data(context, keys, fmt)}


def export_files(context, keys, fmt):
    """({file name: text}, {file name: rows}) for the chosen sets."""
    files, counts = {}, {}
    for name, data in _chosen_data(context, keys, fmt):
        files[name] = to_csv(data) if name.endswith(".csv") else to_ndjson(data)
        counts[name] = len(data)
    return files, counts


def manifest(context, counts, fmt):
    window = getattr(context.ds, "window", None)
    return {
        "exported": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_created": context.created,
        "targets": list(getattr(context.collected, "targets", []) or []),
        "selected_domains": list(getattr(context.ds, "selected_domains", []) or []),
        "analysis_window": getattr(window, "label", None),
        "timestamps": "UTC",
        "format": fmt,
        "files": counts,   # file name -> rows
    }


def build_zip(files, meta):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, text in files.items():
            archive.writestr(name, text)
        archive.writestr("manifest.json", json.dumps(meta, indent=2))
    return buffer.getvalue()

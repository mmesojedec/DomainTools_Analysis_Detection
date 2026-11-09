"""Offline datasets: save everything a live run collected, then re-analyze it later without any API calls.

Format (no pickle - loading a dataset never executes code):
    dt_offline/<dataset_id>/manifest.json          metadata (targets, provider, collection settings, sizes, linked run)
    dt_offline/<dataset_id>/data.json.gz           non-tabular data (enrichment, coverage, statuses, targets)
    dt_offline/<dataset_id>/frames/<name>.json.gz  each DataFrame in pandas' self-describing "table" JSON format
"""
import dataclasses
import gzip
import io
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone

import pandas as pd

from config import (
    CERT_CTL_LIMIT,
    CERT_EVENTS_LOOKBACK_DAYS,
    CERT_EVENTS_MAX_RECORDS,
    CERT_SEARCH_MAX_RECORDS,
    CIDR_ADDRESSES_PER_RANGE,
    CIDR_IP_CHECK_MAX,
    CIDR_IP_CHECK_TOTAL,
    CIDR_MAX_RANGES,
    CNAME_CHASE_MAX_STEPS,
    CNAME_CHASE_RECORD_LIMIT,
    CNAME_RDATA_RECORD_LIMIT,
    DNSDB_DEFAULT_LIMIT,
    DOMAIN_HISTORY_MAX_CHANGES,
    IRIS_INVESTIGATE_BATCH_SIZE,
    IRIS_PDNS_LIMIT,
    MAX_OFFLINE_DATASETS,
    OFFLINE_DIR,
    PIVOT_IP_RECORD_LIMIT,
    SEED_MAX_CERTIFICATES,
    SEED_MAX_TARGETS,
    VPNDB_ASN_MAX,
    VPNDB_HISTORY_MAX,
    VPNDB_NEIGHBOUR_MAX,
    VPNDB_REVERSE_LIMIT,
    VPNDB_REVERSE_MAX,
)
from core.helpers import lookup_name
from core.persistence import load_settings, save_setting
from integrations.collector import CollectedData

OFFLINE_SCHEMA = 1
_ID_RE = re.compile(r"^\d{8}T\d{6}\d*Z$")


def _dataset_dir(dataset_id):
    if not _ID_RE.match(str(dataset_id)):
        raise ValueError(f"Invalid offline dataset id: {dataset_id!r}")
    return OFFLINE_DIR / dataset_id


def offline_retention():
    try:
        return max(1, min(200, int(load_settings().get("offline_retention", MAX_OFFLINE_DATASETS))))
    except (TypeError, ValueError):
        return MAX_OFFLINE_DATASETS


def set_offline_retention(keep):
    save_setting("offline_retention", max(1, min(200, int(keep))))


def _write_gz(path, text):
    with gzip.open(path, "wt", encoding="utf-8", compresslevel=6) as f:
        f.write(text)


def _read_gz(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return f.read()


def _frame_to_json(frame):
    return frame.to_json(orient="table", date_format="iso", date_unit="us", default_handler=str)


def _frame_from_json(text):
    frame = pd.read_json(io.StringIO(text), orient="table")
    return frame.reset_index(drop=True)


def _dir_size(path):
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def default_name(when=None):
    """Name of a dataset saved without one: `dt_analysis 2026-11-04 09:30 UTC`."""
    return f"dt_analysis {(when or datetime.now(timezone.utc)):%Y-%m-%d %H:%M} UTC"


def save_offline_dataset(collected, collection_settings=None, run_key=None, name=""):
    """Saves a CollectedData bundle (named `default_name()` unless `name` is given). Returns the manifest."""
    now = datetime.now(timezone.utc)
    dataset_id = now.strftime("%Y%m%dT%H%M%S%fZ")
    name = str(name or "").strip() or default_name(now)
    OFFLINE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(OFFLINE_DIR, 0o700)
    staging = tempfile.mkdtemp(prefix=f".{dataset_id}.", dir=OFFLINE_DIR)
    try:
        frames_dir = os.path.join(staging, "frames")
        os.makedirs(frames_dir)
        frame_rows, other = {}, {}
        for item in dataclasses.fields(CollectedData):
            value = getattr(collected, item.name)
            if isinstance(value, pd.DataFrame):
                _write_gz(os.path.join(frames_dir, f"{item.name}.json.gz"), _frame_to_json(value))
                frame_rows[item.name] = int(len(value))
            else:
                other[item.name] = value
        _write_gz(os.path.join(staging, "data.json.gz"), json.dumps(other, default=str))
        manifest = {
            "schema": OFFLINE_SCHEMA, "id": dataset_id, "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "name": str(name or "")[:120], "targets": list(collected.targets), "seeds": list(collected.seed_inputs),
            "host_focus": dict(collected.host_focus),
            "provider": collected.pdns_provider,
            "settings": collection_settings or {}, "run_key": run_key, "run_id": None, "frames": frame_rows,
        }
        with open(os.path.join(staging, "manifest.json"), "w") as f:
            json.dump(manifest, f, indent=2, default=str)
        os.chmod(staging, 0o700)
        os.replace(staging, _dataset_dir(dataset_id))
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    manifest["size_bytes"] = _dir_size(_dataset_dir(dataset_id))
    apply_offline_retention()
    return manifest


def _read_manifest(path):
    try:
        with open(path / "manifest.json") as f:
            manifest = json.load(f)
    except (OSError, ValueError):
        return None
    manifest["size_bytes"] = _dir_size(path)
    return manifest


def list_offline_datasets():
    """Manifests of saved datasets, newest first."""
    if not OFFLINE_DIR.exists():
        return []
    manifests = [_read_manifest(d) for d in OFFLINE_DIR.iterdir() if d.is_dir() and _ID_RE.match(d.name)]
    return sorted((m for m in manifests if m), key=lambda m: m["id"], reverse=True)


def load_offline_dataset(dataset_id):
    """Rebuilds the CollectedData of a saved dataset. Returns (collected, manifest)."""
    path = _dataset_dir(dataset_id)
    manifest = _read_manifest(path)
    if manifest is None:
        raise FileNotFoundError(dataset_id)
    other = json.loads(_read_gz(path / "data.json.gz"))
    values = {}
    for item in dataclasses.fields(CollectedData):
        frame_path = path / "frames" / f"{item.name}.json.gz"
        if frame_path.exists():
            values[item.name] = _frame_from_json(_read_gz(frame_path))
        elif item.name in other:
            values[item.name] = other[item.name]
    _rename_lookups(values)
    return CollectedData(**values), manifest


def _rename_lookups(values):
    """Record-type lookups saved as "... Supplement" / "... supplement" get their current "Lookup" names."""
    values["statuses"] = [{**row, "Source": lookup_name(row.get("Source"))} for row in values.get("statuses") or []]
    pdns = values.get("pdns")
    if isinstance(pdns, pd.DataFrame) and "Collection" in pdns.columns:
        pdns["Collection"] = pdns["Collection"].map(lookup_name)


def incremental_base(run_key, provider="DNSDB Scout", limit=None):
    """
    The newest offline dataset of this target list (`run_key`) collected with `provider` (and the same DNSDB `limit`,
    when given), as {"frame": its passive DNS, "created", "name", "id"}; None when there is none. An incremental
    passive DNS lookup builds on it (integrations.collector.collect_pdns).
    """
    for manifest in list_offline_datasets():   # newest first
        settings = manifest.get("settings") or {}
        if manifest.get("run_key") != run_key or manifest.get("provider") != provider:
            continue
        if limit is not None and settings.get("dnsdb_limit") not in (None, limit):
            continue
        frame_path = _dataset_dir(manifest["id"]) / "frames" / "pdns.json.gz"
        try:
            frame = _frame_from_json(_read_gz(frame_path))
        except (OSError, ValueError):
            continue
        if "Collection" in frame.columns:
            frame["Collection"] = frame["Collection"].map(lookup_name)
        return {"frame": frame, "created": manifest.get("created"), "name": manifest.get("name"), "id": manifest["id"]}
    return None


def update_offline_manifest(dataset_id, **fields):
    path = _dataset_dir(dataset_id) / "manifest.json"
    with open(path) as f:
        manifest = json.load(f)
    allowed = {k: v for k, v in fields.items() if k in ("name", "run_id", "note")}
    if "name" in allowed:
        allowed["name"] = str(allowed["name"] or "").strip()[:120]
    if "note" in allowed:
        allowed["note"] = str(allowed["note"] or "").strip()[:2000]
    manifest.update(allowed)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(manifest, f, indent=2, default=str)
    os.replace(tmp, path)
    return manifest


def delete_offline_dataset(dataset_id):
    shutil.rmtree(_dataset_dir(dataset_id), ignore_errors=True)


def apply_offline_retention(keep=None):
    """Deletes the oldest datasets beyond the retention limit. Returns how many were removed."""
    keep = keep or offline_retention()
    datasets = list_offline_datasets()
    removed = datasets[keep:]
    for manifest in removed:
        delete_offline_dataset(manifest["id"])
    return len(removed)


def format_size(num_bytes):
    size = float(num_bytes or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def _on(flag, text):
    return text if flag else "Off"


def _history_limit(s):
    """The Domain History period and Max changes a dataset's run used (older datasets: the default)."""
    cap = s.get("history_max", DOMAIN_HISTORY_MAX_CHANGES)
    period = f"Changes of the last {int(s['history_days']):,} days, " if s.get("history_days") else ""
    if not cap:
        return (period or "") + "no limit"
    return (period + "up to " if period else "Up to ") + f"{int(cap):,} changes per domain"


# What each part of a dataset holds, where it came from, and the limit its lookups ran with (`s`: the run's
# collection settings from the manifest; older datasets fall back to the defaults)
PARTS = {
    "targets": ("Targets", "Input", "The analyzed domains, IPs and CIDR ranges", lambda s: "–"),
    "enrichment": ("Iris Investigate records", "Iris Investigate", "Registration, current hosting, risk score, "
                   "website and trackers per domain", lambda s: f"Batches of {IRIS_INVESTIGATE_BATCH_SIZE} domains; current data"),
    "dh": ("Domain History", "DomainTools API", "Registration, DNS and certificate changes",
           lambda s: _history_limit(s)),
    "risk": ("Risk scores", "Iris Investigate", "Risk score and its components per domain (from the Iris records)",
             lambda s: "One score per domain; no extra query"),
    "pdns": ("Passive DNS", "DNSDB Scout / Iris pDNS", "Every DNS record seen for the domains and subdomains",
             lambda s: (f"Up to {int(s.get('dnsdb_limit') or DNSDB_DEFAULT_LIMIT):,} records per domain"
                        if s.get("pdns_provider", "DNSDB Scout") == "DNSDB Scout" else
                        f"Up to {IRIS_PDNS_LIMIT:,} records per domain")
             + (f"; TXT lookup: latest {s['txt_records']} per domain" if s.get("txt_records") else "")
             + ("; CAA lookup" if s.get("caa_lookup") else "")
             + ("; CNAME lookup" if s.get("cname_lookup") else "")),
    "pdns_coverage": ("Passive DNS coverage", "DNSDB Scout / Iris pDNS", "How much of each domain the lookups "
                      "returned (complete or cut off at the limit)", lambda s: "–"),
    "ssl": ("Certificates", "Certificate API", "Certificates naming the domains (search)",
            lambda s: f"Up to {CERT_SEARCH_MAX_RECORDS:,} certificates per target"),
    "ssl_active": ("Active certificates", "Iris Investigate", "Certificates on the domains' websites now",
                   lambda s: "As reported by Iris"),
    "cert_hostnames": ("Certificate events (hostnames)", "Certificate API", "Hostnames seen with the certificates",
                       lambda s: f"Up to {CERT_EVENTS_MAX_RECORDS:,} events per domain, last "
                                 f"{CERT_EVENTS_LOOKBACK_DAYS} days"),
    "cert_observations": ("Certificate events (observations)", "Certificate API", "Where and when each certificate "
                          "was seen", lambda s: f"Up to {CERT_EVENTS_MAX_RECORDS:,} events per domain or IP"),
    "ctl": ("CT log entries", "Certificate API", "Certificate Transparency entries of the newest certificates",
            lambda s: _on(s.get("include_ct", True), f"{CERT_CTL_LIMIT} entries per certificate, newest "
                                                     f"{s.get('ct_max_hashes', 10)} certificates")),
    "ip_pivots": ("IP pivots", "DNSDB Scout", "Other names on the hosting IPs",
                  lambda s: _on(s.get("pivot_ips"), f"Up to {s.get('pivot_max_ips', 10)} IPs, "
                                                    f"{PIVOT_IP_RECORD_LIMIT:,} records each")),
    "cname_chases": ("CNAME chases", "DNSDB Scout", "Each CNAME followed to its final address",
                     lambda s: f"Up to {CNAME_CHASE_MAX_STEPS} names per chain, {CNAME_CHASE_RECORD_LIMIT} records "
                               "each"),
    "cname_rdata": ("Reverse CNAME", "DNSDB Scout", "Other names pointing to the same CNAME targets",
                    lambda s: f"Up to {CNAME_RDATA_RECORD_LIMIT:,} names per lookup"),
    "anonymizers": ("VPNDB verdicts", "VPNDB", "VPN, proxy and Tor verdict per hosting IP",
                    lambda s: _on(s.get("vpndb_check", True), f"Up to {s.get('vpndb_max_ips', 500)} IPs, "
                                                              f"{s.get('vpndb_details', 50)} full verdicts")),
    "exit_weeks": ("VPNDB exit history", "VPNDB", "Weeks each exit was seen working as an exit",
                   lambda s: _on(s.get("vpndb_check", True), f"Up to {VPNDB_HISTORY_MAX} exits")),
    "neighbour_ranges": ("VPNDB /24 neighbourhood", "VPNDB", "Known exits in the /24 around each hosting IP",
                         lambda s: _on(s.get("vpndb_context", True), f"Up to {VPNDB_NEIGHBOUR_MAX} ranges")),
    "hosting_asns": ("VPNDB hosting networks", "VPNDB", "VPN / proxy providers on the hosting networks",
                     lambda s: _on(s.get("vpndb_context", True), f"Up to {VPNDB_ASN_MAX} networks")),
    "exit_neighbours": ("Other domains on dedicated exits", "DNSDB Scout", "Names seen on exits used by few "
                        "customers", lambda s: _on(s.get("vpndb_context", True), f"Up to {VPNDB_REVERSE_MAX} exits, "
                                                                                f"{VPNDB_REVERSE_LIMIT:,} records each")),
    "prefixes": ("CIDR ranges", "VPNDB", "VPNDB verdict per CIDR target", lambda s: f"Up to {CIDR_MAX_RANGES} ranges"),
    "prefix_addresses": ("CIDR addresses", "VPNDB", "Addresses VPNDB reached in each range",
                         lambda s: f"Up to {CIDR_ADDRESSES_PER_RANGE} per range"),
    "range_ips": ("CIDR IPs", "VPNDB", "Every address of the CIDR targets, checked",
                  lambda s: f"Up to {CIDR_IP_CHECK_MAX:,} per range, {CIDR_IP_CHECK_TOTAL:,} in all"),
    "tor_overview": ("Tor network overview", "VPNDB", "The Tor network at a glance", lambda s: "One per run"),
    "vpndb_raw": ("VPNDB responses", "VPNDB", "Every VPNDB answer as received", lambda s: "–"),
    "seeds": ("Certificate inputs", "Certificate API", "What each certificate input found",
              lambda s: f"Up to {SEED_MAX_CERTIFICATES} certificates per input"),
    "derived": ("Derived targets", "Certificate API", "Targets picked from the certificate inputs",
                lambda s: f"At most {SEED_MAX_TARGETS} per run"),
    "statuses": ("Lookup status", "All sources", "Outcome of every lookup (Data sources)", lambda s: "–"),
}
BREAKDOWN_COLUMNS = ["Data", "Source", "Holds", "Records", "Size", "Bytes", "Limit applied"]


def _records(value, name=""):
    if name == "tor_overview":   # one overview, not its keys
        return 1 if value else 0
    if isinstance(value, pd.DataFrame):
        return len(value)
    return len(value) if isinstance(value, (list, dict)) else (1 if value else 0)


def dataset_breakdown(dataset_id):
    """
    One row (BREAKDOWN_COLUMNS) per part of a saved dataset: records, compressed size on disk (a frame's file; a
    non-tabular part measured as it is stored, gzipped JSON) and the limit its lookups ran with; plus the lookups that
    stopped at a limit (Partial rows of the lookup status). Reads only that dataset; works for older datasets too.
    """
    path = _dataset_dir(dataset_id)
    manifest = _read_manifest(path) or {}
    settings = manifest.get("settings") or {}
    other = json.loads(_read_gz(path / "data.json.gz"))
    rows = []
    for name, (label, source, holds, limit) in PARTS.items():
        frame_path = path / "frames" / f"{name}.json.gz"
        if frame_path.exists():
            records, size = (manifest.get("frames") or {}).get(name, 0), frame_path.stat().st_size
        elif name in other:
            records, size = _records(other[name], name), len(gzip.compress(json.dumps(other[name], default=str).encode(), 6))
        else:
            continue
        if source == "DNSDB Scout / Iris pDNS":   # the run's passive DNS provider
            source = settings.get("pdns_provider") or manifest.get("provider") or source
        rows.append({"Data": label, "Source": source, "Holds": holds, "Records": int(records),
                     "Size": format_size(size), "Bytes": size, "Limit applied": limit(settings)})
    statuses = pd.DataFrame(other.get("statuses") or [])
    capped = statuses[statuses["Status"] == "Partial"][["Source", "Target", "Detail"]] \
        if not statuses.empty and "Status" in statuses else pd.DataFrame(columns=["Source", "Target", "Detail"])
    return pd.DataFrame(rows, columns=BREAKDOWN_COLUMNS), capped.reset_index(drop=True)

"""Local persistence: alert suppressions, saved settings, and run snapshots for run-to-run diffs."""
import hashlib
import json
import os
import pathlib
import re
import tempfile
import uuid
from datetime import datetime, timezone

import pandas as pd

from config import MAX_RUN_SNAPSHOTS, RUNS_DIR, SETTINGS_FILE, SUPPRESSIONS_FILE
from core.helpers import extract_ip_addresses
from core.network_intel import record_types
from core.run_history import (
    ALERT_FIELDS,
    PROFILE_FIELDS,
    alert_key_set,
    run_summary,
    snapshot_alerts,
    snapshot_domains,
    summarize_alerts,
)
from integrations.enrichment import extract_iris_profile, extract_web_trackers


def _utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    """Atomic write (temp file + rename) so a crash never leaves a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def load_settings(path=None):
    return load_json(path or SETTINGS_FILE, {})


def save_setting(key, value, path=None):
    path = path or SETTINGS_FILE
    settings = load_settings(path)
    if settings.get(key) != value:
        settings[key] = value
        save_json(path, settings)


# ---------------------------------------------------------------------------
# Suppressions
# ---------------------------------------------------------------------------

def load_suppressions(path=None):
    data = load_json(path or SUPPRESSIONS_FILE, [])
    return data if isinstance(data, list) else []


def add_suppression(domain, threat_type, note="", path=None):
    """Suppresses `threat_type` for `domain` ('*' = all domains). Returns the new entry."""
    path = path or SUPPRESSIONS_FILE
    entries = load_suppressions(path)
    for entry in entries:
        if entry["domain"] == domain and entry["threat_type"] == threat_type:
            return entry
    entry = {"id": uuid.uuid4().hex[:12], "domain": domain, "threat_type": threat_type, "note": note, "created": _utc_now()}
    entries.append(entry)
    save_json(path, entries)
    return entry


def remove_suppression(entry_id, path=None):
    path = path or SUPPRESSIONS_FILE
    save_json(path, [e for e in load_suppressions(path) if e.get("id") != entry_id])


def apply_suppressions(alerts, suppressions):
    """Splits alerts into (active, suppressed)."""
    if alerts.empty or not suppressions:
        return alerts, alerts.iloc[0:0]
    mask = pd.Series(False, index=alerts.index)
    for entry in suppressions:
        domain_match = alerts["Domain"] == entry["domain"] if entry["domain"] != "*" else True
        type_match = alerts["Threat Type"] == entry["threat_type"] if entry["threat_type"] != "*" else True
        mask |= domain_match & type_match
    return alerts[~mask], alerts[mask]


# ---------------------------------------------------------------------------
# Run snapshots & diffs
# ---------------------------------------------------------------------------

def target_set_key(targets):
    return hashlib.sha256("\n".join(sorted(set(targets))).encode()).hexdigest()[:16]


def collect_run_artifacts(collected):
    """Per-domain artifact sets: IPs, name servers, MX hosts, certificate hashes, web trackers, subdomain hostnames."""
    artifacts = {}

    def add(domain, kind, value):
        value = str(value or "").strip().lower().rstrip(".")
        if value and value != "nan":
            artifacts.setdefault(domain, {}).setdefault(kind, set()).add(value)

    pdns = collected.pdns
    if pdns is not None and not pdns.empty and "RRName" in pdns.columns:
        for domain, name in zip(pdns["Domain"], pdns["RRName"].astype(str)):
            if name.strip().lower().rstrip(".") != str(domain).lower():
                add(domain, "Hostname", name)
    for frame in (collected.pdns, collected.dh):
        if frame is None or frame.empty:
            continue
        values = frame["Value"] if "Value" in frame.columns else frame.get("After", pd.Series(dtype=str))
        types = record_types(frame)
        for domain, rtype, value in zip(frame["Domain"], types, values.astype(str)):
            if rtype in ("A", "AAAA", "IP", "A RECORD"):
                for ip in extract_ip_addresses(value):
                    add(domain, "IP", ip)
            elif rtype in ("NS", "NAME_SERVER", "MX"):
                for line in value.split("\n"):
                    add(domain, "Name Server" if rtype != "MX" else "MX", line.split()[-1] if line.split() else "")
    for domain, obj in (collected.enrichment or {}).items():
        profile = extract_iris_profile(obj)
        for entry in profile["ips"]:
            add(domain, "IP", entry["ip"])
        for host in profile["name_servers"]:
            add(domain, "Name Server", host)
        for tracker in extract_web_trackers(obj):
            add(domain, "Web Tracker", f"{tracker['Platform']}: {tracker['Code']}")
    for frame in (collected.ssl, collected.ssl_active):
        if frame is not None and not frame.empty and "Hash" in frame.columns:
            for domain, value in zip(frame["Domain"], frame["Hash"]):
                add(domain, "Certificate", value)
    return {dom: {kind: sorted(vals) for kind, vals in kinds.items()} for dom, kinds in artifacts.items()}


SNAPSHOT_SCHEMA = 2
_KEY_RE = re.compile(r"^[0-9a-f]{16}$")
_RUN_ID_RE = re.compile(r"^\d{8}T\d{6}\d*Z$")


def _run_dir(key):
    if not _KEY_RE.match(str(key)):
        raise ValueError(f"Invalid target-set key: {key!r}")
    return RUNS_DIR / key


def _run_path(key, run_id):
    if not _RUN_ID_RE.match(str(run_id)):
        raise ValueError(f"Invalid run id: {run_id!r}")
    return _run_dir(key) / f"{run_id}.json"


def run_retention():
    """Snapshots kept per target list (settings override of MAX_RUN_SNAPSHOTS)."""
    try:
        return max(1, min(500, int(load_settings().get("run_retention", MAX_RUN_SNAPSHOTS))))
    except (TypeError, ValueError):
        return MAX_RUN_SNAPSHOTS


def set_run_retention(keep):
    save_setting("run_retention", max(1, min(500, int(keep))))


def _alert_records(alerts):
    if alerts is None or alerts.empty:
        return []
    columns = [c for c in ALERT_FIELDS if c in alerts.columns]
    frame = alerts[columns].drop_duplicates(subset=[c for c in ("Domain", "Threat Type", "Threat Logic") if c in columns])
    return json.loads(frame.to_json(orient="records"))  # native JSON types (no numpy scalars), NaN -> null


def _profile_records(profiles):
    if profiles is None or profiles.empty:
        return []
    columns = [c for c in PROFILE_FIELDS if c in profiles.columns]
    return json.loads(profiles[columns].to_json(orient="records"))


def save_snapshot(key, targets, artifacts, alerts, window_label=None, profiles=None, name="", note="", seeds=None,
                  host_focus=None, parent=None, queries=None):
    """
    Saves a v2 run snapshot (alerts with severity / confidence, per-domain risk and DIF) and applies retention.
    `parent` ({"id": run id, "via": what led here}) links a run started from another run's lead (hunt tree).
    `queries` ({product or service: API queries}) is what the run cost.
    """
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    alert_rows = _alert_records(alerts)
    profile_rows = _profile_records(profiles)
    summary = summarize_alerts(pd.DataFrame(alert_rows, columns=ALERT_FIELDS))
    summary["max_unified_risk"] = max((p["Unified Risk"] for p in profile_rows if p.get("Unified Risk") is not None), default=None)
    snapshot = {
        "schema": SNAPSHOT_SCHEMA, "id": run_id, "created": _utc_now(), "name": name, "note": note,
        "targets": sorted(set(targets)), "seeds": list(seeds or []),
        "host_focus": dict(host_focus or {}), "window": window_label, "artifacts": artifacts,
        "alerts": alert_rows, "profiles": profile_rows, "summary": summary,
    }
    if queries is not None:
        snapshot["queries"] = {str(k): int(v) for k, v in queries.items()}
    if parent:
        snapshot["parent"] = {"id": parent.get("id"), "via": str(parent.get("via") or "")[:200]}
    save_json(_run_path(key, run_id), snapshot)
    apply_retention(key)
    return snapshot


def apply_retention(key, keep=None):
    """Deletes the oldest snapshots beyond the retention limit. Returns how many were removed."""
    keep = keep or run_retention()
    files = sorted(_run_dir(key).glob("*.json"))
    removed = files[:-keep] if len(files) > keep else []
    for old in removed:
        old.unlink(missing_ok=True)
    return len(removed)


def _load_snapshot_file(path):
    snapshot = load_json(path, None)
    if isinstance(snapshot, dict):
        snapshot.setdefault("id", path.stem)
        snapshot.setdefault("schema", 1)
    return snapshot


def load_runs(key):
    """All snapshots for a target list, oldest first."""
    run_dir = _run_dir(key)
    if not run_dir.exists():
        return []
    return [s for s in (_load_snapshot_file(f) for f in sorted(run_dir.glob("*.json"))) if s]


def load_run(key, run_id):
    path = _run_path(key, run_id)
    return _load_snapshot_file(path) if path.exists() else None


def load_latest_snapshot(key):
    runs = load_runs(key)
    return runs[-1] if runs else None


_ALL_RUNS_CACHE = {"signature": None, "runs": []}


def _runs_signature():
    if not RUNS_DIR.exists():
        return ()
    return tuple(sorted((str(f), f.stat().st_mtime_ns, f.stat().st_size)
                        for d in RUNS_DIR.iterdir() if d.is_dir() and _KEY_RE.match(d.name) for f in d.glob("*.json")))


def load_all_runs():
    """Every saved run across all target lists as (target_set_key, snapshot), oldest first. Cached until files change."""
    signature = _runs_signature()
    if signature != _ALL_RUNS_CACHE["signature"]:
        runs = []
        for path_str, _, _ in signature:
            path = pathlib.Path(path_str)
            snapshot = _load_snapshot_file(path)
            if snapshot:
                runs.append((path.parent.name, snapshot))
        _ALL_RUNS_CACHE.update(signature=signature, runs=sorted(runs, key=lambda item: str(item[1].get("created"))))
    return list(_ALL_RUNS_CACHE["runs"])


def runs_before(created, domains=None):
    """Snapshots (any target list) saved before `created`, optionally only those covering one of `domains`."""
    cutoff = pd.to_datetime(created, errors="coerce", utc=True)
    selected = []
    for _, snapshot in load_all_runs():
        when = pd.to_datetime(snapshot.get("created"), errors="coerce", utc=True)
        if pd.notna(cutoff) and pd.notna(when) and when >= cutoff:
            continue
        if domains and not (snapshot_domains(snapshot) & set(domains)):
            continue
        selected.append(snapshot)
    return selected


def list_target_sets():
    """Target lists with saved runs, most recently analyzed first."""
    if not RUNS_DIR.exists():
        return []
    sets = []
    for run_dir in RUNS_DIR.iterdir():
        if not run_dir.is_dir() or not _KEY_RE.match(run_dir.name):
            continue
        files = sorted(run_dir.glob("*.json"))
        if not files:
            continue
        latest = _load_snapshot_file(files[-1]) or {}
        sets.append({"key": run_dir.name, "targets": latest.get("targets", []), "seeds": latest.get("seeds", []),
                     "runs": len(files), "latest": latest.get("created")})
    return sorted(sets, key=lambda s: str(s["latest"]), reverse=True)


def list_runs(key):
    """Run metadata rows (newest first) for the history table."""
    rows = []
    for snapshot in reversed(load_runs(key)):
        summary = run_summary(snapshot)
        rows.append({
            "id": snapshot["id"], "created": snapshot.get("created"), "name": snapshot.get("name") or "",
            "note": snapshot.get("note") or "", "window": snapshot.get("window") or "", "targets": snapshot.get("targets", []),
            "schema": snapshot.get("schema", 1), "alerts": summary.get("alerts", 0), "by_severity": summary.get("by_severity", {}),
            "max_unified_risk": summary.get("max_unified_risk"),
            "queries": sum((snapshot.get("queries") or {}).values()) if "queries" in snapshot else None,
        })
    return rows


def update_run_meta(key, run_id, name=None, note=None):
    path = _run_path(key, run_id)
    snapshot = _load_snapshot_file(path)
    if snapshot is None:
        raise FileNotFoundError(run_id)
    if name is not None:
        snapshot["name"] = name.strip()[:120]
    if note is not None:
        snapshot["note"] = note.strip()[:2000]
    save_json(path, snapshot)
    return snapshot


def delete_run(key, run_id):
    _run_path(key, run_id).unlink(missing_ok=True)


def delete_target_set(key):
    run_dir = _run_dir(key)
    for path in run_dir.glob("*.json"):
        path.unlink(missing_ok=True)
    try:
        run_dir.rmdir()
    except OSError:
        pass


def export_run_json(key, run_id):
    return json.dumps(load_run(key, run_id), indent=2, default=str)


def new_alert_mask(alerts, previous_snapshot):
    """True for alerts whose (domain, threat type) is not present in the previous snapshot."""
    if alerts.empty or not previous_snapshot:
        return pd.Series(False, index=alerts.index)
    previous = alert_key_set(snapshot_alerts(previous_snapshot))
    return pd.Series([k not in previous for k in zip(alerts["Domain"].astype(str), alerts["Threat Type"].astype(str))],
                     index=alerts.index)


# ---------------------------------------------------------------------------
# Watched target lists
# ---------------------------------------------------------------------------

WATCHES_SETTING = "watched_targets"   # [{"name", "targets", "created"}] in dt_settings.json


def load_watches(path=None):
    watches = load_settings(path).get(WATCHES_SETTING)
    return [w for w in watches if isinstance(w, dict) and w.get("targets")] if isinstance(watches, list) else []


def save_watch(name, targets, path=None):
    """Adds or replaces (same target list) a watched target list. Returns the saved entry."""
    targets = sorted(set(targets))
    entry = {"name": (name or ", ".join(targets[:3])).strip()[:80], "targets": targets, "created": _utc_now()}
    watches = [w for w in load_watches(path) if sorted(set(w["targets"])) != targets]
    save_setting(WATCHES_SETTING, watches + [entry], path)
    return entry


def remove_watch(targets, path=None):
    targets = sorted(set(targets))
    save_setting(WATCHES_SETTING, [w for w in load_watches(path) if sorted(set(w["targets"])) != targets], path)


def find_watch(targets, path=None):
    targets = sorted(set(targets))
    return next((w for w in load_watches(path) if sorted(set(w["targets"])) == targets), None)

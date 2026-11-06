"""Run history analytics: snapshot normalization, run-to-run comparison, and alert lifecycle across runs."""
from dataclasses import dataclass, field

import pandas as pd

ALERT_FIELDS = ["Domain", "Threat Type", "Severity", "Confidence", "Category", "MITRE ATT&CK", "Threat Logic"]
ALERT_KEY = ["Domain", "Threat Type"]   # stable across runs (logic text contains counts and dates that change)
PROFILE_FIELDS = ["Domain", "Unified Risk", "Base Domain Risk Score", "DIF Fingerprint"]
SEVERITY_ORDER = ["Critical", "High", "Medium-High", "Medium", "Low"]


def snapshot_alerts(snapshot):
    """Alerts of a snapshot as a DataFrame. Legacy (v1) snapshots stored only [domain, threat type, logic]."""
    rows = (snapshot or {}).get("alerts") or []
    records = []
    for row in rows:
        if isinstance(row, dict):
            records.append({k: row.get(k) for k in ALERT_FIELDS})
        elif isinstance(row, (list, tuple)) and len(row) >= 2:
            records.append({"Domain": row[0], "Threat Type": row[1], "Threat Logic": row[2] if len(row) > 2 else None})
    return pd.DataFrame(records, columns=ALERT_FIELDS)


def snapshot_profiles(snapshot):
    return pd.DataFrame((snapshot or {}).get("profiles") or [], columns=PROFILE_FIELDS)


def is_legacy(snapshot):
    return int((snapshot or {}).get("schema", 1)) < 2


def summarize_alerts(alerts):
    """Counts used in run listings: total, per severity, distinct (domain, threat type) keys."""
    by_severity = alerts["Severity"].value_counts().to_dict() if not alerts.empty and alerts["Severity"].notna().any() else {}
    return {"alerts": int(len(alerts)), "alert_keys": int(len(alert_key_set(alerts))),
            "by_severity": {s: int(by_severity.get(s, 0)) for s in SEVERITY_ORDER if s in by_severity}}


def run_summary(snapshot):
    """Stored summary for v2 snapshots, recomputed for legacy ones."""
    if snapshot and snapshot.get("summary"):
        return snapshot["summary"]
    summary = summarize_alerts(snapshot_alerts(snapshot))
    profiles = snapshot_profiles(snapshot)
    summary["max_unified_risk"] = None if profiles.empty else profiles["Unified Risk"].max()
    return summary


def alert_key_set(alerts):
    if alerts is None or alerts.empty:
        return set()
    return set(zip(alerts["Domain"].astype(str), alerts["Threat Type"].astype(str)))


def _keys(alerts):
    return list(zip(alerts["Domain"].astype(str), alerts["Threat Type"].astype(str)))


def _first_per_key(alerts):
    return alerts.drop_duplicates(subset=ALERT_KEY).reset_index(drop=True)


@dataclass
class RunComparison:
    new: pd.DataFrame = field(default_factory=pd.DataFrame)          # in target, not in base
    resolved: pd.DataFrame = field(default_factory=pd.DataFrame)     # in base, not in target
    persisting: pd.DataFrame = field(default_factory=pd.DataFrame)   # in both (target's details)
    artifact_diff: pd.DataFrame = field(default_factory=pd.DataFrame)
    risk_changes: pd.DataFrame = field(default_factory=pd.DataFrame)
    window_mismatch: bool = False
    legacy: bool = False


LATER_KINDS = {"Hostname"}   # artifact kinds snapshots only record since a later version


def diff_artifacts(previous, current):
    """
    Rows of added/removed artifacts per domain between two artifact maps. A kind in LATER_KINDS that the previous
    map has nowhere is left out: an older snapshot did not record it, so all of it would look new.
    """
    rows = []
    recorded = {kind for kinds in previous.values() for kind in kinds}
    for domain in sorted(set(previous) | set(current)):
        prev_kinds, curr_kinds = previous.get(domain, {}), current.get(domain, {})
        for kind in sorted(set(prev_kinds) | set(curr_kinds)):
            if kind in LATER_KINDS and kind not in recorded:
                continue
            prev_vals, curr_vals = set(prev_kinds.get(kind, [])), set(curr_kinds.get(kind, []))
            rows += [{"Domain": domain, "Artifact": kind, "Value": v, "Change": "Added"} for v in sorted(curr_vals - prev_vals)]
            rows += [{"Domain": domain, "Artifact": kind, "Value": v, "Change": "Removed"} for v in sorted(prev_vals - curr_vals)]
    return pd.DataFrame(rows, columns=["Domain", "Artifact", "Value", "Change"])


def compare_runs(base, target):
    """Compares two snapshots: alerts new / resolved / persisting, infrastructure changes, and risk / DIF changes."""
    base_alerts, target_alerts = _first_per_key(snapshot_alerts(base)), _first_per_key(snapshot_alerts(target))
    base_keys, target_keys = alert_key_set(base_alerts), alert_key_set(target_alerts)
    comparison = RunComparison(
        new=target_alerts[[k not in base_keys for k in _keys(target_alerts)]],
        resolved=base_alerts[[k not in target_keys for k in _keys(base_alerts)]],
        persisting=target_alerts[[k in base_keys for k in _keys(target_alerts)]],
        artifact_diff=diff_artifacts(base.get("artifacts", {}), target.get("artifacts", {})),
        window_mismatch=(base.get("window") or None) != (target.get("window") or None),
        legacy=is_legacy(base) or is_legacy(target),
    )
    base_profiles, target_profiles = snapshot_profiles(base), snapshot_profiles(target)
    if not base_profiles.empty or not target_profiles.empty:
        merged = base_profiles.merge(target_profiles, on="Domain", how="outer", suffixes=(" (A)", " (B)"))
        merged["Risk Change"] = pd.to_numeric(merged["Unified Risk (B)"], errors="coerce") - pd.to_numeric(merged["Unified Risk (A)"], errors="coerce")
        merged["DIF Changed"] = merged["DIF Fingerprint (A)"].fillna("") != merged["DIF Fingerprint (B)"].fillna("")
        comparison.risk_changes = merged[[
            "Domain", "Unified Risk (A)", "Unified Risk (B)", "Risk Change", "DIF Fingerprint (A)", "DIF Fingerprint (B)", "DIF Changed",
        ]].sort_values("Domain").reset_index(drop=True)
    return comparison


def alert_lifecycle(history, current_alerts, current_created):
    """
    Per (domain, threat type) in the current alerts: when it was first / last detected and in how many runs
    (previous snapshots in `history` plus the current run). Returns a DataFrame indexed by the key.
    """
    columns = ["First Detected", "Last Detected", "Runs Seen", "Previous Runs"]
    if current_alerts is None or current_alerts.empty:
        return pd.DataFrame(columns=columns)
    seen = {}
    for snapshot in history or []:
        created = pd.to_datetime(snapshot.get("created"), errors="coerce", utc=True)
        for key in alert_key_set(snapshot_alerts(snapshot)):
            first, last, count = seen.get(key, (created, created, 0))
            seen[key] = (min(first, created), max(last, created), count + 1)
    now = pd.to_datetime(current_created, errors="coerce", utc=True)
    rows = {}
    for key in alert_key_set(current_alerts):
        first, _, count = seen.get(key, (now, now, 0))
        rows[key] = {"First Detected": first, "Last Detected": now, "Runs Seen": count + 1, "Previous Runs": count}
    frame = pd.DataFrame.from_dict(rows, orient="index", columns=columns)
    frame.index = pd.MultiIndex.from_tuples(frame.index, names=ALERT_KEY)
    return frame


def resolved_since(previous_snapshot, current_alerts):
    """Alerts present in the previous run but not in the current one."""
    if not previous_snapshot:
        return pd.DataFrame(columns=ALERT_FIELDS)
    previous = _first_per_key(snapshot_alerts(previous_snapshot))
    current = alert_key_set(current_alerts)
    return previous[[k not in current for k in _keys(previous)]].reset_index(drop=True)


def first_detected_mask(alerts, lifecycle):
    """True for alerts never seen in an earlier run."""
    if alerts.empty or lifecycle is None or lifecycle.empty:
        return pd.Series(False, index=alerts.index)
    previous_runs = lifecycle["Previous Runs"].to_dict()
    return pd.Series([previous_runs.get(key, 0) == 0 for key in _keys(alerts)], index=alerts.index)


def format_created(created, timezone="UTC", fmt="%Y-%m-%d %H:%M"):
    ts = pd.to_datetime(created, errors="coerce", utc=True)
    return ts.tz_convert(timezone).strftime(fmt) if pd.notna(ts) else str(created or "")


# ---------------------------------------------------------------------------
# Trends across runs (option 3)
# ---------------------------------------------------------------------------

def _run_time(snapshot):
    return pd.to_datetime(snapshot.get("created"), errors="coerce", utc=True)


def severity_trend(snapshots):
    """Alert counts per run and severity (legacy runs counted as 'Unknown')."""
    rows = []
    for snapshot in snapshots:
        alerts = snapshot_alerts(snapshot)
        if alerts.empty:
            rows.append({"Run Time": _run_time(snapshot), "Run": snapshot.get("id"), "Severity": "None", "Alerts": 0})
            continue
        counts = alerts["Severity"].fillna("Unknown").value_counts()
        rows += [{"Run Time": _run_time(snapshot), "Run": snapshot.get("id"), "Severity": sev, "Alerts": int(n)} for sev, n in counts.items()]
    return pd.DataFrame(rows, columns=["Run Time", "Run", "Severity", "Alerts"])


def risk_trend(snapshots):
    """Unified Risk and DIF per domain per run (v2 snapshots only); flags runs where the DIF changed."""
    rows = []
    for snapshot in snapshots:
        for _, row in snapshot_profiles(snapshot).iterrows():
            rows.append({"Run Time": _run_time(snapshot), "Run": snapshot.get("id"), "Domain": row["Domain"],
                         "Unified Risk": row["Unified Risk"], "DIF Fingerprint": row["DIF Fingerprint"]})
    frame = pd.DataFrame(rows, columns=["Run Time", "Run", "Domain", "Unified Risk", "DIF Fingerprint"])
    if frame.empty:
        return frame.assign(**{"DIF Changed": pd.Series(dtype=bool)})
    frame = frame.sort_values(["Domain", "Run Time"]).reset_index(drop=True)
    previous = frame.groupby("Domain")["DIF Fingerprint"].shift(1)
    frame["DIF Changed"] = previous.notna() & (previous != frame["DIF Fingerprint"])
    return frame


def artifact_trend(snapshots):
    """Distinct artifact counts (IP, Name Server, MX, Certificate, Web Tracker) per domain per run."""
    rows = []
    for snapshot in snapshots:
        for domain, kinds in (snapshot.get("artifacts") or {}).items():
            for kind, values in kinds.items():
                rows.append({"Run Time": _run_time(snapshot), "Run": snapshot.get("id"), "Domain": domain, "Artifact": kind, "Count": len(values)})
    return pd.DataFrame(rows, columns=["Run Time", "Run", "Domain", "Artifact", "Count"])


# ---------------------------------------------------------------------------
# Per-domain history across target lists (option 5)
# ---------------------------------------------------------------------------

def snapshot_domains(snapshot):
    """Domains a snapshot covers: its targets plus any domain with alerts, profiles, or artifacts."""
    domains = set((snapshot or {}).get("targets") or [])
    domains.update((snapshot or {}).get("artifacts", {}).keys())
    alerts = snapshot_alerts(snapshot)
    if not alerts.empty:
        domains.update(alerts["Domain"].dropna().astype(str))
    return domains


def domain_slice(snapshot, domain):
    """One domain's part of a snapshot (alerts, profile, artifacts) as a snapshot-shaped dict."""
    alerts = snapshot_alerts(snapshot)
    profiles = snapshot_profiles(snapshot)
    return {
        "id": snapshot.get("id"), "created": snapshot.get("created"), "window": snapshot.get("window"),
        "schema": snapshot.get("schema", 1), "targets": snapshot.get("targets", []), "seeds": snapshot.get("seeds", []),
        "host_focus": snapshot.get("host_focus", {}),
        "alerts": alerts[alerts["Domain"] == domain].to_dict("records"),
        "profiles": profiles[profiles["Domain"] == domain].to_dict("records"),
        "artifacts": {domain: (snapshot.get("artifacts") or {}).get(domain, {})},
    }


def domain_history(runs, domain):
    """
    All saved runs (from any target list) that covered `domain`, oldest first, de-duplicated by run id.
    `runs` is a list of (target_set_key, snapshot).
    """
    seen, rows = set(), []
    for key, snapshot in runs:
        if snapshot.get("id") in seen or domain not in snapshot_domains(snapshot):
            continue
        seen.add(snapshot.get("id"))
        rows.append((key, domain_slice(snapshot, domain)))
    return sorted(rows, key=lambda item: str(item[1].get("created")))


LIFECYCLE_COLUMNS = ["Threat Type", "Severity (last known)", "First Detected", "Last Detected", "Runs Seen", "Active in Latest Run"]


def domain_lifecycle(history):
    """Per threat type for one domain: first / last detected, runs seen, and whether it fires in the latest run."""
    if not history:
        return pd.DataFrame(columns=LIFECYCLE_COLUMNS)
    stats = {}
    for _, snapshot in history:
        created = _run_time(snapshot)
        for _, row in snapshot_alerts(snapshot).drop_duplicates("Threat Type").iterrows():
            first, last, count, severity = stats.get(row["Threat Type"], (created, created, 0, None))
            stats[row["Threat Type"]] = (min(first, created), max(last, created), count + 1, row.get("Severity") or severity)
    latest = set(snapshot_alerts(history[-1][1])["Threat Type"])
    rows = [{"Threat Type": t, "Severity (last known)": sev, "First Detected": first, "Last Detected": last, "Runs Seen": count,
             "Active in Latest Run": t in latest} for t, (first, last, count, sev) in stats.items()]
    if not rows:  # the domain was analyzed but never had a detection
        return pd.DataFrame(columns=LIFECYCLE_COLUMNS)
    return pd.DataFrame(rows, columns=LIFECYCLE_COLUMNS).sort_values(["Active in Latest Run", "Last Detected"], ascending=[False, False]).reset_index(drop=True)

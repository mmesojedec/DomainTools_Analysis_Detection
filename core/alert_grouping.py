"""Alert grouping: merges repeated findings and groups alerts by rule, campaign cluster, domain, or ATT&CK technique."""
import re

import pandas as pd

from config import SEVERITY_WEIGHTS
from core.intel_data import CONFIDENCE_ORDER, MITRE_TACTICS

GROUP_MODES = ("Finding", "Campaign Cluster", "Domain", "ATT&CK Technique")
GROUP_COLUMNS = ["Group", "Label", "Worst Severity", "Best Confidence", "Alerts", "Domains", "Domain List", "Threat Types",
                 "First Seen", "Last Seen", "Members"]
EVIDENCE_COLUMNS = ["Time", "Domain", "Threat Type", "Severity", "Field", "Value", "Artifact"]

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_WEIGHT_TO_SEVERITY = {v: k for k, v in SEVERITY_WEIGHTS.items()}
_CONFIDENCE_RANK = {c: i for i, c in enumerate(CONFIDENCE_ORDER)}  # 0 = highest


def severity_weights(severities):
    return pd.Series(severities).map(SEVERITY_WEIGHTS).fillna(0)


def worst_severity(severities):
    weights = severity_weights(severities)
    return _WEIGHT_TO_SEVERITY.get(weights.max(), "Low") if len(weights) else "Low"


def best_confidence(confidences):
    ranks = pd.Series(confidences).map(_CONFIDENCE_RANK).dropna()
    return CONFIDENCE_ORDER[int(ranks.min())] if not ranks.empty else "Medium"


def _records(value):
    return value if isinstance(value, list) else []


def _dedupe_records(records):
    seen, unique = set(), []
    for record in records:
        key = (str(record.get("Time")), record.get("Field"), record.get("Value"), record.get("Artifact"))
        if key not in seen:
            seen.add(key)
            unique.append(record)
    return unique


def merge_duplicate_alerts(alerts):
    """
    One alert per (Domain, Threat Type). Rules evaluated per certificate or record can fire several times for one domain;
    the merged alert keeps the worst severity's logic, the best confidence, and all IOC text and evidence.
    """
    if alerts.empty:
        return alerts.reset_index(drop=True)
    alerts = alerts.drop_duplicates(subset=["Domain", "Threat Type", "Threat Logic", "Triggering IOCs"])
    if not alerts.duplicated(subset=["Domain", "Threat Type"]).any():
        return alerts.reset_index(drop=True)
    rows = []
    ranked = alerts.assign(_weight=severity_weights(alerts["Severity"]).to_numpy())
    for _, group in ranked.groupby(["Domain", "Threat Type"], sort=False):
        primary = group.sort_values("_weight", ascending=False, kind="stable").iloc[0].drop("_weight").to_dict()
        if len(group) > 1:
            primary["Threat Logic"] = f"{primary['Threat Logic']} (+{len(group) - 1} similar finding(s) merged)"
            primary["Triggering IOCs"] = "\n\n".join(dict.fromkeys(str(v) for v in group["Triggering IOCs"] if str(v).strip()))
            primary["Confidence"] = best_confidence(group["Confidence"])
            if "Evidence" in group.columns:
                primary["Evidence"] = _dedupe_records([r for value in group["Evidence"] for r in _records(value)])
            if "Occurrences" in group.columns:
                primary["Occurrences"] = int(pd.to_numeric(group["Occurrences"], errors="coerce").fillna(1).sum())
        rows.append(primary)
    return pd.DataFrame(rows, columns=alerts.columns).reset_index(drop=True)


def primary_technique(mitre):
    match = _TECHNIQUE_RE.search(str(mitre or ""))
    return match.group(0) if match else None


def _cluster_labels(correlation):
    labels = {}
    for cluster in getattr(correlation, "clusters", None) or []:
        labels[cluster["Cluster"]] = f"Cluster {cluster['Cluster']} · {cluster['Strength']} · {cluster['Size']} domains"
    return labels


def group_keys(alerts, mode, correlation=None):
    """(group key per alert, key -> display label) for one of GROUP_MODES."""
    if mode == "Finding":
        keys = alerts["Threat Type"].astype(str)
        return keys, {k: k for k in keys.unique()}
    if mode == "Domain":
        keys = alerts["Domain"].astype(str)
        return keys, {k: k for k in keys.unique()}
    if mode == "ATT&CK Technique":
        keys = alerts["MITRE ATT&CK"].map(primary_technique).fillna("No technique")
        labels = {k: k if k == "No technique" else f"{k} · {MITRE_TACTICS.get(k.split('.')[0], 'Other')}" for k in keys.unique()}
        return keys, labels
    if mode == "Campaign Cluster":
        domain_cluster = getattr(correlation, "domain_cluster", None) or {}
        cluster_labels = _cluster_labels(correlation)
        keys = alerts["Domain"].map(lambda d: domain_cluster.get(d, f"domain:{d}"))
        labels = {k: cluster_labels.get(k, f"Cluster {k}") if not k.startswith("domain:") else f"{k[7:]} (no shared infrastructure)"
                  for k in keys.unique()}
        return keys, labels
    raise ValueError(f"Unknown grouping mode: {mode}")


def _evidence_span(evidence):
    times = pd.to_datetime(pd.Series([r.get("Time") for r in _records(evidence)], dtype=object), errors="coerce")
    times = times.dropna()
    return (times.min(), times.max()) if not times.empty else (pd.NaT, pd.NaT)


def group_alerts(alerts, mode="Finding", correlation=None):
    """
    One row per group, most severe first: worst severity, best confidence, alert / domain counts, the evidence time span,
    and `Members` (the alert index labels in the group, for `alerts.loc[...]`).
    """
    if alerts is None or alerts.empty:
        return pd.DataFrame(columns=GROUP_COLUMNS)
    keys, labels = group_keys(alerts, mode, correlation)
    spans = [_evidence_span(v) for v in alerts["Evidence"]] if "Evidence" in alerts.columns else [(pd.NaT, pd.NaT)] * len(alerts)
    frame = alerts.assign(
        _key=keys.to_numpy(), _first=[s[0] for s in spans], _last=[s[1] for s in spans],
    )
    rows = []
    for key, group in frame.groupby("_key", sort=False):
        domains = sorted(group["Domain"].astype(str).unique())
        rows.append({
            "Group": key,
            "Label": labels.get(key, key),
            "Worst Severity": worst_severity(group["Severity"]),
            "Best Confidence": best_confidence(group["Confidence"]),
            "Alerts": len(group),
            "Domains": len(domains),
            "Domain List": domains,
            "Threat Types": sorted(group["Threat Type"].astype(str).unique()),
            "First Seen": pd.to_datetime(group["_first"]).min(),
            "Last Seen": pd.to_datetime(group["_last"]).max(),
            "Members": list(group.index),
        })
    groups = pd.DataFrame(rows, columns=GROUP_COLUMNS)
    groups["_weight"] = severity_weights(groups["Worst Severity"]).to_numpy()
    groups = groups.sort_values(["_weight", "Domains", "Alerts", "Label"], ascending=[False, False, False, True], kind="stable")
    return groups.drop(columns="_weight").reset_index(drop=True)


def alert_evidence(alerts):
    """All evidence records of the given alerts as one time-ordered frame (undated records last)."""
    rows = []
    if alerts is not None and not alerts.empty:
        has_evidence = "Evidence" in alerts.columns
        for _, alert in alerts.iterrows():
            base = {"Domain": alert["Domain"], "Threat Type": alert["Threat Type"], "Severity": alert["Severity"]}
            records = _records(alert["Evidence"]) if has_evidence else []
            if not records:
                records = [{"Time": pd.NaT, "Field": "IOCs", "Value": str(alert.get("Triggering IOCs") or ""), "Artifact": None}]
            for record in records:
                rows.append({**base, "Time": record.get("Time"), "Field": record.get("Field", ""),
                             "Value": record.get("Value", ""), "Artifact": record.get("Artifact")})
    evidence = pd.DataFrame(rows, columns=EVIDENCE_COLUMNS)
    evidence["Time"] = pd.to_datetime(evidence["Time"], errors="coerce")
    return evidence.sort_values(["Time", "Domain", "Threat Type"], na_position="last", kind="stable").reset_index(drop=True)

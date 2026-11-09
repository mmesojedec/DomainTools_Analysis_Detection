"""Runs & Diffs (Previous Runs & Comparison): browse saved runs, inspect one, compare any two, and manage them; the
Offline Datasets page (saved datasets: load, rename, delete, retention)."""
import pandas as pd
import plotly.express as px
import streamlit as st

from core.helpers import md_escape
from core.hunt_tree import hunt_tree
from core.offline import (
    apply_offline_retention,
    dataset_breakdown,
    delete_offline_dataset,
    format_size,
    list_offline_datasets,
    offline_retention,
    set_offline_retention,
    update_offline_manifest,
)
from core.persistence import (
    apply_retention,
    delete_run,
    delete_target_set,
    export_run_json,
    list_runs,
    list_target_sets,
    load_all_runs,
    load_run,
    load_runs,
    load_watches,
    remove_watch,
    run_retention,
    set_run_retention,
    target_set_key,
    update_run_meta,
)
from core.run_history import (
    SEVERITY_ORDER,
    artifact_trend,
    compare_runs,
    domain_history,
    domain_lifecycle,
    format_created,
    is_legacy,
    risk_trend,
    severity_trend,
    snapshot_alerts,
    snapshot_domains,
    snapshot_profiles,
)
from views import navigation
from views.common import chart, table
from views.sidebar import (
    HISTORY_TAB_KEY,
    OFFLINE_SELECT_KEY,
    TOAST_KEY,
    request_offline_load,
    start_hunt,
)

ALERT_COLUMNS = ["Domain", "Threat Type", "Severity", "Confidence", "Category", "MITRE ATT&CK", "Threat Logic"]
LEGACY_NOTE = ("Saved by an earlier version: only alert keys and infrastructure were recorded, so severity, confidence, "
               "risk scores, and DIF are not available for this run.")


def _targets_label(targets, limit=4, seeds=None):
    """Targets as a short list; runs started from certificate inputs show those first ("cn:Acme VPN → a.com, ...")."""
    targets, seeds = list(targets or []), list(seeds or [])
    shown = ", ".join(targets[:limit]) + (f" (+{len(targets) - limit} more)" if len(targets) > limit else "")
    if not seeds:
        return shown
    seed_text = ", ".join(seeds[:2]) + (f" (+{len(seeds) - 2})" if len(seeds) > 2 else "")
    return f"{seed_text} → {shown}"


def _run_labels(runs, timezone):
    """Unique, readable labels per run id (seconds + short id, so quick re-runs never share a label)."""
    labels = {}
    for run in runs:
        name = f" — {run['name']}" if run.get("name") else ""
        labels[run["id"]] = (f"{format_created(run['created'], timezone, '%Y-%m-%d %H:%M:%S')}{name} "
                             f"({run['alerts']} alerts) · #{run['id'][-6:-1]}")
    return labels


def _runs_table(runs, timezone, current_run_id):
    rows = []
    for run in runs:
        sev = run["by_severity"] or {}
        rows.append({
            "Run": format_created(run["created"], timezone, "%Y-%m-%d %H:%M:%S") + ("  ◀ current" if run["id"] == current_run_id else ""),
            "Name": run["name"], "Window": run["window"] or "—", "Alerts": run["alerts"],
            "Critical": sev.get("Critical") if sev else None, "High": sev.get("High") if sev else None,
            "Max Unified Risk": run["max_unified_risk"], "API queries": run.get("queries"), "Note": run["note"],
            "Format": "legacy" if run["schema"] < 2 else "v2",
        })
    frame = pd.DataFrame(rows)
    for col in ("Critical", "High", "Max Unified Risk", "API queries"):
        frame[col] = pd.to_numeric(frame[col], errors="coerce").round().astype("Int64")  # blank (not 1.0 / NaN) for legacy runs
    return frame


def _artifact_counts(snapshot):
    rows = [{"Domain": dom, "Artifact": kind, "Count": len(values)}
            for dom, kinds in (snapshot.get("artifacts") or {}).items() for kind, values in kinds.items()]
    if not rows:
        return pd.DataFrame(columns=["Domain"])
    return pd.DataFrame(rows).pivot_table(index="Domain", columns="Artifact", values="Count", fill_value=0).reset_index()


def _render_run_details(key, runs, timezone):
    options = [r["id"] for r in runs]
    labels = _run_labels(runs, timezone)
    run_id = st.selectbox("Run", options, format_func=labels.get, key=f"hist_detail_{key}")
    snapshot = load_run(key, run_id)
    if not snapshot:
        st.warning("Run not found (it may have been deleted).")
        return
    if is_legacy(snapshot):
        st.caption(LEGACY_NOTE)
    alerts, profiles = snapshot_alerts(snapshot), snapshot_profiles(snapshot)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Alerts", len(alerts))
    c2.metric("Domains with alerts", alerts["Domain"].nunique() if not alerts.empty else 0)
    c3.metric("Max Unified Risk", "—" if profiles.empty else int(profiles["Unified Risk"].max()))
    c4.metric("Window", snapshot.get("window") or "—")
    if snapshot.get("note"):
        st.info(f"**Note:** {snapshot['note']}")
    if snapshot.get("seeds"):
        st.caption(f"Certificate inputs: {', '.join(snapshot['seeds'])}")
    if snapshot.get("host_focus"):
        st.caption("Hostname focus: " + md_escape("; ".join(f"{apex}: {', '.join(hosts)}"
                                                             for apex, hosts in snapshot["host_focus"].items())))
    st.caption(f"Targets: {_targets_label(snapshot.get('targets'), limit=20)}")
    if not alerts.empty:
        st.markdown("##### Detections")
        table(alerts[[c for c in ALERT_COLUMNS if alerts[c].notna().any()]])
    if not profiles.empty:
        st.markdown("##### Risk & DIF")
        table(profiles)
    counts = _artifact_counts(snapshot)
    if len(counts.columns) > 1:
        st.markdown("##### Infrastructure")
        table(counts)
        with st.expander("All recorded artifacts", expanded=False):
            rows = [{"Domain": d, "Artifact": k, "Value": str(v)} for d, kinds in snapshot["artifacts"].items() for k, vals in kinds.items() for v in vals]
            table(pd.DataFrame(rows))


def _render_comparison(key, runs, timezone):
    if len(runs) < 2:
        st.info("At least two runs of this target list are needed for a comparison.")
        return
    options = [r["id"] for r in runs]
    labels = _run_labels(runs, timezone)
    col1, col2 = st.columns(2)
    base_id = col1.selectbox("Baseline run (A)", options, index=1, format_func=labels.get, key=f"hist_base_{key}")
    target_id = col2.selectbox("Compare to (B)", options, index=0, format_func=labels.get, key=f"hist_target_{key}")
    if base_id == target_id:
        st.info("Choose two different runs.")
        return
    base, target = load_run(key, base_id), load_run(key, target_id)
    if not base or not target:
        st.warning("One of the selected runs was not found.")
        return
    result = compare_runs(base, target)
    if result.window_mismatch:
        st.warning(f"The runs used different analysis windows ('{base.get('window') or 'unknown'}' vs "
                   f"'{target.get('window') or 'unknown'}'); some differences may come from the window, not the infrastructure.")
    if result.legacy:
        st.caption("At least one run was saved by an earlier version, so severity and risk / DIF comparisons may be incomplete.")

    diff = result.artifact_diff
    added = int((diff["Change"] == "Added").sum()) if not diff.empty else 0
    removed = int((diff["Change"] == "Removed").sum()) if not diff.empty else 0
    dif_changes = int(result.risk_changes["DIF Changed"].sum()) if not result.risk_changes.empty else 0
    m = st.columns(6)
    m[0].metric("New alerts", len(result.new))
    m[1].metric("Resolved alerts", len(result.resolved))
    m[2].metric("Persisting", len(result.persisting))
    m[3].metric("Artifacts added", added)
    m[4].metric("Artifacts removed", removed)
    m[5].metric("DIF changes", dif_changes)

    tabs = st.tabs(["New in B", "Resolved in B", "Persisting", "Infrastructure Changes", "Risk & DIF"])
    for tab, frame, empty in ((tabs[0], result.new, "No new detections."), (tabs[1], result.resolved, "Nothing was resolved."),
                              (tabs[2], result.persisting, "No detections present in both runs.")):
        with tab:
            if frame.empty and frame is result.persisting:
                st.info(empty)
            elif frame.empty:
                st.success(empty)
            else:
                if frame["Severity"].notna().any():
                    counts = frame["Severity"].value_counts().reindex(SEVERITY_ORDER).dropna()
                    st.caption("By severity: " + ", ".join(f"{s} {int(n)}" for s, n in counts.items()))
                table(frame[[c for c in ALERT_COLUMNS if frame[c].notna().any()]])
    with tabs[3]:
        if diff.empty:
            st.success("No infrastructure changes between the two runs.")
        else:
            summary = diff.groupby(["Domain", "Artifact", "Change"]).size().reset_index(name="Count")
            fig = px.bar(summary, x="Domain", y="Count", color="Artifact", pattern_shape="Change", barmode="stack",
                         title="Infrastructure added / removed (A ➔ B)")
            chart(fig, key=f"hist_diff_chart_{key}", height=340)
            table(diff)
    with tabs[4]:
        if result.risk_changes.empty:
            st.info("Risk and DIF data are not available for these runs.")
        else:
            table(result.risk_changes, column_config={
                "Risk Change": st.column_config.NumberColumn("Risk Change", format="%+d"),
                "DIF Changed": st.column_config.CheckboxColumn("DIF Changed"),
            })


def _render_manage(key, runs, timezone):
    options = [r["id"] for r in runs]
    labels = _run_labels(runs, timezone)
    run_id = st.selectbox("Run", options, format_func=labels.get, key=f"hist_manage_{key}")
    run = next(r for r in runs if r["id"] == run_id)

    with st.form(f"hist_meta_{key}_{run_id}"):
        name = st.text_input("Name", value=run["name"], max_chars=120, placeholder="e.g. Pre-takedown baseline")
        note = st.text_area("Note", value=run["note"], max_chars=2000, height=80)
        if st.form_submit_button("Save name & note"):
            update_run_meta(key, run_id, name=name, note=note)
            st.rerun()

    col1, col2 = st.columns(2)
    col1.download_button("Export run (JSON)", export_run_json(key, run_id).encode(), file_name=f"dt_run_{key}_{run_id}.json",
                         mime="application/json", width="stretch", key=f"hist_export_{key}_{run_id}")
    with col2:
        confirm = st.checkbox("Confirm deletion of this run", key=f"hist_del_confirm_{key}_{run_id}")
        if st.button("Delete run", disabled=not confirm, width="stretch", key=f"hist_del_{key}_{run_id}"):
            delete_run(key, run_id)
            st.rerun()

    st.divider()
    col3, col4 = st.columns(2)
    with col3:
        keep = st.number_input("Runs kept per target list", min_value=1, max_value=500, value=run_retention(), step=1,
                               key="hist_retention", help="Older runs beyond this number are deleted when a new run is saved.")
        if st.button("Save retention & apply now", key=f"hist_retention_apply_{key}"):
            set_run_retention(keep)
            removed = apply_retention(key, int(keep))
            st.toast(f"Retention set to {int(keep)}; removed {removed} old run(s) for this target list.")
            if removed:
                st.rerun()
    with col4:
        confirm_all = st.checkbox(f"Confirm deletion of all {len(runs)} run(s) for this target list", key=f"hist_del_all_confirm_{key}")
        if st.button("Delete all runs for this target list", disabled=not confirm_all, key=f"hist_del_all_{key}"):
            delete_target_set(key)
            st.rerun()


SEVERITY_COLORS = {"Critical": "#DC2626", "High": "#F97316", "Medium-High": "#F59E0B", "Medium": "#EAB308", "Low": "#3B82F6",
                   "Unknown": "#748590", "None": "#2A3040"}


def _localize(frame, timezone, column="Run Time"):
    if not frame.empty:
        frame = frame.copy()
        frame[column] = pd.to_datetime(frame[column], utc=True).dt.tz_convert(timezone).dt.tz_localize(None)
    return frame


def _render_trends(key, timezone):
    """Option 3: how alerts, risk, infrastructure, and DIF evolved across runs of this target list."""
    snapshots = load_runs(key)
    if len(snapshots) < 2:
        st.info("Trends need at least two runs of this target list.")
        return
    if any(is_legacy(s) for s in snapshots):
        st.caption("Legacy runs contribute alert counts (severity 'Unknown') and infrastructure, but no risk or DIF.")

    sev = _localize(severity_trend(snapshots), timezone)
    sev = sev[sev["Severity"] != "None"]
    if not sev.empty:
        order = [s for s in SEVERITY_ORDER + ["Unknown"] if s in set(sev["Severity"])]
        fig = px.bar(sev, x="Run Time", y="Alerts", color="Severity", color_discrete_map=SEVERITY_COLORS,
                     category_orders={"Severity": order}, title="Detections per run by severity")
        fig.update_layout(bargap=0.4, xaxis_title=f"Run time ({timezone})")
        chart(fig, key=f"trend_sev_{key}", height=340)

    risk = _localize(risk_trend(snapshots), timezone)
    if not risk.empty:
        col1, col2 = st.columns([1.4, 1])
        with col1:
            fig = px.line(risk, x="Run Time", y="Unified Risk", color="Domain", markers=True, range_y=[0, 100],
                          hover_data={"DIF Fingerprint": True}, title="Unified Risk per domain")
            changed = risk[risk["DIF Changed"]]
            if not changed.empty:
                fig.add_scatter(x=changed["Run Time"], y=changed["Unified Risk"], mode="markers", name="DIF changed",
                                marker=dict(symbol="star", size=16, color="#FFFFFF", line=dict(width=1, color="#F76509")))
            chart(fig, key=f"trend_risk_{key}", height=360)
        with col2:
            st.markdown("##### DIF changes")
            if changed.empty:
                st.success("No DIF fingerprint changes across these runs.")
            else:
                st.caption("A changed fingerprint means the hosting, TLS, or service profile changed between runs.")
                table(changed[["Run Time", "Domain", "DIF Fingerprint", "Unified Risk"]])

    arts = _localize(artifact_trend(snapshots), timezone)
    if not arts.empty:
        kinds = sorted(arts["Artifact"].unique())
        kind = st.selectbox("Infrastructure type", kinds, index=kinds.index("IP") if "IP" in kinds else 0, key=f"trend_kind_{key}")
        fig = px.line(arts[arts["Artifact"] == kind], x="Run Time", y="Count", color="Domain", markers=True,
                      title=f"Distinct {kind} values per domain")
        chart(fig, key=f"trend_art_{key}", height=320)


def _render_domain_history(current_key, timezone):
    """Option 5: one domain's history across every saved run, regardless of which target list it was analyzed in."""
    runs = load_all_runs()
    domains = sorted({d for _, snap in runs for d in snapshot_domains(snap)})
    if not domains:
        st.info("No saved runs yet.")
        return
    current_targets = next((snap.get("targets", []) for k, snap in reversed(runs) if k == current_key), [])
    default = domains.index(current_targets[0]) if current_targets and current_targets[0] in domains else 0
    domain = st.selectbox("Domain", domains, index=default, key="hist_domain",
                          help="History for this domain from every saved run that included it, across all target lists.")
    history = domain_history(runs, domain)
    target_lists = {k for k, _ in history}
    st.caption(f"{len(history)} saved run(s) across {len(target_lists)} target list(s) included **{domain}**.")

    rows = []
    for list_key, snap in history:
        alerts, profiles = snapshot_alerts(snap), snapshot_profiles(snap)
        arts = snap["artifacts"].get(domain, {})
        rows.append({
            "Run Time": pd.to_datetime(snap["created"], utc=True), "Target List": _targets_label(snap.get("targets"), seeds=snap.get("seeds")),
            "Window": snap.get("window") or "—", "Alerts": len(alerts),
            "Critical": int((alerts["Severity"] == "Critical").sum()) if alerts["Severity"].notna().any() else None,
            "High": int((alerts["Severity"] == "High").sum()) if alerts["Severity"].notna().any() else None,
            "Unified Risk": profiles["Unified Risk"].iloc[0] if not profiles.empty else None,
            "DIF Fingerprint": profiles["DIF Fingerprint"].iloc[0] if not profiles.empty else None,
            "IPs": len(arts.get("IP", [])), "Certificates": len(arts.get("Certificate", [])),
            "Current List": "✓" if list_key == current_key else "",
        })
    frame = _localize(pd.DataFrame(rows), timezone)
    for col in ("Critical", "High", "Unified Risk"):
        frame[col] = pd.to_numeric(frame[col], errors="coerce").round().astype("Int64")
    table(frame.sort_values("Run Time", ascending=False), column_config={
        "Run Time": st.column_config.DatetimeColumn(f"Run Time ({timezone})", format="YYYY-MM-DD HH:mm:ss")})

    if len(history) >= 2:
        plot = frame.assign(**{"Alerts": frame["Alerts"].astype(float), "Unified Risk": frame["Unified Risk"].astype("Float64").astype(float)})
        fig = px.line(plot.sort_values("Run Time"), x="Run Time", y=["Alerts", "Unified Risk"], markers=True,
                      title=f"{domain}: alerts and Unified Risk per run")
        fig.update_layout(legend_title_text="", yaxis_title="")
        chart(fig, key="domain_hist_trend", height=320)

    st.markdown("##### Detection lifecycle for this domain")
    lifecycle = _localize(_localize(domain_lifecycle(history), timezone, "First Detected"), timezone, "Last Detected")
    if lifecycle.empty:
        st.success("No detections recorded for this domain in saved runs.")
    else:
        st.caption("Active = fires in the most recent saved run that included this domain.")
        table(lifecycle, column_config={
            "First Detected": st.column_config.DatetimeColumn("First Detected", format="YYYY-MM-DD HH:mm"),
            "Last Detected": st.column_config.DatetimeColumn("Last Detected", format="YYYY-MM-DD HH:mm"),
            "Active in Latest Run": st.column_config.CheckboxColumn("Active in Latest Run"),
        })

    if len(history) >= 2:
        result = compare_runs(history[-2][1], history[-1][1])
        st.markdown("##### Latest change for this domain (previous ➔ latest run)")
        c = st.columns(4)
        c[0].metric("New", len(result.new))
        c[1].metric("Resolved", len(result.resolved))
        c[2].metric("Artifacts added", int((result.artifact_diff["Change"] == "Added").sum()) if not result.artifact_diff.empty else 0)
        c[3].metric("Artifacts removed", int((result.artifact_diff["Change"] == "Removed").sum()) if not result.artifact_diff.empty else 0)
        if not result.artifact_diff.empty:
            table(result.artifact_diff)


OFFLINE_SAVED_KEY = "offline_just_saved"   # a dataset the top menu's Save offline copy just saved: ask for its name


def _render_dataset_breakdown(dataset_id, manifest):
    """What the dataset holds, part by part: records, size on disk and the limit each lookup ran with."""
    try:
        parts, capped = dataset_breakdown(dataset_id)
    except (OSError, ValueError) as exc:
        st.caption(f"The dataset's contents could not be read: {exc}")
        return
    with st.expander(f"What's in this dataset ({len(parts)} parts, {format_size(manifest.get('size_bytes'))})",
                     icon=":material/dataset:", expanded=True):
        st.caption("Each part with the records it holds, its compressed size on disk and the limit its lookups ran "
                   "with (the run's collection options; *Off*: that lookup was not on). Empty parts were looked up "
                   "but found nothing.")
        st.dataframe(parts.sort_values("Bytes", ascending=False).drop(columns="Bytes"), hide_index=True,
                     width="stretch", column_config={
                         "Records": st.column_config.NumberColumn("Records", format="%d"),
                         "Size": st.column_config.TextColumn("Size", help="Compressed, as stored in dt_offline/"),
                         "Limit applied": st.column_config.TextColumn("Limit applied", width="large")})
        if capped.empty:
            st.caption(":material/check: No lookup stopped at its limit: every source returned all it had.")
        else:
            st.markdown(f"**Lookups that stopped at a limit ({len(capped)})**",
                        help="These returned the most records their limit allows, so there may be more. Raise the "
                             "limit under Settings → Collection options and analyze again to fetch more.")
            st.dataframe(capped, hide_index=True, width="stretch")


def render_offline_datasets():
    """Offline Datasets page (Manage Data): saved offline datasets (load, rename, delete, retention)."""
    st.subheader("Offline Datasets", help="Datasets saved from live runs (dt_offline/): load one to re-analyze it "
                 "without API calls, rename it, delete it, and choose how many are kept.")
    datasets = list_offline_datasets()
    st.caption("Offline datasets hold everything a live run collected (dt_offline/, local and git-ignored). Pick one "
               "and click **Load offline dataset** to re-analyze it without API calls. They can contain sensitive "
               "investigation data.")
    if not datasets:
        st.info("No offline datasets saved yet. Tick **Save offline copy** in the sidebar before clicking Analyze, or "
                "click **Save offline copy** at the top of a page after a run.")
    else:
        rows = [{"Saved (UTC)": format_created(m.get("created"), "UTC", "%Y-%m-%d %H:%M:%S"), "Name": m.get("name", ""),
                 "Targets": _targets_label(m.get("targets"), seeds=m.get("seeds")), "pDNS": m.get("provider"),
                 "DNSDB Limit": (m.get("settings") or {}).get("dnsdb_limit"), "Records": sum((m.get("frames") or {}).values()),
                 "Size": format_size(m.get("size_bytes")), "Linked Run": "yes" if m.get("run_id") else "—"} for m in datasets]
        table(pd.DataFrame(rows))
        st.caption(f"Total size: {format_size(sum(m.get('size_bytes', 0) for m in datasets))}")
        ids = [m["id"] for m in datasets]
        labels = {m["id"]: f"{format_created(m.get('created'), 'UTC', '%Y-%m-%d %H:%M:%S')} · {_targets_label(m.get('targets'), 2, m.get('seeds'))}"
                  + (f" — {m['name']}" if m.get("name") else "") for m in datasets}
        if st.session_state.get(OFFLINE_SELECT_KEY) not in ids:
            st.session_state.pop(OFFLINE_SELECT_KEY, None)
        dataset_id = st.selectbox("Dataset", ids, format_func=labels.get, key=OFFLINE_SELECT_KEY)
        manifest = next(m for m in datasets if m["id"] == dataset_id)
        settings = manifest.get("settings", {})
        details = [f"**Targets:** {md_escape(', '.join(manifest.get('targets', [])))}",
                   f"**pDNS:** {manifest.get('provider')}" + (f" (limit {int(settings['dnsdb_limit']):,})"
                                                              if settings.get("dnsdb_limit") else "")]
        if manifest.get("seeds"):
            details.insert(0, f"**Certificate inputs:** {md_escape(', '.join(manifest['seeds']))}")
        st.caption("  \n".join(details))
        _render_dataset_breakdown(dataset_id, manifest)
        loaded = (st.session_state.get("data_origin") or {}).get("offline_id") == dataset_id
        st.button("Loaded" if loaded else "Load offline dataset", key=f"offline_load_{dataset_id}",
                  type="secondary" if loaded else "primary", icon=":material/check:" if loaded else
                  ":material/upload_file:", on_click=request_offline_load, args=(dataset_id,),
                  help="Re-analyzes the saved data with the current window, thresholds and filters; no API calls. "
                       "Opens on the Summary.")
        if st.session_state.get(OFFLINE_SAVED_KEY) == dataset_id:
            st.success(f"Offline copy saved as “{manifest.get('name', '')}” ({format_size(manifest.get('size_bytes'))})."
                       " Rename it below if you like, e.g. after the case or the question it answers.",
                       icon=":material/save:")
        with st.form(f"offline_meta_{dataset_id}"):
            name = st.text_input("Name", value=manifest.get("name", ""), max_chars=120,
                                 placeholder="e.g. Acme phishing kit, 2026-11 takedown")
            if st.form_submit_button("Save name", type="primary" if st.session_state.get(OFFLINE_SAVED_KEY) ==
                                     dataset_id else "secondary"):
                update_offline_manifest(dataset_id, name=name)
                st.session_state.pop(OFFLINE_SAVED_KEY, None)
                st.session_state[TOAST_KEY] = (f"Named the offline copy “{name.strip()}”." if name.strip()
                                               else "Name cleared.")
                st.rerun()
        confirm = st.checkbox("Confirm deletion of this offline dataset", key=f"offline_del_confirm_{dataset_id}")
        if st.button("Delete offline dataset", disabled=not confirm, key=f"offline_del_{dataset_id}"):
            delete_offline_dataset(dataset_id)
            st.rerun()
    keep = st.number_input("Offline datasets kept", min_value=1, max_value=200, value=offline_retention(), step=1, key="offline_retention",
                           help="When a new dataset is saved, the oldest ones beyond this number are deleted.")
    if st.button("Save retention & apply now", key="offline_retention_apply"):
        set_offline_retention(keep)
        removed = apply_offline_retention(int(keep))
        st.toast(f"Offline retention set to {int(keep)}; removed {removed} dataset(s).")
        if removed:
            st.rerun()


def _render_hunt_tree(timezone, current_run_id):
    """Every hunt with two or more runs, as a tree: which run led to which, and through which pivot."""
    st.caption("A run started from a lead, a certificate or an Iris search (Summary, Certificates, Pivot Ranking) "
               "remembers the run it came from. Each hunt below starts at its first run; indented runs came from the "
               "run above them.")
    rows = hunt_tree(load_all_runs())
    if not rows:
        st.info("No hunts yet. Use *Analyze* on a lead on the Summary page, *Analyze its domains* on a certificate, or "
                "*Analyze the top … as a new run* on Iris search results to start one.")
        return
    for row in rows:
        c_text, c_button = st.columns([6, 1], vertical_alignment="center")
        indent = "&nbsp;" * 6 * row["Depth"] + ("↳ " if row["Depth"] else "")
        via = f" · *via {md_escape(row['Via'])}*" if row["Via"] else ""
        current = " :blue-badge[current]" if row["Run"] == current_run_id else ""
        c_text.markdown(f"{indent}**{md_escape(row['Targets'])}** · {format_created(row['Created'], timezone)} · "
                        f"{row['Alerts']} alert(s){via}{current}")
        c_button.button("Analyze again", key=f"hunt_again::{row['Run']}", on_click=start_hunt,
                        args=(row["Target List"], row["Via"] or "Analyzed again", row["Parent"]), width="stretch",
                        help="Runs this branch's targets again (same place in the tree) with the current options.")


def _render_watches(timezone):
    st.caption("Target lists you watch (*Watch this list* on the Summary page). Run one to see what is new since its "
               "last run: the Summary's *What's new since the last analysis* lists the new IPs, name servers, "
               "certificates, hostnames and alerts.")
    watches = load_watches()
    if not watches:
        st.info("No watched lists yet.")
        return
    for watch in watches:
        runs = load_runs(target_set_key(watch["targets"]))
        last = format_created(runs[-1].get("created"), timezone) if runs else "never"
        c_text, c_run, c_remove = st.columns([5, 1, 1], vertical_alignment="center")
        c_text.markdown(f"**{md_escape(watch['name'])}** · {len(watch['targets'])} target(s) · last run {last}  \n"
                        f":gray[{md_escape(', '.join(watch['targets'][:8]))}]")
        c_run.button("Run now", key=f"watch_run::{watch['name']}", on_click=start_hunt, type="primary",
                     args=(watch["targets"], f"Watched list {watch['name']}"), width="stretch")
        if c_remove.button("Remove", key=f"watch_remove::{watch['name']}", width="stretch"):
            remove_watch(watch["targets"])
            st.rerun()


def render_run_history(current_key=None, timezone="UTC", current_run_id=None):
    st.subheader("Previous Runs & Comparison",
                 help="Every analysis run is saved locally (dt_runs/). Browse past runs of a target list, compare any two, follow "
                      "trends, review one domain across all target lists and manage runs. Offline datasets have their "
                      "own page: Manage Data → Offline Datasets.")
    target_sets = list_target_sets()
    if not target_sets:
        st.info("No saved runs yet. Each Analyze run is saved automatically once its results are displayed.")
        return
    keys = [s["key"] for s in target_sets]
    meta = {s["key"]: s for s in target_sets}
    default = keys.index(current_key) if current_key in keys else 0
    key = st.selectbox(
        "Target list", keys, index=default, key="hist_target_set",
        format_func=lambda k: f"{_targets_label(meta[k]['targets'], seeds=meta[k].get('seeds'))} · {meta[k]['runs']} run(s) · last {format_created(meta[k]['latest'], timezone)}"
                              + ("  (current)" if k == current_key else ""),
    )
    runs = list_runs(key)
    if not runs:
        st.info("No runs saved for this target list.")
        return
    table(_runs_table(runs, timezone, current_run_id))
    tabs = st.tabs(["Run Details", "Compare Runs", "Trends", "Domain History", "Hunt Tree", "Watched Lists",
                    "Manage Runs"], key=HISTORY_TAB_KEY, on_change="rerun")
    navigation.scroll_to_tab()
    with tabs[0]:
        _render_run_details(key, runs, timezone)
    with tabs[1]:
        _render_comparison(key, runs, timezone)
    with tabs[2]:
        _render_trends(key, timezone)
    with tabs[3]:
        _render_domain_history(current_key or key, timezone)
    with tabs[4]:
        _render_hunt_tree(timezone, current_run_id)
    with tabs[5]:
        _render_watches(timezone)
    with tabs[6]:
        _render_manage(key, runs, timezone)

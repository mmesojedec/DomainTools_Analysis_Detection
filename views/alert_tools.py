"""Alert triage tools: heatmap (click-to-filter), MITRE ATT&CK view, filters, suppressions, run diff, and exports."""
import re
from dataclasses import dataclass, field

import pandas as pd
import plotly.express as px
import streamlit as st

from config import SEVERITY_WEIGHTS
from core.export import build_report_html, build_report_markdown, dataset_iocs, to_stix_bundle
from core.helpers import md_escape
from core.intel_data import CONFIDENCE_ORDER, MITRE_TACTICS, TACTIC_ORDER
from core.persistence import add_suppression, remove_suppression
from core.triage import STATUS_HELP, STATUSES
from views.common import chart, table

SEVERITY_ORDER = ["Critical", "High", "Medium-High", "Medium", "Low"]
_TECHNIQUE_RE = re.compile(r"\b(T\d{4})(?:\.(\d{3}))?\b")


@dataclass
class AlertView:
    """Alerts prepared for display: active vs. suppressed, plus run-to-run comparison."""
    active: pd.DataFrame
    suppressed: pd.DataFrame
    suppressions: list = field(default_factory=list)
    new_mask: pd.Series = None                  # not in the previous run (for "Changes Since Last Run")
    previous_snapshot: dict = None
    artifact_diff: pd.DataFrame = field(default_factory=pd.DataFrame)
    first_detected_mask: pd.Series = None       # never seen in any earlier run of this target list
    resolved: pd.DataFrame = field(default_factory=pd.DataFrame)
    history_runs: int = 0


def render_alert_overview(alerts):
    """Heatmap (domain x category) and ATT&CK views. Returns the selected (domain, category) cells."""
    if alerts.empty:
        return set()
    st.markdown("#### Alert Overview",
                help="Click or box-select heatmap cells to filter the detections table below. Double-click to clear.")
    tab_heat, tab_mitre = st.tabs(["Alert Heatmap (click to filter)", "MITRE ATT&CK"])
    with tab_heat:
        selected = _render_heatmap(alerts)
    with tab_mitre:
        render_mitre_view(alerts)
    return selected


HEATMAP_SEVERITY_COLORS = {
    "Critical": "#DC2626", "High": "#F97316", "Medium-High": "#F59E0B", "Medium": "#EAB308", "Low": "#3B82F6",
}
HEATMAP_ROW_PX = 34      # fixed height per domain row so cells never overlap
HEATMAP_CELL_PX = 24     # square size; fits inside a row with a visible gap


def _render_heatmap(alerts):
    weights = alerts["Severity"].map(SEVERITY_WEIGHTS).fillna(0)
    cells = alerts.assign(Weight=weights).groupby(["Domain", "Category"]).agg(
        Alerts=("Threat Type", "size"), Max_Weight=("Weight", "max"),
        Threats=("Threat Type", lambda x: "<br>".join(sorted(set(x))[:8])),
    ).reset_index()
    weight_to_label = {v: k for k, v in SEVERITY_WEIGHTS.items()}
    cells["Worst Severity"] = cells["Max_Weight"].map(weight_to_label).fillna("Low")

    # Rows sorted by total alerts (busiest domain on top); columns by total alerts per category
    domain_order = cells.groupby("Domain")["Alerts"].sum().sort_values(ascending=True).index.tolist()
    category_order = cells.groupby("Category")["Alerts"].sum().sort_values(ascending=False).index.tolist()
    severities = [s for s in SEVERITY_ORDER if s in set(cells["Worst Severity"])]

    fig = px.scatter(
        cells, x="Category", y="Domain", color="Worst Severity", text="Alerts",
        color_discrete_map=HEATMAP_SEVERITY_COLORS,
        category_orders={"Worst Severity": severities, "Domain": domain_order, "Category": category_order},
        custom_data=["Domain", "Category"],
        hover_data={"Alerts": True, "Worst Severity": True, "Threats": True, "Domain": True, "Category": True},
        title="Detections by Domain and Category (number = alert count, color = worst severity)",
    )
    fig.update_traces(
        marker=dict(symbol="square", size=HEATMAP_CELL_PX, line=dict(width=1, color="rgba(255,255,255,0.6)")),
        textposition="middle center", textfont=dict(color="white", size=11),
    )
    n_domains = len(domain_order)
    fig.update_layout(
        legend=dict(title_text="Worst severity", orientation="h", yanchor="bottom", y=1.0, x=0, xanchor="left",
                    itemsizing="constant", font=dict(size=11)),
        title=dict(y=0.99, yanchor="top"),
        margin=dict(t=80, l=10, r=10, b=10),
    )
    fig.update_xaxes(tickangle=-30, title="", side="top" if n_domains > 15 else "bottom", automargin=True,
                     showgrid=True, gridcolor="rgba(255,255,255,0.06)")
    fig.update_yaxes(title="", automargin=True, showgrid=True, gridcolor="rgba(255,255,255,0.06)",
                     range=[-0.6, n_domains - 0.4])
    points = chart(fig, key="alert_heatmap", height=max(300, n_domains * HEATMAP_ROW_PX + 220), selectable=True)
    selected = set()
    for point in points:
        custom = point.get("customdata") if isinstance(point, dict) else getattr(point, "customdata", None)
        if custom and len(custom) >= 2:
            selected.add((custom[0], custom[1]))
    return selected


def _tactic_rows(alerts):
    rows = []
    for _, row in alerts.iterrows():
        for base, sub in _TECHNIQUE_RE.findall(str(row["MITRE ATT&CK"])):
            technique = f"{base}.{sub}" if sub else base
            rows.append({"Tactic": MITRE_TACTICS.get(base, "Other"), "Technique": technique,
                         "Threat Type": row["Threat Type"], "Domain": row["Domain"]})
    return pd.DataFrame(rows)


def render_mitre_view(alerts):
    rows = _tactic_rows(alerts)
    if rows.empty:
        st.info("No ATT&CK technique IDs found on the current detections.")
        return
    col1, col2 = st.columns([1.6, 1])
    with col1:
        fig = px.treemap(rows.assign(Count=1), path=[px.Constant("ATT&CK"), "Tactic", "Technique", "Threat Type"], values="Count",
                         color="Tactic", title="Detections by Tactic ➔ Technique ➔ Rule")
        fig.update_layout(margin=dict(t=40, l=5, r=5, b=5))
        chart(fig, key="mitre_treemap", height=460)
    with col2:
        matrix = rows.groupby(["Tactic", "Technique"]).agg(Alerts=("Threat Type", "size"), Domains=("Domain", "nunique")).reset_index()
        matrix["Tactic"] = pd.Categorical(matrix["Tactic"], categories=TACTIC_ORDER, ordered=True)
        table(matrix.sort_values(["Tactic", "Alerts"], ascending=[True, False]))


THREAT_TYPE_KEY = "flt_threat_type"   # Alerts page threat-type filter; links from other pages preset it


def render_alert_filters(view, selected_cells):
    """Confidence / severity filters plus heatmap selection. Returns the filtered alerts."""
    alerts = view.active
    if alerts.empty:
        return alerts
    col1, col2, col3, col4 = st.columns([1.2, 1.4, 1.4, 2])
    types = sorted(alerts["Threat Type"].astype(str).unique())
    if THREAT_TYPE_KEY in st.session_state:   # preset by a link from another page: keep what this run still has
        st.session_state[THREAT_TYPE_KEY] = [t for t in st.session_state[THREAT_TYPE_KEY] if t in types]
    with col1:
        confidences = st.multiselect("Confidence", CONFIDENCE_ORDER, default=CONFIDENCE_ORDER, key="flt_confidence")
    with col2:
        severities = st.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER, key="flt_severity")
    with col3:
        statuses = st.multiselect("Status", STATUSES, default=STATUSES, key="flt_status", help=STATUS_HELP)
    with col4:
        chosen = st.multiselect("Threat type", types, key=THREAT_TYPE_KEY, placeholder="Every threat type")
    mask = alerts["Confidence"].isin(confidences) & alerts["Severity"].isin(severities)
    if chosen:
        mask &= alerts["Threat Type"].isin(chosen)
    if "Status" in alerts.columns:
        mask &= alerts["Status"].isin(statuses)
    if selected_cells:
        cell_keys = list(zip(alerts["Domain"], alerts["Category"]))
        mask &= pd.Series([key in selected_cells for key in cell_keys], index=alerts.index)
        st.caption(f"Filtered to {len(selected_cells)} heatmap cell(s). Double-click the heatmap background to clear the selection.")
    return alerts[mask]


def render_first_detected_toggle(view):
    """'Only first detected in this run' checkbox; disabled until an earlier saved run covers these domains."""
    if not view.history_runs:
        st.checkbox("Only first detected in this run", value=False, key="flt_only_new", disabled=True,
                    help="No earlier saved run covers these domains yet; this filter becomes available on the next run.")
        return False
    first_count = int(view.first_detected_mask.sum()) if view.first_detected_mask is not None else 0
    return st.checkbox(f"Only first detected in this run ({first_count})", value=False, key="flt_only_new",
                       help=f"Hides detections already seen in any of the {view.history_runs} earlier saved run(s) "
                            "that covered these domains (from any target list).")


def apply_first_detected(alerts, view, only_new):
    if not only_new or view.first_detected_mask is None or alerts.empty:
        return alerts
    return alerts[view.first_detected_mask.reindex(alerts.index, fill_value=False)]


def render_suppression_manager(view):
    with st.expander(f"Manage Suppressions ({len(view.suppressions)} rule(s), {len(view.suppressed)} alert(s) hidden)", expanded=False):
        st.caption("Suppressed alerts are hidden from the dashboard, KPIs, and exports. Stored locally in dt_suppressions.json.")
        alerts = pd.concat([view.active, view.suppressed], ignore_index=True)
        if not alerts.empty:
            with st.form("add_suppression", clear_on_submit=True):
                col1, col2 = st.columns(2)
                domain = col1.selectbox("Domain", ["*"] + sorted(alerts["Domain"].unique()), help="'*' applies to every domain.")
                threat_type = col2.selectbox("Threat Type", sorted(alerts["Threat Type"].unique()))
                note = st.text_input("Reason / note", placeholder="e.g. known CDN rotation, approved vendor")
                if st.form_submit_button("Suppress"):
                    add_suppression(domain, threat_type, note)
                    st.rerun()
        if view.suppressions:
            for entry in view.suppressions:
                col1, col2 = st.columns([5, 1])
                col1.markdown(f"**{md_escape(entry['threat_type'])}** on `{entry['domain']}` — {md_escape(entry.get('note') or 'no note')} "
                              f"(added {entry.get('created', '')})")
                if col2.button("Remove", key=f"rm_supp_{entry['id']}"):
                    remove_suppression(entry["id"])
                    st.rerun()
        if not view.suppressed.empty:
            st.markdown("##### Currently Suppressed Alerts")
            table(view.suppressed[["Domain", "Threat Type", "Severity", "Confidence", "Threat Logic"]])


def render_run_diff(view):
    if not view.previous_snapshot:
        return
    diff = view.artifact_diff
    new_alerts = int(view.new_mask.sum()) if view.new_mask is not None else 0
    added = int((diff["Change"] == "Added").sum()) if not diff.empty else 0
    removed = int((diff["Change"] == "Removed").sum()) if not diff.empty else 0
    resolved = len(view.resolved)
    label = (f"Changes Since Last Run ({view.previous_snapshot.get('created', '?')}): {new_alerts} new / {resolved} resolved alert(s), "
             f"{added} added / {removed} removed artifact(s)")
    previous_window = view.previous_snapshot.get("window")
    current_window = st.session_state.get("window_label")
    with st.expander(label, expanded=bool(new_alerts or added)):
        if previous_window and current_window and previous_window != current_window:
            st.caption(f"The previous run's alerts were saved with the '{previous_window}' window (now '{current_window}'), "
                       "so some 'new' alerts may only reflect the different window.")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("New Alerts", new_alerts)
        col2.metric("Resolved Alerts", resolved)
        col3.metric("Artifacts Added", added)
        col4.metric("Artifacts Removed", removed)
        if not diff.empty:
            counts = diff.groupby(["Domain", "Artifact", "Change"]).size().reset_index(name="Count")
            fig = px.bar(counts, x="Domain", y="Count", color="Artifact", pattern_shape="Change", barmode="stack",
                         title="Infrastructure Changes by Domain")
            chart(fig, key="run_diff_chart", height=340)
            table(diff)
        if new_alerts:
            st.markdown("##### New Alerts")
            table(view.active[view.new_mask.reindex(view.active.index, fill_value=False)][["Domain", "Threat Type", "Severity", "Confidence"]])
        if resolved:
            st.markdown("##### Resolved Since Last Run")
            st.caption("Detections present in the previous run that no longer fire (fixed, taken down, or outside the current window).")
            table(view.resolved[[c for c in ["Domain", "Threat Type", "Severity", "Confidence", "Threat Logic"] if view.resolved[c].notna().any()]])
        st.caption("Open **Manage Data → Runs & Diffs** to compare any two runs.")


def render_exports(ds, alerts, profiles, correlation):
    with st.expander("Export Detections, IOCs & Report", expanded=False):
        iocs = dataset_iocs(ds)
        st.caption(f"{len(alerts)} detection(s) and {len(iocs)} indicator(s) for the current filters (suppressed alerts excluded).")
        col1, col2, col3 = st.columns(3)
        col1.download_button("Detections (CSV)", alerts.drop(columns=["Evidence"], errors="ignore").to_csv(index=False).encode(), "detections.csv", "text/csv", width="stretch")
        col2.download_button("IOCs (CSV)", iocs.to_csv(index=False).encode(), "iocs.csv", "text/csv", width="stretch")
        col3.download_button("IOCs (JSON)", iocs.to_json(orient="records", indent=2).encode(), "iocs.json", "application/json", width="stretch")
        col4, col5, col6 = st.columns(3)
        col4.download_button("STIX 2.1 Bundle", to_stix_bundle(iocs, alerts).encode(), "stix_bundle.json", "application/json", width="stretch")
        col5.download_button("Evidence Report (HTML)", build_report_html(ds, alerts, profiles, iocs, correlation).encode(),
                             "detection_report.html", "text/html", width="stretch")
        col6.download_button("Evidence Report (Markdown)", build_report_markdown(ds, alerts, profiles, iocs, correlation).encode(),
                             "detection_report.md", "text/markdown", width="stretch")
        st.dataframe(iocs, width="stretch", hide_index=True, height=260)

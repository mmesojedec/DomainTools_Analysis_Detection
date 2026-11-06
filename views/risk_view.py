"""Lens 1: KPI banner, Digital Risk & Threat Engine, and DomainTools Risk Evidence."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from config import DT_BLUE, DT_GREEN, DT_ORANGE, DT_SLATE, SEVERITY_WEIGHTS
from core.alert_grouping import GROUP_MODES, alert_evidence, group_alerts
from core.helpers import md_escape
from core.persistence import add_suppression
from core.risk_profile import DIF_SEGMENTS, VECTOR_COLUMNS, decode_profiles
from core.rule_catalog import COLUMN_GUIDE, CONFIDENCE_LEVELS, SEVERITY_LEVELS, rule_catalog_frame
from core.timezone import apply_tz_shift
from core.triage import STATUS_COLORS, STATUS_HELP, STATUSES, set_status
from views.alert_tools import (
    apply_first_detected,
    render_alert_filters,
    render_alert_overview,
    render_exports,
    render_first_detected_toggle,
    render_run_diff,
    render_suppression_manager,
)
from views.common import chart, table
from views.export_view import render_confirmed_export

SANKEY_PALETTE = [DT_BLUE, DT_GREEN, DT_ORANGE, "#E13A3E", "#009E73", "#F0E442", "#0072B2", "#D55E00", "#CC79A7"]
SEVERITY_LABEL_COLORS = {"Critical": "red", "High": "orange", "Medium-High": "orange", "Medium": "violet", "Low": "blue"}
GROUP_PAGE_SIZE = 20
ALERT_TABLE_COLUMNS = ["Domain", "Risk", "Risk Evidence", "Threat Type", "MITRE ATT&CK", "Severity", "Confidence", "Status",
                       "Category", "Occurrences", "First Detected", "Runs Seen", "Threat Logic", "Triage Note"]
ALERT_COLUMN_CONFIG = {
    "First Detected": st.column_config.DatetimeColumn("First Detected", format="YYYY-MM-DD HH:mm",
                                                      help="First saved run (any target list) in which this detection appeared for this domain"),
    "Runs Seen": st.column_config.NumberColumn("Runs Seen", help="Number of saved runs (including this one) with this detection"),
    "Occurrences": st.column_config.NumberColumn("Occurrences", help="Matching certificates / records merged into this detection"),
    "Status": st.column_config.Column("Status", help=STATUS_HELP.replace("**", "")),
}


def render_kpi_banner(profiles, high_risk_cutoff):
    if profiles.empty:
        return
    max_risk = profiles["Unified Risk"].max()
    high_risk_cnt = int((profiles["Unified Risk"] >= high_risk_cutoff).sum())
    tot_doms = len(profiles)
    top_vector = profiles[VECTOR_COLUMNS].mean().idxmax()

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Max Digital Risk", f"{max_risk} / 100", delta="Critical" if max_risk >= high_risk_cutoff else "Low/Med",
              delta_color="inverse", help="The highest computed Unified Risk Score across all analyzed domains.")
    k2.metric("High-Risk Domains", f"{high_risk_cnt} of {tot_doms}",
              delta=f"{round((high_risk_cnt / tot_doms) * 100)}% of target list" if tot_doms else "0%",
              delta_color="inverse" if high_risk_cnt else "normal",
              help=f"Number of domains with a Unified Risk Score >= {high_risk_cutoff}.")
    k3.metric("Unique Infrastructure Profiles", profiles["DIF Fingerprint"].nunique(),
              help="Count of unique DIF Fingerprints. Fewer unique DIFs than domains suggests shared campaign infrastructure.")
    k4.metric("Primary Threat Driver", top_vector,
              help="The threat vector contributing the highest average score across the investigated domains.")
    st.divider()


def _render_profiles(profiles):
    col_rad, col_ledg = st.columns([1.2, 1.3])
    with col_rad:
        st.markdown("#### Digital Risk Vector Profile",
                    help="Radar chart mapping domain risk across 6 dimensions.")
        radar_melt = profiles.rename(columns={"Domain": "Domain / IP"}).melt(
            id_vars=["Domain / IP"], value_vars=VECTOR_COLUMNS, var_name="Risk Vector", value_name="Score"
        )
        fig = px.line_polar(radar_melt, r="Score", theta="Risk Vector", color="Domain / IP", line_close=True, range_r=[0, 100])
        fig.update_traces(fill="toself", opacity=0.6)
        fig.update_polars(radialaxis=dict(angle=90, tickangle=0, gridcolor="rgba(255, 255, 255, 0.2)"))
        fig.update_layout(margin=dict(t=30, l=30, r=30, b=30))
        chart(fig, height=380)

    with col_ledg:
        st.markdown("#### Infrastructure Fingerprints (DIF)",
                    help="Encodes hosting type, TLS validation tier, CA, validity, key size, app footprint, and a configuration hash.")
        st.caption(
            "**DIF** is a composite infrastructure signature summarizing each domain's hosting architecture, TLS certificate "
            "profile, and cloud service footprint. Identical DIFs across distinct root domains expose shared campaign infrastructure."
        )
        ledger = profiles[["Domain", "Unified Risk", "Base Domain Risk Score", "DIF Fingerprint", "DIF Breakdown"]] \
            .sort_values("Unified Risk", ascending=False).rename(columns={"Domain": "Domain / IP"})
        table(ledger, column_config={
            "Unified Risk": st.column_config.ProgressColumn("Unified Risk", format="%d", min_value=0, max_value=100),
            "Base Domain Risk Score": st.column_config.NumberColumn("Base Risk", format="%d"),
            "DIF Fingerprint": st.column_config.TextColumn("DIF Fingerprint", help="[Hosting]_[TLS]_[Apps]_[ConfigHash]"),
            "DIF Breakdown": st.column_config.TextColumn("DIF Breakdown", help="Hosting | TLS | Enterprise Services"),
        })
        if st.button("Decode DIF fingerprints", key="dif_reference",
                     help="What every DIF segment and code means, and each domain's fingerprint decoded."):
            _dif_reference_dialog(profiles)


@st.dialog("DIF fingerprints decoded", width="large")
def _dif_reference_dialog(profiles):
    st.markdown("A **DIF** (Domain Infrastructure Fingerprint) has four segments: `Hosting_TLS_Identity&Apps_ConfigHash`, "
                "e.g. `F-CF_DVLE-R2048_EM_3fa91c`. Identical DIFs, or identical configuration hashes, on unrelated domains "
                "point to shared campaign infrastructure.")
    st.markdown("**Fingerprints in this run**")
    decoded = decode_profiles(profiles)
    table(decoded, column_config={"Same DIF As": st.column_config.TextColumn(
        "Same DIF As", help="Other analyzed domains with an identical fingerprint")})
    st.markdown("**Segment codes**")
    reference = pd.DataFrame(DIF_SEGMENTS, columns=["Segment", "Format", "Code", "Meaning", "Derived From"])
    table(reference, height=35 * (len(reference) + 1) + 3)
    st.caption("The TLS segment describes the domain's primary (first listed) certificate; the identity code checks SPF first, "
               "then Google, then Microsoft 365 verification records.")


@st.dialog("Detection reasons", width="large")
def _detection_reasons_dialog(alerts):
    st.markdown("How each detection is assigned its **severity**, **confidence**, **category**, and **MITRE ATT&CK** technique.")
    col_sev, col_conf = st.columns(2)
    with col_sev:
        st.markdown("**Severity: impact if true**")
        st.table(pd.DataFrame([{"Severity": level, "Weight": SEVERITY_WEIGHTS[level], "Meaning": meaning}
                               for level, meaning in SEVERITY_LEVELS]).set_index("Severity"))
    with col_conf:
        st.markdown("**Confidence: likelihood it is a true positive**")
        st.table(pd.DataFrame(CONFIDENCE_LEVELS, columns=["Confidence", "Meaning"]).set_index("Confidence"))
    with st.expander("Alert columns explained"):
        st.table(pd.DataFrame(COLUMN_GUIDE, columns=["Column", "Meaning"]).set_index("Column"))
    catalog = rule_catalog_frame(alerts)
    fired = int((catalog["In This Run"] > 0).sum())
    only_fired = st.toggle(f"Only rules that fired in this run ({fired} of {len(catalog)})", value=fired > 0,
                           key="reasons_only_fired")
    if only_fired:
        catalog = catalog[catalog["In This Run"] > 0]
    table(catalog, height=min(560, 35 * (len(catalog) + 1) + 3), column_config={
        "In This Run": st.column_config.NumberColumn("In This Run", help="Active detections of this rule in the current run"),
        "Severity": st.column_config.TextColumn("Severity", help="As assigned by the rule; some rules depend on the evidence"),
        "Confidence": st.column_config.TextColumn("Confidence", help="Default per rule; some rules adjust it at runtime"),
        "Fires When": st.column_config.TextColumn("Fires When", width="large"),
        "Why It Matters": st.column_config.TextColumn("Why It Matters", width="large"),
    })
    st.caption("Threshold names (e.g. Min Risk Score, DGA Entropy Score) refer to Settings → Detection thresholds. "
               "Lookalike rules need a brand watchlist.")


def _render_engine_status(threats, min_risk):
    col_a, col_b = st.columns([2.5, 1])
    with col_a:
        if min_risk > 0:
            if threats.skipped_domains:
                st.info(f"**Risk Score Threshold Active:** Skipped threat analysis for **{len(threats.skipped_domains)} domain(s)** "
                        f"with a known risk score below **{min_risk}**: {md_escape(', '.join(threats.skipped_domains))}")
            else:
                st.info(f"**Risk Score Threshold Active:** All scored domains meet or exceed threshold **{min_risk}**.")
        else:
            st.warning("**Risk Score Threshold Disabled:** Evaluating all domains regardless of risk score.")
        if threats.unscored_domains:
            st.warning(f"**No risk score available** for {len(threats.unscored_domains)} domain(s); they were evaluated anyway: "
                       f"{md_escape(', '.join(threats.unscored_domains))}. Check the Data Source Status panel for Risk Evidence errors.")
    with col_b:
        st.info(f"**Current Filter Level:**\n\n* **Filter Active (Score >= {min_risk})**")


GROUP_BY_HELP = ("Finding: one group per detection rule across domains. Campaign Cluster: domains linked by shared "
                 "certificates, keys, trackers, or IP + name server. Domain: everything for one domain. "
                 "ATT&CK Technique: by primary technique.")


def _render_alert_controls(view):
    """Layout, grouping, first-detected filter, and detection reasons in one row. Returns (layout, mode, only_new)."""
    col_layout, col_mode, col_new, col_reasons = st.columns([0.8, 2.2, 1.9, 1.0], vertical_alignment="bottom")
    layout = col_layout.radio("Layout", ["Grouped", "Table"], horizontal=True, key="alert_layout")
    mode = col_mode.radio("Group by", GROUP_MODES, horizontal=True, key="alert_group_mode", help=GROUP_BY_HELP,
                          disabled=layout == "Table")
    with col_new:
        only_new = render_first_detected_toggle(view)
    if col_reasons.button("Detection reasons", key="detection_reasons", width="stretch",
                          help="What every detection means and how its severity and confidence are set."):
        _detection_reasons_dialog(view.active)
    return layout, mode, only_new


def _render_threats(alerts, threats, total_active, timezone="UTC", layout="Grouped", mode="Finding"):
    if total_active == 0:
        st.success(f"Clean: No automated threat patterns matched the {len(threats.evaluated_domains)} domain(s) evaluated by the engine.")
        return
    if alerts.empty:
        st.info(f"No detections match the current filters ({total_active} active detection(s) in total).")
        return
    shown = f"{len(alerts)} of {total_active}" if len(alerts) != total_active else str(len(alerts))
    st.error(f"**Action Required:** {shown} potential threat indicator(s) automatically detected.")
    if layout == "Table":
        table(alerts[[c for c in ALERT_TABLE_COLUMNS if c in alerts.columns]], column_config=ALERT_COLUMN_CONFIG)
        return
    _render_alert_groups(alerts, threats.correlation, timezone, mode)


@st.fragment
def _render_alert_groups(alerts, correlation, timezone, mode):
    """Grouped findings in a fragment, so paging, raw IOC toggles, and expanders only rerun this section."""
    groups = group_alerts(alerts, mode, correlation)
    caption = f"{len(groups)} group(s) from {len(alerts)} detection(s), most severe first. Expand a group to see its related events."
    if len(groups) > GROUP_PAGE_SIZE:
        pages = [f"{i + 1}-{min(i + GROUP_PAGE_SIZE, len(groups))}" for i in range(0, len(groups), GROUP_PAGE_SIZE)]
        page = st.selectbox("Groups", pages, key=f"alert_group_page_{mode}")
        offset = pages.index(page) * GROUP_PAGE_SIZE
        groups = groups.iloc[offset:offset + GROUP_PAGE_SIZE]
    st.caption(caption)
    for _, group in groups.iterrows():
        _render_alert_group(alerts.loc[group["Members"]], group, mode, timezone)


def _span_text(first, last):
    if pd.isna(first):
        return ""
    first_day, last_day = f"{first:%Y-%m-%d}", f"{last:%Y-%m-%d}" if pd.notna(last) else ""
    return f" · {first_day}" if first_day == last_day or not last_day else f" · {first_day} → {last_day}"


def _group_status(members):
    statuses = set(members["Status"]) if "Status" in members.columns else {"New"}
    return next(iter(statuses)) if len(statuses) == 1 else "Mixed"


def _render_triage_form(members, key):
    """Sets one status and note for every alert of the group (dt_triage.json)."""
    current = _group_status(members)
    notes = [n for n in members.get("Triage Note", []) if n]
    with st.form(f"triage_{key}", border=False):
        c_status, c_note, c_save = st.columns([1.2, 3, 1], vertical_alignment="bottom")
        status = c_status.selectbox("Status", STATUSES, index=STATUSES.index(current) if current in STATUSES else 0,
                                    key=f"triage_status_{key}", help=STATUS_HELP)
        note = c_note.text_input("Note", value=notes[0] if notes else "", key=f"triage_note_{key}",
                                 placeholder="Why: e.g. known vendor, confirmed phishing kit, ticket number")
        if c_save.form_submit_button(f"Save for {len(members)} alert(s)", width="stretch"):
            set_status(zip(members["Domain"], members["Threat Type"]), status, note)
            st.toast(f"{len(members)} alert(s) marked {status}.")
            st.rerun()


def _render_alert_group(members, group, mode, timezone):
    severity = group["Worst Severity"]
    status = _group_status(members)
    badge = "" if status == "New" else f" :{STATUS_COLORS.get(status, 'gray')}-badge[{status}]"
    label = (f":{SEVERITY_LABEL_COLORS.get(severity, 'gray')}[**{severity}**] {md_escape(group['Label'])} · "
             f"{group['Domains']} domain(s) · {group['Alerts']} alert(s){_span_text(group['First Seen'], group['Last Seen'])}"
             f"{badge}")
    with st.expander(label):
        _render_triage_form(members, f"{mode}:{group['Group']}")
        if mode != "Domain":
            domains = group["Domain List"]
            st.caption("**Domains:** " + md_escape(", ".join(domains[:25])) + (f" … (+{len(domains) - 25})" if len(domains) > 25 else ""))
        if mode != "Finding":
            st.caption("**Findings:** " + md_escape(", ".join(group["Threat Types"])))
        columns = [c for c in ALERT_TABLE_COLUMNS if c in members.columns and not (mode == "Domain" and c in ("Domain", "Risk", "Risk Evidence"))]
        table(members[columns], column_config=ALERT_COLUMN_CONFIG)

        evidence = apply_tz_shift(alert_evidence(members), ["Time"], timezone)
        hidden = {"Domain"} if mode == "Domain" else {"Threat Type"} if mode == "Finding" else set()
        if mode == "Finding" and len(members) == 1:
            hidden.add("Domain")
        st.markdown(f"**Related events ({len(evidence)})**")
        table(evidence[[c for c in evidence.columns if c not in hidden]], height=min(420, 35 * (len(evidence) + 1) + 3),
              column_config={"Time": st.column_config.DatetimeColumn(f"Time ({timezone})", format="YYYY-MM-DD HH:mm:ss"),
                             "Artifact": st.column_config.TextColumn("Artifact", help="Pivotable indicator (certificate hash, IP, ...)")})

        key = f"{mode}:{group['Group']}"
        col_raw, col_suppress = st.columns([3, 1])
        if col_raw.toggle("Show raw IOC text", key=f"raw_iocs_{key}"):
            for _, row in members.iterrows():
                st.markdown(f"**{md_escape(row['Domain'])} — {md_escape(row['Threat Type'])}:** {md_escape(row['Threat Logic'])}")
                st.code(row["Triggering IOCs"], language="text")
        if col_suppress.button(f"Suppress {len(members)} alert(s)", key=f"suppress_group_{key}", width="stretch",
                               help="Adds one suppression per (domain, finding) in this group. Manage them under Manage Suppressions."):
            for domain, threat_type in dict.fromkeys(zip(members["Domain"], members["Threat Type"])):
                add_suppression(domain, threat_type, f"Suppressed with group '{group['Label']}'")
            st.rerun()


def _hex_to_rgba(hex_code, alpha=0.4):
    code = str(hex_code).lstrip("#")
    try:
        return f"rgba({int(code[0:2], 16)},{int(code[2:4], 16)},{int(code[4:6], 16)},{alpha})"
    except ValueError:
        return f"rgba(76, 104, 253, {alpha})"


def _render_risk_sankey(risk):
    sankey_df = risk[risk["Evidence"].fillna("") != ""]
    if sankey_df.empty:
        st.info("No underlying evidence mapped to risk scores to generate flow diagram.")
        return
    unique_domains = list(sankey_df["Domain"].unique())
    focus_dom = st.selectbox("Focus Flow on Specific Domain:", ["View All Domains"] + unique_domains, key="sankey_focus_risk")
    if focus_dom != "View All Domains":
        sankey_df = sankey_df[sankey_df["Domain"] == focus_dom]

    domain_colors = {dom: SANKEY_PALETTE[i % len(SANKEY_PALETTE)] for i, dom in enumerate(unique_domains)}
    label_index, labels, node_colors = {}, [], []
    source, target, value, link_colors = [], [], [], []

    def node(name, color=DT_SLATE):
        if name not in label_index:
            label_index[name] = len(labels)
            labels.append(name)
            node_colors.append(color)
        return label_index[name]

    for _, row in sankey_df.iterrows():
        color = domain_colors.get(row["Domain"], DT_BLUE)
        weight = row["Score"] if row["Score"] and row["Score"] > 0 else 1
        dom_idx = node(row["Domain"], color)
        comp_idx = node(str(row["Component"]).replace("Threat Profile ", ""))
        source.append(dom_idx), target.append(comp_idx), value.append(weight), link_colors.append(_hex_to_rgba(color))
        for ev in (e.strip() for e in str(row["Evidence"]).split(",") if e.strip()):
            source.append(comp_idx), target.append(node(ev.title())), value.append(weight), link_colors.append(_hex_to_rgba(color))

    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=15, thickness=20, label=labels, color=node_colors),
        link=dict(source=source, target=target, value=value, color=link_colors),
    )])
    fig.update_layout(title_text="Risk Attribution Flow (Domain ➔ Threat ➔ Evidence)", font_size=12)
    chart(fig, key="sankey_chart_risk", height=450)


def _render_risk_evidence(risk):
    st.subheader("Domain Risk Evidence (Scores & Threats)",
                 help="DomainTools risk scores by component (Phishing, Malware, Spam) with mapped evidence tags.")
    tab_bar, tab_radar, tab_sankey = st.tabs(["Score Comparison (Bar)", "Threat Profile (Radar)", "Attribution Flow (Sankey)"])
    with tab_bar:
        fig = px.bar(risk, x="Domain", y="Score", color="Component", barmode="group",
                     hover_data={"Threats": True, "Evidence": True}, title="Domain Risk Score by Component")
        fig.update_layout(yaxis_title="Risk Score (0-100)")
        chart(fig, key="bar_risk", height=400)
    with tab_radar:
        radar_df = risk[~risk["Component"].isin(["Overall Risk", "Threat Profile"])].copy()
        if radar_df.empty:
            st.info("No specific threat components available to plot on radar.")
        else:
            radar_df["Component"] = radar_df["Component"].str.replace("Threat Profile ", "")
            fig = px.line_polar(radar_df, r="Score", theta="Component", color="Domain", line_close=True, title="Risk Component Topology")
            fig.update_traces(fill="toself")
            chart(fig, key="radar_risk", height=450)
    with tab_sankey:
        _render_risk_sankey(risk)

    st.markdown("#### Risk Components & Evidence Details",
                help="Component-specific risk scores, threats, and raw evidence flags.")
    detail_df = risk[risk["Component"] != "Overall Risk"]
    if not detail_df.empty:
        table(detail_df)


def render_risk_lens(ds, profiles, threats, thresholds, view):
    st.subheader("Digital Risk & Threat Engine",
                 help="Combines DomainTools risk score baselines with telemetry penalty vectors into a Unified Digital Risk score and DIF fingerprints.")
    if not profiles.empty:
        _render_profiles(profiles)
    _render_engine_status(threats, thresholds["risk_score"])
    render_run_diff(view)
    selected_cells = render_alert_overview(view.active)
    filtered = render_alert_filters(view, selected_cells)
    layout, mode = "Grouped", "Finding"
    if not view.active.empty:
        layout, mode, only_new = _render_alert_controls(view)
        filtered = apply_first_detected(filtered, view, only_new)
    _render_threats(filtered, threats, len(view.active), ds.timezone, layout, mode)
    render_suppression_manager(view)
    render_exports(ds, filtered, profiles, threats.correlation)
    render_confirmed_export(ds, view.active)
    if not ds.risk.empty:
        _render_risk_evidence(ds.risk)
    st.divider()

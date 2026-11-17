"""
The loaded run's hunting work on the Hunt map (moved there from the Summary, which keeps a short pointer): the alert
decisions so far, what to check next (each with a button to the right page), and the strong leads of All pivots
the suggested hunt doesn't already list. Local data only: nothing here makes an API call until a button is clicked.
"""
import pandas as pd
import streamlit as st

from core.cname import dataset_cname_map
from core.helpers import md_escape
from core.hunt_result import norm
from core.next_steps import next_steps
from core.pivots import top_leads
from core.triage import STATUS_HELP, open_alerts, triage_counts
from views import navigation
from views.hunt_actions import analyze_button, iris_button
from views.pivot_view import dataset_pivots

SIGNAL_BADGES = {"Strong": "green", "Useful": "blue"}


def render_alert_decisions(alerts, verdicts):
    """Your decisions on the alerts and domains of the loaded run (kept between runs)."""
    counts = triage_counts(alerts)
    st.markdown("**Alert decisions**", help="Your decisions on the alerts (Alerts page, in each group) and on domains "
                                            "(Domain profile). They are kept between runs, so a rerun shows what is "
                                            "still open. " + STATUS_HELP.replace("**", ""))
    columns = st.columns(5)
    columns[0].metric("Open alerts", f"{counts['New'] + counts['Investigating']:,}",
                      help="New and Investigating: still need a decision")
    columns[1].metric("Investigating", f"{counts['Investigating']:,}")
    columns[2].metric("Benign", f"{counts['Benign']:,}")
    columns[3].metric("Malicious", f"{counts['Malicious']:,}", help="Confirmed bad; exported as confirmed indicators")
    malicious = [d for d, s in verdicts.items() if s == "Malicious"]
    columns[4].metric("Domains marked malicious", f"{len(malicious):,}", help=", ".join(malicious) or None)


def check_next(ctx, alerts):
    """The loaded run's "What to check next" steps."""
    view = ctx.view
    new_alerts = int(view.new_mask.sum()) if view.new_mask is not None else 0
    return next_steps(open_alerts(alerts), ctx.profiles, dataset_cname_map(ctx.ds), ctx.collected.statuses,
                      new_alerts, len(view.resolved), ctx.thresholds["high_risk_score"])


def render_check_next(ctx, alerts):
    steps = [step for step in check_next(ctx, alerts) if navigation.page(step["page"]) is not None]
    st.markdown("**What to check next**", help="Built from the open alerts (not yet marked Benign or Malicious), the "
                                               "riskiest domain, CNAME chains and the lookups. The indicators to "
                                               "confirm are under *Start here* below.")
    if not steps:
        st.caption("Nothing stands out: no open serious alerts, no open CNAME chains and every lookup succeeded.")
    for i, step in enumerate(steps):
        c_text, c_button = st.columns([5, 1.3], vertical_alignment="center")
        c_text.markdown(f"{step['icon']} {step['text']}")
        navigation.jump_button(step["page"], f"Open {navigation.title(step['page'])}", step["state"],
                               button_key=f"next_step::{i}", container=c_button, width="stretch")


def more_leads(ds, listed):
    """All pivots's strong leads not already a branch or step of the suggested hunt (`listed`: lower-case values)."""
    leads = top_leads(dataset_pivots(ds))
    if leads is None or leads.empty:
        return leads
    return leads[~leads["Value"].map(norm).isin(listed)]


def render_more_leads(ds, listed):
    """The other strong leads, each one click from a new run or an Iris search."""
    leads = more_leads(ds, listed)
    if leads is None or leads.empty:
        return
    with st.expander(f"More leads (All pivots): {len(leads)}", icon=":material/hub:"):
        st.caption("Rare values of the run's domains (shared by only a few hundred domains in Iris) that the suggested "
                   "hunt above doesn't list. Values two or more of your domains share come first.")
        for i, lead in leads.iterrows():
            count = (f"{int(lead['Iris Domains']):,} domains in Iris" if pd.notna(lead["Iris Domains"])
                     else "count unknown")
            shared = f" · shared by **{lead['Run Domains']}** of your domains" if lead["Run Domains"] > 1 else \
                f" · {md_escape(lead['Shared With'])}"
            c_text, c_analyze, c_iris = st.columns([4, 1.3, 1], vertical_alignment="center")
            c_text.markdown(f":{SIGNAL_BADGES.get(lead['Signal'], 'gray')}-badge[{lead['Signal']}] **{lead['Type']}** "
                            f"`{lead['Value']}` · {count}{shared}")
            if lead["Analyze As"]:
                analyze_button([lead["Analyze As"]], f"{lead['Type']} {lead['Value']}", key=f"lead_hunt::{i}",
                               container=c_analyze, label="Analyze", width="stretch", direct=True)
            iris_button(lead["Iris Search"], key=f"lead_iris::{i}", container=c_iris, width="stretch")
        navigation.link("pivots", label="All pivots, ranked")

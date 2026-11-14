"""
Suggested hunt on the Summary page: where to start (the indicators the open alerts point at, in order), the hunt tree
this run would probably grow (its best leads, scored, with a look-ahead of what each would bring), and the leads set
aside with the reason. Local data only: nothing here makes an API call until a button is clicked.
"""
import pandas as pd
import streamlit as st

from core.helpers import md_escape
from core.hunt_plan import BRANCHES, LOOKAHEAD, followed, lookahead, score_leads, sightings_index, start_order
from core.hunt_tree import hunt_trail
from core.persistence import load_all_runs
from core.triage import open_alerts
from views import navigation
from views.hunt_actions import PIVOT_RESULTS_KEY, analyze_button, current_run_id, iris_button
from views.indicator_view import show_indicator
from views.pivot_view import dataset_pivots
from views.ssl_view import CERT_FOCUS_KEY

TOP_RUN = 3   # leads analyzed together by "Analyze the top 3 as one run"
KIND_LABELS = {"JA4X": "JA4X", "Certificate": "certificate", "IP": "IP", "Host": "host"}


def _context(ds):
    """(saved runs, this run's snapshot or None, runs started from it, values already analyzed in this hunt)."""
    runs = load_all_runs()
    run_id = current_run_id()
    this = next((snapshot for _, snapshot in runs if snapshot.get("id") == run_id), None)
    children = [snapshot for _, snapshot in runs if run_id and (snapshot.get("parent") or {}).get("id") == run_id]
    analyzed = set(ds.selected_domains)
    for snapshot in hunt_trail(runs, run_id) if run_id else []:
        analyzed |= set(snapshot.get("targets") or []) | set(snapshot.get("seeds") or [])
    return runs, this, children, analyzed


def _index(ds, runs, this):
    """The saved runs' values by target list, left out this run's own list; kept with the dataset until runs change."""
    key = (len(runs), runs[-1][1].get("id") if runs else None)
    cached = ds.derived.get("hunt_sightings")
    if not cached or cached[0] != key:
        own = {k for k, snapshot in runs if this is not None and snapshot.get("id") == this.get("id")}
        cached = (key, sightings_index(runs, exclude_keys=own))
        ds.derived["hunt_sightings"] = cached
    return cached[1]


def plan(ds, alerts):
    """(scored leads, start order, runs started from this run) for the Summary and the next steps."""
    runs, this, children, analyzed = _context(ds)
    open_ = open_alerts(alerts)
    leads = score_leads(dataset_pivots(ds), open_, analyzed, _index(ds, runs, this))
    return leads, start_order(open_, leads), children


def first_step(steps):
    """The first indicator to confirm, as a "What to check next" step, or None."""
    if not steps:
        return None
    step = steps[0]
    state = {CERT_FOCUS_KEY: step["value"]} if step["page"] == "certs" else {}   # the page narrowed to it
    return {"rank": 0.5, "page": step["page"], "state": state, "icon": ":material/flag:",
            "text": f"Confirm the {KIND_LABELS.get(step['kind'], step['kind'])} {step['value']} first ({step['why']}): "
                    "see *Suggested hunt* below"}


def _details(ds, alerts, kind, value, key, container):
    """'Details': the indicator in focus (its records, alerts, sightings and next steps already pointed at it)."""
    if container.button("Details", key=key, icon=":material/zoom_in:", width="stretch",
                        help="Everything this run knows about it, and its next steps (no API call)"):
        show_indicator(ds, alerts, kind, value)


def _render_start(ds, alerts, steps):
    st.markdown("**Start here**", help="The indicators the open alerts name, most severe first. Within a severity, "
                                        "what identifies an operator best comes first: a JA4X, then the certificate, "
                                        "then the IP, then other hosts. An indicator that is also a lead is followed "
                                        "by its shared domains.")
    for step in steps:
        c_text, c_button = st.columns([5, 1.3], vertical_alignment="center")
        if step["kind"] == "Lead":
            lead = step["lead"]
            c_text.markdown(f"{step['step']}. &nbsp;↳ {md_escape(step['why'])}")
            iris_button(lead["Iris Search"], key=f"plan_start_iris::{step['step']}", container=c_button,
                        width="stretch")
            continue
        on = f" on {md_escape(', '.join(step['domains'][:2]))}" if step["domains"] else ""
        c_text.markdown(f"{step['step']}. Confirm the {KIND_LABELS[step['kind']]} `{step['value']}`{on} · "
                        f":gray[{md_escape(step['why'])}]")
        _details(ds, alerts, step["kind"], step["value"], f"plan_start::{step['step']}", c_button)


def _render_branch(ds, alerts, number, lead, children, iris_results, index):
    done = followed(lead, children)
    badge = ":green-badge[followed]" if done else f":blue-badge[score {lead['Score']}]"
    count = f" · {lead['Iris Domains']:,} domains in Iris" if lead["Iris Domains"] else ""
    c_text, c_details, c_analyze, c_iris = st.columns([4, 1, 1, 1.1], vertical_alignment="center")
    c_text.markdown(f"&nbsp;&nbsp;↳ {badge} **{md_escape(lead['Type'])}** `{lead['Value']}`{count}  \n"
                    f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:gray[{md_escape('; '.join(lead['Reasons']))}]")
    _details(ds, alerts, lead["Type"], lead["Value"], f"plan_details::{number}", c_details)
    if done:
        navigation.link("hunt_tree", label="In the Hunt tree", container=c_analyze, icon=":material/park:")
    else:
        if lead["Analyze As"]:
            analyze_button([lead["Analyze As"]], f"{lead['Type']} {lead['Value']}", key=f"plan_hunt::{number}",
                           container=c_analyze, label="Analyze", width="stretch")
        iris_button(lead["Iris Search"], key=f"plan_iris::{number}", container=c_iris, width="stretch")
    if number < LOOKAHEAD and not done:
        for line in lookahead(lead, iris_results, index):
            st.markdown(f"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;:gray[⤷ {line}]")


def _render_set_aside(stopped):
    with st.expander(f"Set aside: {len(stopped)} lead(s) not worth following", icon=":material/block:"):
        st.caption("Leads that would fan out into infrastructure many unrelated domains use, or that this hunt already "
                   "analyzed.")
        frame = pd.DataFrame([{"Type": lead["Type"], "Value": lead["Value"], "Iris domains": lead["Iris Domains"],
                               "Why": lead["Stop"]} for lead in stopped])
        st.dataframe(frame, hide_index=True, width="stretch",
                     column_config={"Iris domains": st.column_config.NumberColumn(format="%d"),
                                    "Why": st.column_config.TextColumn(width="large")})


def render_suggested_hunt(ds, alerts, leads, steps, children):
    st.subheader("Suggested hunt",
                 help="Ranked from what this run already knows: how few domains share each lead in Iris, which open "
                      "alerts name it, what kind of value it is (certificates, tracker codes and contact emails "
                      "rarely are shared by chance), and whether earlier investigations saw it. A ranking, not a "
                      "prediction of what new lookups will find. Nothing here makes an API call until you click.")
    if steps:
        _render_start(ds, alerts, steps)
    branches = [lead for lead in leads if not lead["Stop"]][:BRANCHES]
    stopped = [lead for lead in leads if lead["Stop"]]
    if not branches:
        st.caption("No lead worth following: every value of these domains is either unique to them or shared "
                   "infrastructure." if leads else "No leads: Iris Investigate found no value these domains share "
                                                    "with other domains.")
    else:
        targets = ", ".join(ds.selected_domains[:3]) + (f" +{len(ds.selected_domains) - 3}"
                                                         if len(ds.selected_domains) > 3 else "")
        st.markdown(f"**The hunt this run would grow** · from **{md_escape(targets)}** (this run)",
                    help="The best leads, as the branches of a hunt tree. Under the first ones, what following them "
                         "would bring, from the Iris count, the saved runs and any Iris search already made on Pivot "
                         "Ranking. A branch you followed is marked and appears in the Hunt tree.")
        iris_results = st.session_state.get(PIVOT_RESULTS_KEY) or {}
        index = ds.derived.get("hunt_sightings", (None, {}))[1]
        for number, lead in enumerate(branches):
            _render_branch(ds, alerts, number, lead, children, iris_results, index)
        top = [lead for lead in branches if lead["Analyze As"] and not followed(lead, children)][:TOP_RUN]
        if len(top) > 1:
            analyze_button([lead["Analyze As"] for lead in top],
                           "Suggested hunt: " + ", ".join(f"{lead['Type']} {lead['Value']}" for lead in top),
                           key="plan_hunt_top", label=f"Analyze the top {len(top)} as one run",
                           help="Analyzes the best leads the app can take as targets (IPs, certificates, redirect "
                                "domains) together as one new run, linked to this one in the Hunt tree. Live lookups.")
    if stopped:
        _render_set_aside(stopped)

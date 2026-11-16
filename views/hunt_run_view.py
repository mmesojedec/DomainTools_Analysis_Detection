"""
Run the suggested hunt (Hunt → Hunt map, Summary): pick steps, then act on them. One
picked step gets its own buttons (Details, Analyze, Find in Iris, a CertsQL search for a JA4X); several run together:
their targets as one new run linked to this one, and their Iris searches. *Run suggested hunt…* lists every step in
order to tick, then runs them all at once, or one step at a time (guided). Nothing runs without a click.
"""
import html

import pandas as pd
import streamlit as st

from core.hunt_plan import MAX_TARGETS, run_parts, runnable, via_text
from core.pivots import iris_search_params
from integrations.enrichment import fetch_iris_pivot
from views import navigation
from views.hunt_actions import PIVOT_RESULTS_KEY
from views.indicator_view import _certsql_search, show_indicator
from views.sidebar import rerun_app_if_requested, start_hunt

OPEN_PIVOTS_KEY = "_hunt_open_pivots"   # set by a run of Iris searches only: open Pivot Ranking
GUIDE_KEY = "hunt_guide"   # guided hunt: {"parent", "label", "items", "position"}
LABEL = 22                 # characters of a value shown beside a graph node
ACTION_TEXT = {"Analyze": "Analyze as a new run", "Iris": "Find in Iris", "CertsQL": "Search CertsQL (by hand)",
               None: "Details only"}


def _short(text, limit=LABEL):
    text = str(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def searched(item):
    """Whether this session already made the step's Iris search (its results are on Pivot Ranking)."""
    return bool(item["search"]) and item["search"] in (st.session_state.get(PIVOT_RESULTS_KEY) or {})


def describe(item):
    """One line: what running the step does."""
    if item["action"] == "Analyze":
        return f"Analyze `{item['target']}`"
    if item["action"] == "Iris":
        return f"Iris search `{item['search']}`"
    if item["action"] == "CertsQL":
        return "Search CertsQL for its certificates (run it there)"
    return "Nothing to run: see Details"


def status(item):
    if item["done"]:
        return "followed"
    if item["action"] == "Iris" and searched(item):
        return "searched"
    return ""


# ---- running steps ------------------------------------------------------------------------------------------------

def start_steps(items, parent_id, prefix="Suggested hunt", guide_next=False):
    """
    Button callback (runs before the page, so it may set the sidebar targets): makes the steps' Iris searches (results
    kept for Pivot Ranking), then starts their targets as one new run linked to `parent_id`, straight through (no
    certificate review screens). With nothing to analyze, the page opens Pivot Ranking (run_button).
    """
    if guide_next:
        st.session_state[GUIDE_KEY]["position"] += 1
    targets, searches, _ = run_parts(items)
    results = st.session_state.setdefault(PIVOT_RESULTS_KEY, {})
    for search in searches:
        param, value = next(iter(iris_search_params(search).items()))
        results[search] = fetch_iris_pivot(param, value)
    if targets:
        start_hunt(targets, via_text([item for item in items if item["action"] == "Analyze"], prefix), parent_id,
                   direct=True)
    elif searches:
        st.session_state[OPEN_PIVOTS_KEY] = True


def run_button(label, items, parent_id, key, prefix="Suggested hunt", guide_next=False, container=None, **kwargs):
    """A button that runs `items` (start_steps); afterwards the app reruns to analyze, or Pivot Ranking opens."""
    (container or st).button(label, key=key, on_click=start_steps, args=(items, parent_id, prefix, guide_next),
                             **kwargs)
    if st.session_state.pop(OPEN_PIVOTS_KEY, False):
        navigation.go("pivots")


def _render_one(ds, alerts, item, parent_id, key):
    """Buttons for one picked step."""
    st.markdown(f"**{item['step']}. {html.escape(str(item['kind']))}** `{item['value']}`"
                + (f" · score {item['score']}" if item["score"] is not None else "")
                + (f" · :green-badge[{status(item)}]" if status(item) else ""))
    st.caption(item["why"])
    with st.container(horizontal=True):
        if ds is not None and st.button("Details", key=f"{key}::details", icon=":material/zoom_in:",
                                        help="Everything this run knows about it (no API call)"):
            show_indicator(ds, alerts, item["kind"], item["value"])
        if item["target"]:
            run_button("Analyze", [{**item, "action": "Analyze"}], parent_id, f"{key}::analyze",
                       icon=":material/travel_explore:", type="primary",
                       help=f"New run on `{item['target']}` linked to this one, started right away (live lookups)")
        if item["search"] and navigation.page("pivots") is not None:
            run_button("Find in Iris", [{**item, "action": "Iris"}], parent_id, f"{key}::iris",
                       icon=":material/search:",
                       help=f"Iris Investigate search `{item['search']}` (one query); results on Pivot Ranking")
        if item["kind"] == "JA4X" and st.button("Search CertsQL", key=f"{key}::certsql", icon=":material/badge:",
                                                help="Opens CertsQL with every certificate of this JA4X"):
            _certsql_search("ja4x", item["value"])


def render_picked(ds, alerts, picked, parent_id, key):
    """What can be done with the picked steps: one step's buttons, or run several together."""
    if not picked:
        st.caption("Pick a step to analyze it, search Iris for it or see its details; pick several to run them "
                   "together.")
        return
    if len(picked) == 1:
        _render_one(ds, alerts, picked[0], parent_id, key)
        return
    targets, searches, over = run_parts(picked)
    st.markdown(f"**{len(picked)} steps picked:** " + ", ".join(f"{item['step']}. `{_short(item['value'])}`"
                                                               for item in picked))
    parts = [f"{len(targets)} target(s) analyzed as one new run" if targets else "",
             f"{len(searches)} Iris search(es)" if searches else ""]
    if over:
        st.warning(f"Only the first {MAX_TARGETS} targets go into one run; left out: {', '.join(over)}.")
    if not targets and not searches:
        st.caption("None of them can be run: see each one's Details.")
        return
    run_button(f"Run {len(picked)} picked steps", picked, parent_id, f"{key}::run", icon=":material/play_arrow:",
               type="primary", help="Runs " + " and ".join(p for p in parts if p) + ", linked to this run (live "
                                                                                   "lookups).")


# ---- run the whole suggested hunt -------------------------------------------------------------------------------

@st.dialog("Run suggested hunt", width="large")
def run_dialog(items, parent_id, label):
    """Every step in order, ticked; run them all now or one at a time (guided)."""
    st.caption("Untick what you don't want. *Run all ticked* starts one new run now with the ticked targets "
               "(certificates go straight to their domains) and makes their Iris searches. *Guide me* runs them one "
               "at a time from a banner on the Hunt map. Live lookups: they use API quota.")
    ready = runnable(items)
    frame = pd.DataFrame([{"Run": item in ready, "Step": item["step"], "From": item["source"], "Kind": item["kind"],
                           "Value": item["value"], "Does": describe(item).replace("`", ""), "Status": status(item)}
                          for item in items])
    edited = st.data_editor(frame, hide_index=True, width="stretch", key="hunt_run_pick",
                            disabled=[c for c in frame.columns if c != "Run"],
                            column_config={"Run": st.column_config.CheckboxColumn(width="small"),
                                           "Step": st.column_config.NumberColumn(width="small"),
                                           "Does": st.column_config.TextColumn(width="large")})
    ticked = [item for item, tick in zip(items, edited["Run"], strict=True) if tick and item in ready]
    targets, searches, over = run_parts(ticked)
    st.markdown(f"**{len(ticked)} step(s) ticked:** {len(targets)} target(s) as one run, {len(searches)} Iris "
                "search(es)")
    if over:
        st.warning(f"Only the first {MAX_TARGETS} targets go into one run; left out: {', '.join(over)}.")
    skipped = [item for item, tick in zip(items, edited["Run"], strict=True) if tick and item not in ready]
    if skipped:
        st.caption("Ticked but not run (followed already, or searched by hand): "
                   + ", ".join(str(item["step"]) for item in skipped))
    c_all, c_guide = st.columns(2)
    run_button("Run all ticked", ticked, parent_id, "hunt_run_all", container=c_all, icon=":material/play_arrow:",
               type="primary", disabled=not ticked, width="stretch",
               help="Starts the run now: certificate steps go straight to their domains, no review screens")
    rerun_app_if_requested()   # a dialog reruns only itself: the whole app reruns to start the analysis
    if c_guide.button("Guide me, one step at a time", icon=":material/directions_walk:", disabled=not ticked,
                      width="stretch"):
        st.session_state[GUIDE_KEY] = {"parent": parent_id, "label": label, "items": ticked, "position": 0}
        st.rerun()


def render_guide():
    """The guided hunt banner: the next step, with Run / Skip / Stop."""
    guide = st.session_state.get(GUIDE_KEY)
    if not guide:
        return
    items, position = guide["items"], guide["position"]
    if position >= len(items):
        st.success(f"Guided hunt from **{guide['label']}** done: {len(items)} step(s). Each run is on the map below.")
        if st.button("Close", key="hunt_guide_close"):
            st.session_state.pop(GUIDE_KEY, None)
            st.rerun()
        return
    item = items[position]
    with st.container(border=True):
        st.markdown(f":material/directions_walk: **Guided hunt** from **{guide['label']}** · step {position + 1} of "
                    f"{len(items)}: {html.escape(str(item['kind']))} `{item['value']}`  \n{describe(item)}")
        with st.container(horizontal=True):
            run_button("Run this step", [item], guide["parent"], "hunt_guide_run",
                       prefix=f"Guided hunt step {position + 1}", guide_next=True, icon=":material/play_arrow:",
                       type="primary", help="Live lookups. The new run is linked to the run the hunt started from.")
            if st.button("Skip", key="hunt_guide_skip", icon=":material/skip_next:"):
                guide["position"] += 1
                st.rerun()
            if st.button("Stop", key="hunt_guide_stop", icon=":material/stop:"):
                st.session_state.pop(GUIDE_KEY, None)
                st.rerun()

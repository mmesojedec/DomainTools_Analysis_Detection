"""Hunting graph (Hunt menu): how saved runs connect, through leads followed and artifacts shared across target lists."""
import pandas as pd
import streamlit as st

from core.helpers import md_escape
from core.offline import list_offline_datasets
from core.persistence import load_all_runs
from core.run_history import format_created
from core.run_views import COMMON_LISTS, GRAPH_RUNS, SHARED_KINDS, shared_text
from views import navigation
from views.common import chart
from views.history_view import _list_labels, _offline_by_run, render_run_actions
from views.run_visuals import _picked, graph_data, hunting_figure

SELECTED_KEY = "hunt_graph_selected"   # the run id clicked in the graph
KINDS_KEY = "hunt_graph_kinds"
RUNS_KEY = "hunt_graph_runs"
LINKED_KEY = "hunt_graph_linked"


def _links_of(run_id, edges, nodes, labels):
    """Rows for the links of one run: the other run, how they are linked, and what they share."""
    by_id = {node["id"]: node for node in nodes}
    rows = []
    for edge in edges:
        if run_id not in (edge["source"], edge["target"]):
            continue
        other = by_id.get(edge["target"] if edge["source"] == run_id else edge["source"])
        if other is None:
            continue
        if edge["kind"] == "lead":
            how = "Led to this run" if edge["target"] == run_id else "Started from this run"
            rows.append({"Run": labels[other["key"]], "When": other["created"], "Link": how,
                         "Shared": edge.get("via") or ""})
        else:
            rows.append({"Run": labels[other["key"]], "When": other["created"], "Link": "Shares artifacts",
                         "Shared": shared_text(edge["items"], limit=8)})
    return rows


def render_hunting_graph(timezone="UTC"):
    st.subheader("Hunting graph",
                 help="Every saved run as a dot on its target list's lane, over time. Arrows: a run started from a "
                      "lead in another run (Analyze on a lead, a certificate or an Iris search). Dashed lines: two "
                      "target lists whose runs found the same IP, name server, certificate, JA4X, tracker or email on "
                      "different domains. Read from dt_runs/; no API calls.")
    st.caption("How your investigations connect: the leads you followed, and the infrastructure different "
               "investigations have in common without you linking them. Click a run for its links and actions.")
    all_runs = load_all_runs()
    if not all_runs:
        st.info("No saved runs yet. Each live Analyze is saved automatically and appears here.")
        return
    st.session_state.setdefault(KINDS_KEY, list(SHARED_KINDS))
    st.session_state.setdefault(RUNS_KEY, min(GRAPH_RUNS, len(all_runs)))
    st.session_state.setdefault(LINKED_KEY, True)
    c_kinds, c_runs, c_linked = st.columns([3, 1.4, 1.2], vertical_alignment="bottom")
    kinds = c_kinds.multiselect("Link through", list(SHARED_KINDS), key=KINDS_KEY,
                                help="Which shared artifacts draw a dashed line. CDN IPs, large DNS providers and "
                                     f"values found in more than {COMMON_LISTS} target lists are always left out. "
                                     "Untick IP when shared hosting links too much.")
    max_runs = c_runs.number_input("Newest runs", min_value=5, max_value=max(5, len(all_runs)), step=5, key=RUNS_KEY,
                                   help="How many of the newest saved runs the graph draws.")
    linked_only = c_linked.toggle("Only linked runs", key=LINKED_KEY,
                                  help="Leave out runs with no arrow and no dashed line.")
    nodes, edges = graph_data(all_runs, int(max_runs), set(kinds), linked_only)
    if not nodes:
        st.info("None of these runs are linked yet. Start a run from a lead (Summary, Certificates, Pivot Ranking) or "
                "turn off *Only linked runs* to see them all.")
        return
    labels = _list_labels(all_runs)
    ids = [node["id"] for node in nodes]
    if st.session_state.get(SELECTED_KEY) not in ids:
        st.session_state[SELECTED_KEY] = ids[-1]
    selected = st.session_state[SELECTED_KEY]
    leads = sum(edge["kind"] == "lead" for edge in edges)
    shares = len(edges) - leads
    lanes = len({node["key"] for node in nodes})
    st.caption(f"{len(nodes)} run(s) on {lanes} target list(s): {leads} lead(s) followed, {shares} shared-artifact "
               "link(s). Hover a line's middle for what it shares.")
    figure, trace_ids = hunting_figure(nodes, edges, labels, timezone, selected, set(kinds))
    clicked = _picked(chart(figure, key="hunt_graph", selectable=True), trace_ids)
    if clicked and clicked != selected:
        st.session_state[SELECTED_KEY] = clicked
        st.rerun()
    node = next(node for node in nodes if node["id"] == selected)
    st.markdown(f"#### {md_escape(labels[node['key']])}")
    st.caption(" · ".join(part for part in (format_created(node["created"], timezone),
                                            f"{node['alerts']} alert(s)" if node["alerts"] else "no alerts",
                                            f"highest: {node['top_severity']}" if node["alerts"] else "",
                                            f"started from a lead: {node['via']}" if node.get("via") else "")
                          if part))
    rows = _links_of(selected, edges, nodes, labels)
    if rows:
        frame = pd.DataFrame(rows)
        frame["When"] = frame["When"].map(lambda value: format_created(value, timezone))
        st.dataframe(frame, hide_index=True, width="stretch",
                     column_config={"Shared": st.column_config.TextColumn(width="large")})
    else:
        st.caption("This run has no links with these settings.")
    render_run_actions(node, _offline_by_run(list_offline_datasets()).get(node["id"]), prefix="hunt_graph")
    navigation.link("hunt_tree", label="See the hunts as a tree on the Hunt tree", icon=":material/park:")

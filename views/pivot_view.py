"""Pivot Ranking lens: the run's shared values (IPs, name servers, emails, certificates, trackers) ranked by how rare they are."""
import streamlit as st

from config import PIVOT_RESULT_LIMIT
from core.pivots import SIGNALS, build_pivot_ranking, iris_curl, iris_search_params, pivot_domains_frame
from integrations.enrichment import fetch_iris_pivot
from views.common import selected_rows, selection_key
from views.hunt_actions import HUNT_MAX_DOMAINS, analyze_button
from views.hunt_actions import PIVOT_RESULTS_KEY as RESULTS_KEY
from views.sidebar import add_to_targets, rerun_app_if_requested

TABLE_COLUMNS = ["Signal", "Type", "Value", "Iris Domains", "Run Domains", "Shared With", "Analyze As"]
COLUMN_HELP = {
    "Signal": "; ".join(f"{name}: {text}" for name, text in SIGNALS.items()),
    "Type": "What the value is (Iris Investigate field)",
    "Iris Domains": "Domains in Iris Investigate that share this value (Iris pivot count)",
    "Run Domains": "Domains of this run that have this value",
    "Shared With": "Which domains of this run have it",
    "Analyze As": "Target-box line to analyze it directly (IPs, certificates, redirect domains); empty when the app "
                  "cannot take it as a target, use Find domains in Iris instead",
}
MAX_SEARCHES = 5   # Iris Investigate searches per click


def dataset_pivots(ds):
    if "pivots" not in ds.derived:
        ds.derived["pivots"] = build_pivot_ranking(ds.enrichment)
    return ds.derived["pivots"]


def render_pivot_lens(ds):
    st.header("Pivot Ranking", help="Every value in the run's Iris Investigate records that other domains can share, "
                                    "with the number of domains in Iris that share it. Rare values (a few to a few "
                                    "hundred domains) usually lead to the same operator; values shared by millions "
                                    "(CDN IPs, large registrars) are noise.")
    ranking = dataset_pivots(ds)
    if ranking.empty:
        st.info("No Iris Investigate data for the selected domains, so there is nothing to rank. Pivot counts come from "
                "Iris Investigate, which every live run collects when DomainTools API credentials are set.")
        return
    signal = ranking["Signal"]
    metrics = [("Strong pivots", int((signal == "Strong").sum()), SIGNALS["Strong"]),
               ("Useful pivots", int((signal == "Useful").sum()), SIGNALS["Useful"]),
               ("Shared within the run", int(((ranking["Run Domains"] > 1) & signal.isin(["Strong", "Useful"])).sum()),
                "Strong or useful values that two or more of this run's domains share: the run's domains are probably "
                "linked"),
               ("Values ranked", len(ranking), "Every pivotable value of the selected domains")]
    for col, (label, value, help_text) in zip(st.columns(len(metrics)), metrics):
        col.metric(label, value, help=help_text)
    _render_pivot_table(ranking)


@st.fragment
def _render_pivot_table(ranking):
    """A fragment: filters, selection and Iris searches rerun only this part."""
    c_signal, c_type, c_search, c_shared = st.columns([2, 2, 2, 1])
    signals = c_signal.multiselect("Signal", list(SIGNALS), default=["Strong", "Useful"], key="pivot_signals",
                                   placeholder="Any signal")
    types = c_type.multiselect("Type", sorted(ranking["Type"].unique()), placeholder="Any type", key="pivot_types")
    search = c_search.text_input("Value or domain contains", key="pivot_search").strip().lower()
    shared = c_shared.toggle("Shared in run", key="pivot_shared", help="Only values two or more of the run's domains share")
    shown = ranking
    if signals:
        shown = shown[shown["Signal"].isin(signals)]
    if types:
        shown = shown[shown["Type"].isin(types)]
    if search:
        shown = shown[shown["Value"].str.lower().str.contains(search, regex=False)
                      | shown["Shared With"].str.contains(search, regex=False)]
    if shared:
        shown = shown[shown["Run Domains"] > 1]
    st.caption(f"{len(shown):,} of {len(ranking):,} value(s): strongest first, then the most shared within the run, "
               "then the fewest Iris domains. Select rows to analyze them or find their domains in Iris.")
    if shown.empty:
        return
    shown = shown.reset_index(drop=True)
    column_config = {col: st.column_config.Column(col, help=text) for col, text in COLUMN_HELP.items()}
    column_config["Iris Domains"] = st.column_config.NumberColumn("Iris Domains", help=COLUMN_HELP["Iris Domains"],
                                                                  format="localized")
    event = st.dataframe(shown[TABLE_COLUMNS], hide_index=True, column_config=column_config, on_select="rerun",
                         selection_mode="multi-row", key=selection_key("pivot_table", shown["Iris Search"]))
    rows = selected_rows(event, shown)
    picked = shown.iloc[rows] if rows else shown.iloc[0:0]
    _render_actions(picked)
    _render_results()
    rerun_app_if_requested()


def _render_actions(picked):
    targets = [t for t in picked["Analyze As"] if t]
    searches = list(dict.fromkeys(picked["Iris Search"]))
    c_targets, c_iris = st.columns(2)
    c_targets.button(f"Add {len(targets):,} to targets" if targets else "Add to targets", disabled=not targets,
                     on_click=add_to_targets, args=(targets,), key="pivot_add_targets", icon=":material/add:",
                     help="Puts the selected IPs, certificates and redirect domains in the sidebar target box and "
                          "switches to live lookups; click Analyze to run them. Other types cannot be targets: use "
                          "Find domains in Iris.")
    find = c_iris.button(f"Find domains in Iris ({min(len(searches), MAX_SEARCHES)})" if searches else
                         "Find domains in Iris", disabled=not searches, key="pivot_find", icon=":material/search:",
                         help=f"Searches Iris Investigate for the domains sharing each selected value: one query per "
                              f"value, up to {MAX_SEARCHES} per click and {PIVOT_RESULT_LIMIT:,} domains each. Uses "
                              "API quota, also when an offline dataset is loaded.")
    if find:
        results = st.session_state.setdefault(RESULTS_KEY, {})
        with st.spinner("Searching Iris Investigate..."):
            for search in searches[:MAX_SEARCHES]:
                param, value = next(iter(iris_search_params(search).items()))
                results[search] = fetch_iris_pivot(param, value)
        if len(searches) > MAX_SEARCHES:
            st.warning(f"Searched the first {MAX_SEARCHES} of {len(searches)} selected values; select the rest and "
                       "click again.")
    if searches:
        with st.expander(f"Iris searches for the {len(searches):,} selected value(s)"):
            st.caption("Iris Investigate search parameters, and the same searches as API calls (credentials from "
                       "$DT_API_USERNAME / $DT_API_KEY)")
            st.code("\n".join(searches), language=None)
            st.code("\n".join(iris_curl(s) for s in searches), language="bash")


def _render_results():
    results = st.session_state.get(RESULTS_KEY) or {}
    if not results:
        return
    c_title, c_clear = st.columns([4, 1])
    c_title.subheader("Domains found in Iris", help="Domains sharing each searched value, highest Iris risk first")
    if c_clear.button("Clear results", key="pivot_clear", icon=":material/close:"):
        st.session_state.pop(RESULTS_KEY, None)
        st.rerun(scope="fragment")
    for search, result in reversed(list(results.items())):
        total = result.extras.get("total", result.record_count)
        label = f"{search}: {total:,} domain(s)" + (f", first {result.record_count:,} shown" if result.truncated else "")
        with st.expander(label if result.ok else f"{search}: failed", expanded=True):
            if not result.ok:
                st.error(result.error)
                continue
            domains = pivot_domains_frame(result.data)
            if domains.empty:
                st.info("No domains found.")
                continue
            st.dataframe(domains, hide_index=True, column_config={
                "Risk Score": st.column_config.ProgressColumn("Risk Score", min_value=0, max_value=100, format="%d")})
            c_hunt, c_add, c_copy = st.columns([1.4, 1.2, 2])
            top = list(domains["Domain"].head(HUNT_MAX_DOMAINS))
            analyze_button(top, f"Iris search {search}", key=f"pivot_hunt::{search}", container=c_hunt,
                           label=f"Analyze the top {len(top)} as a new run",
                           help=f"Analyzes the {len(top)} highest-risk domains right away as a new run, linked to "
                                "this one in the hunt tree (Hunt → Hunt tree).")
            c_add.button(f"Add {len(domains):,} domains to targets", on_click=add_to_targets,
                         args=(list(domains["Domain"]),), key=f"pivot_add::{search}", icon=":material/add:")
            with c_copy.popover("Copy domains"):
                st.code("\n".join(domains["Domain"]), language=None)

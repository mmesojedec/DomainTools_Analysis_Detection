"""Lookup Queries lens: every lookup the run made, as queries and commands to reuse in the DomainTools, DNSDB, VPNDB and
BGPDB tools."""
import streamlit as st

from core.lookup_queries import TOOLS, build_lookup_queries, one_line, request_counts, tool_bundle
from views.common import selected_rows, selection_key

TOOL_HELP = {
    "IrisQL": "The IrisQL search this run's targets were picked from (IrisQL page): the query to paste into Iris "
              "Investigate's IrisQL search, the `domaintools` CLI line and the curl request (key from $DT_API_KEY). "
              "Requests: one per page of results",
    "CertsQL": "The CertsQL search this run's targets were picked from (CertsQL page): the query and the Certificate "
               "Search curl request (key from $DT_CERT_API_KEY, else $DT_API_KEY). Requests: one per page of results",
    "Iris Investigate": "Paste the domain list into the Iris Investigate search box; the command uses the `domaintools` "
                        "CLI installed with the DomainTools Python SDK",
    "DomainTools API": "Domain History and Risk Evidence through the `domaintools` CLI installed with the DomainTools "
                       "Python SDK (credentials from $DT_API_USERNAME / $DT_API_KEY, else ~/.dtapi)",
    "DomainTools Certificates": "CertsQL queries for certificate search, and JSON bodies for the Certificate Events endpoints; "
                                "the curl commands read the key from $DT_CERT_API_KEY",
    "DNSDB Scout": "Names to search in DNSDB Scout with the record type shown: `*.domain` covers the domain and its "
                   "subdomains, and the domain itself is listed too when that lookup hit its limit; the curl commands "
                   "are the DNSDB API requests the app sent, with the key from $DNSDB_API_KEY",
    "VPNDB": "Each VPNDB request the run made: the endpoint, the path to call (or, for a bulk request, the IPs it sent, "
             "one per line) and the curl command, with the key from $VPNDB_API_KEY. The answers are on Evidence → Records → "
             "VPNDB Responses",
    "BGPDB": "Each BGPDB lookup the run made (ip, route, asn, prefix) as a `bgpdbq` command (the DomainTools bgpdbq "
             "tool, reading ~/.bgpdbq.conf) and the same request as curl: the host comes from Settings → API "
             "credentials, an API key from $BGPDB_API_KEY and HTTP auth from $BGPDB_USER / $BGPDB_PASS when used. "
             "Needs the DomainTools network or VPN. The answers are on Evidence → Records → BGPDB Responses",
}
LANGUAGE = {"DomainTools Certificates": "sql", "IrisQL": "text", "CertsQL": "text"}
TABLE_COLUMNS = ["Search", "Target", "Query", "Requests", "Cached", "Cached At", "Status", "Records"]
COLUMN_HELP = {
    "Search": "Search type or endpoint to pick in that tool",
    "Query": "What to enter in the tool, on one line (the copy block below keeps the original layout)",
    "Requests": "Requests the lookup made: 2 for a DNSDB lookup that hit its limit, since the exact name was then "
                "looked up too; 0 when the result was reused from the cache",
    "Cached": "Reused from the cache (Settings → Storage & cache): no API query was made",
    "Cached At": "When the cached result was originally fetched (UTC)",
    "Records": "Records the lookup returned in this run",
    "Status": "Outcome of the lookup in this run (Data sources page)",
}


def render_query_lens(collected, created=None):
    st.subheader("Lookup queries", help="Every lookup this run made, rebuilt as queries you can run again in the "
                                     "DomainTools (Iris Investigate and IrisQL included), DNSDB, VPNDB and BGPDB tools to check or extend a finding. Paging is left out of the "
                                     "commands.")
    queries = build_lookup_queries(collected, created)
    if queries.empty:
        st.info("No lookups recorded for this run.")
        return
    _render_query_tables(queries, [t for t in TOOLS if t in set(queries["Tool"])])


@st.fragment
def _render_query_tables(queries, tools):
    """A fragment: picking a tool, filtering or selecting rows reruns only this part, not the whole app."""
    st.subheader("Lookups by tool", help="IrisQL, CertsQL, DomainTools Iris, API, Certificates, DNSDB Scout, VPNDB and BGPDB. Pick a "
                                         "tool, then select rows to copy only their queries and commands.")
    queries = queries.assign(Requests=request_counts(queries))
    counts = queries.groupby("Tool").size()
    tool = st.segmented_control("Tool", tools, default=tools[0], key="queries_tool", label_visibility="collapsed",
                                format_func=lambda t: f"{t} · {counts[t]:,}",
                                help="Each tool with the number of lookups the run made with it (a lookup reused from "
                                     "the cache counts too; it made no API request)") or tools[0]
    st.caption(TOOL_HELP[tool])
    of_tool = queries[queries["Tool"] == tool]
    c_source, c_search = st.columns(2)
    wanted_sources = c_source.multiselect("Source", sorted(of_tool["Source"].unique()), placeholder="All sources",
                                          key=f"queries_sources::{tool}")
    search = c_search.text_input("Target or query contains", key=f"queries_search::{tool}").strip().lower()
    shown = of_tool
    if wanted_sources:
        shown = shown[shown["Source"].isin(wanted_sources)]
    if search:
        shown = shown[shown["Target"].str.lower().str.contains(search, regex=False)
                      | shown["Query"].str.lower().str.contains(search, regex=False)]
    if shown.empty:
        st.caption(f"0 of {len(of_tool):,} lookup(s).")
        return

    shown = shown.reset_index(drop=True)
    view = shown[TABLE_COLUMNS].assign(Query=shown["Query"].map(one_line))
    column_config = {col: st.column_config.Column(col, help=text) for col, text in COLUMN_HELP.items()}
    column_config["Query"] = st.column_config.TextColumn("Query", help=COLUMN_HELP["Query"], width="large")
    column_config["Cached"] = st.column_config.CheckboxColumn("Cached", help=COLUMN_HELP["Cached"])
    column_config["Cached At"] = st.column_config.DatetimeColumn("Cached at", help=COLUMN_HELP["Cached At"],
                                                                 format="YYYY-MM-DD HH:mm")
    event = st.dataframe(view, hide_index=True, column_config=column_config, on_select="rerun",
                         selection_mode="multi-row", key=selection_key(f"queries_table::{tool}", shown["Command"]))
    rows = selected_rows(event, shown)
    picked = shown.iloc[rows] if rows else shown
    scope = f"{len(picked):,} selected lookup(s)" if rows else f"all {len(picked):,} lookup(s) shown"
    requests, cached = int(shown["Requests"].sum()), int(shown["Cached"].fillna(False).astype(bool).sum())
    st.caption(f"{len(shown):,} of {len(of_tool):,} lookup(s): {requests:,} API request(s)"
               + (f", {cached:,} reused from the cache (no request)" if cached else "")
               + ". Select rows to copy only those.")
    with st.expander(f"Queries to copy: {scope}", expanded=bool(rows)):
        st.code(tool_bundle(picked, tool), language=LANGUAGE.get(tool))
    with st.expander(f"Commands: {scope}", expanded=bool(rows)):
        st.code("\n".join(dict.fromkeys(picked["Command"])), language="bash")

    st.download_button("Download all lookups (CSV)", queries.drop(columns=["Requests", "Pages"]).to_csv(index=False), file_name="lookup_queries.csv",
                       mime="text/csv", key="queries_download", help="Every tool, with the full queries and commands")

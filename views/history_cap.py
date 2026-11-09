"""
Domains whose Domain History stopped at the cap (Settings → Collection options → Domain History): a notice naming
them, and a button that fetches the rest of their history into the loaded run.
"""
import streamlit as st

from config import DOMAIN_HISTORY_SAFETY_LIMIT
from core.api_usage import capped_history
from integrations.collector import fetch_rest_of_history
from integrations.credentials import get_dt_api
from integrations.domain_history import PAGE_SIZE
from views.sidebar import TOAST_KEY

HOW = ("To fetch them, click **Fetch the rest** here, or raise *Max changes* or pick *All time, no cap* under "
       "Settings → Collection options → Domain History and analyze again.")
REST_CAPS = {0: "All changes", 5_000: "Up to 5,000 per domain", 10_000: "Up to 10,000 per domain"}


def _count(n):
    return f"{n} domain" if n == 1 else f"{n} domains"


def _capped(domains=None):
    collected = st.session_state.get("collected")
    capped = capped_history(getattr(collected, "statuses", None))
    if domains is not None:
        capped = {d: n for d, n in capped.items() if d in set(domains)}
    return collected, capped


def render_history_cap_notice(domains=None, compact=False, key="history_rest"):
    """
    Notice naming the domains (of `domains`, the Global View Filter's selection; None for all) whose Domain History stopped at the cap: they have more changes.
    With `compact`, one short line; otherwise with a button (widget keys from `key`) that fetches the rest.
    """
    collected, capped = _capped(domains)
    if not capped:
        return
    names = sorted(capped)
    if compact:
        listed = ", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else "")
        st.caption(f":blue[:material/history: Domain History stopped at the cap for {_count(len(names))}: {listed}. "
                   "More changes are available: use **Fetch the rest** on the Domain Profile or on Raw Records → "
                   "Domain History Logs.]", help=HOW)
        return
    if len(names) == 1:
        text = (f"**Domain History stopped at the cap for {names[0]}** ({capped[names[0]]:,} changes fetched). It has "
                "more changes.")
    else:
        listed = ", ".join(f"{d} ({capped[d]:,})" for d in names[:8]) + \
            (f" and {len(names) - 8} more" if len(names) > 8 else "")
        text = (f"**Domain History stopped at the cap for {len(names)} domains**: {listed} changes fetched. These "
                "domains have more changes.")
    with st.container(border=True):
        st.markdown(f":material/history: {text}", help=HOW)
        _render_fetch_rest(collected, names, key)


def _render_fetch_rest(collected, names, key):
    cap = st.selectbox("Fetch", list(REST_CAPS), format_func=REST_CAPS.get, key=key + "_cap",
                          help=f"How much of the history to fetch. *All changes* stops at {DOMAIN_HISTORY_SAFETY_LIMIT:,} "
                               "per domain as a safeguard.")
    has_key = get_dt_api() is not None
    pages = -(-(cap or DOMAIN_HISTORY_SAFETY_LIMIT) // PAGE_SIZE)
    clicked = st.button("Fetch the rest" + (f" of {len(names)} domains" if len(names) > 1 else ""),
                        key=key + "_go", icon=":material/download:", disabled=not has_key,
                        help=f"Fetches the Domain History of {', '.join(names)} again, from the newest change, "
                             f"{PAGE_SIZE} per query (up to {pages:,} queries per domain), and puts it in this "
                             "run in place of the capped history. Long histories take a while (about 3 s per "
                             "query) and longer to process. Uses Domain History quota, also with an offline "
                             "dataset. Detections update with the results."
                             + ("" if has_key else " Needs DomainTools API credentials."))
    if cap == 0 or cap > 1_000:
        st.caption(":orange[:material/warning: Domains with long histories take many queries, and collecting and "
                   "processing them takes longer.]")
    if not clicked:
        return
    with st.spinner(f"Fetching the Domain History of {', '.join(names)}..."):
        rows = fetch_rest_of_history(collected, names, cap)
    st.session_state.pop("dataset_memo", None)   # the loaded run changed: rebuild the pages from it
    fetched = sum(int(row.get("Records") or 0) for row in rows)
    queries = sum(int(row.get("Queries") or 0) for row in rows)
    still = [row["Target"] for row in rows if row.get("Status") == "Partial"]
    failed = [row["Target"] for row in rows if row.get("Status") == "Error"]
    st.session_state[TOAST_KEY] = (f"Domain History: {fetched:,} changes for {_count(len(rows))} with {queries:,} "
                                   "queries. Detections are updated."
                                   + (f" Still capped: {', '.join(still)}." if still else "")
                                   + (f" Failed: {', '.join(failed)}." if failed else "")
                                   + " Save an offline copy to keep them.")
    st.rerun()

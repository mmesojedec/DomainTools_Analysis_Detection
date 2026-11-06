"""
Hunt buttons shared by several pages: analyze a value as a new run linked to this one (hunt tree), and find the
domains that share a value in Iris Investigate (results open on the Pivot Ranking page).
"""
import streamlit as st

from core.pivots import iris_search_params
from integrations.enrichment import fetch_iris_pivot
from views import navigation
from views.sidebar import start_hunt

PIVOT_RESULTS_KEY = "pivot_results"   # Iris searches shown on the Pivot Ranking page (search -> FetchResult)
HUNT_MAX_DOMAINS = 25                 # domains of an Iris search analyzed as one new run


def current_run_id():
    return st.session_state.get("current_run_id")


def analyze_button(targets, via, key, label="Analyze as a new run", container=None, **kwargs):
    """Starts a new run on `targets` right away, linked to the current run through `via`."""
    kwargs.setdefault("help", "Replaces the sidebar targets with this value and runs Analyze with the current "
                              "collection options. The new run remembers it came from this one (Run History → Hunt "
                              "tree).")
    (container or st).button(label, key=key, on_click=start_hunt, args=(list(targets), via, current_run_id()),
                             icon=":material/travel_explore:", **kwargs)


def find_in_iris(search):
    """Runs the Iris Investigate search `param=value` and opens its domains on the Pivot Ranking page."""
    param, value = next(iter(iris_search_params(search).items()))
    with st.spinner("Searching Iris Investigate..."):
        st.session_state.setdefault(PIVOT_RESULTS_KEY, {})[search] = fetch_iris_pivot(param, value)
    navigation.go("pivots")


def iris_button(search, key, container=None, label="Find in Iris", **kwargs):
    if navigation.page("pivots") is None:   # the results page is analyst-only
        return
    kwargs.setdefault("help", f"Iris Investigate search `{search}`: lists the domains that share this value (one "
                              "query, uses API quota) and opens them on the Pivot Ranking page.")
    if (container or st).button(label, key=key, icon=":material/search:", **kwargs):
        find_in_iris(search)


def certificate_target(sha256="", sha1=""):
    """Target-box line for a certificate: `sha256:<hash>` or `sha1:<hash>`."""
    sha256, sha1 = str(sha256 or "").strip().lower(), str(sha1 or "").strip().lower()
    if len(sha256) == 64:
        return f"sha256:{sha256}"
    if len(sha1) == 40 or len(sha256) == 40:
        return f"sha1:{sha1 if len(sha1) == 40 else sha256}"
    return ""


def certificate_actions(sha256, sha1, label, key):
    """Pivots on one certificate: analyze every domain / IP that uses it, and find its domains in Iris (SHA-1)."""
    target = certificate_target(sha256, sha1)
    sha1 = sha1 if len(str(sha1 or "")) == 40 else (sha256 if len(str(sha256 or "")) == 40 else "")
    if not target and not sha1:
        return
    c_analyze, c_iris, _ = st.columns([1.3, 1, 2])
    if target:
        analyze_button([target], f"Certificate {label}", key=f"cert_hunt::{key}", container=c_analyze,
                       label="Analyze its domains", width="stretch",
                       help="Starts a new run from this certificate: finds the domains and IPs that use it, lets you "
                            "pick them, then analyzes them (linked to this run in the hunt tree).")
    if sha1:
        iris_button(f"ssl_hash={sha1}", key=f"cert_iris::{key}", container=c_iris, width="stretch")

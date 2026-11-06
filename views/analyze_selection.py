"""
"Analyze the selection" step shared by the IrisQL and CertsQL pages: the user says whether the run takes the ticked
domains, the ticked IPs, or both (the Domains and IPs tabs keep their ticks either way), then picks a use case and
analyzes them, or adds them to the sidebar targets.
"""
import streamlit as st

from config import SEED_MAX_TARGETS
from core.irisql import analysis_cost
from core.persistence import load_settings
from core.use_cases import PROFILES_SETTING, all_cases

SCOPES = ("domains", "ips", "both")


def _plural(count, one, many):
    return f"{count:,} {one if count == 1 else many}"


def scope_targets(scope, domains, ips):
    """(domains, IPs) the run takes for `scope`: "domains", "ips" or "both"."""
    return (list(domains) if scope in ("domains", "both") else [],
            list(ips) if scope in ("ips", "both") else [])


def scope_label(scope, domains, ips):
    """The choice as shown, with how many ticked targets it takes."""
    if scope == "domains":
        return f"Domains ({len(domains):,})"
    if scope == "ips":
        return f"IPs ({len(ips):,})"
    return f"Domains & IPs ({len(domains) + len(ips):,})"


def analyze_label(domains, ips):
    """The Analyze button text: what the run will look up."""
    parts = ([_plural(len(domains), "domain", "domains")] if domains else []) + \
            ([_plural(len(ips), "IP", "IPs")] if ips else [])
    return "Analyze " + " & ".join(parts) if parts else "Analyze"


def default_scope(domains, ips):
    """Domains when any are ticked, else IPs when any are, else domains."""
    return "domains" if domains or not ips else "ips"


def render_analyze_selection(prefix, picked_domains, picked_ips, on_analyze, on_add, state):
    """The step under the result tabs; `on_analyze(targets, case_key, state)` / `on_add(targets, state)` are the
    page's button callbacks."""
    st.subheader("Analyze the selection", help="Choose whether the run takes the domains, the IPs or both that are "
                                               "ticked in the tabs above, then a use case for the collection options.")
    scope_key, case_key_name = f"{prefix}_analyze_scope", f"{prefix}_use_case"
    if st.session_state.get(scope_key) not in SCOPES:
        st.session_state[scope_key] = default_scope(picked_domains, picked_ips)
    scope = st.segmented_control(
        "What to analyze", SCOPES, key=scope_key, required=True,
        format_func=lambda s: scope_label(s, picked_domains, picked_ips),
        help="Only the ticks of the chosen tab(s) are used; the other tab keeps its ticks for later.")
    domains, ips = scope_targets(scope, picked_domains, picked_ips)
    targets = list(dict.fromkeys(domains + ips))

    profiles = load_settings().get(PROFILES_SETTING)
    cases = {case.key: case for case in all_cases(profiles)}
    st.session_state.setdefault(case_key_name, st.session_state.get("use_case")
                                if st.session_state.get("use_case") in cases else "triage")
    if st.session_state[case_key_name] not in cases:
        st.session_state[case_key_name] = "triage"
    case_key = st.selectbox("Use case", list(cases), key=case_key_name, format_func=lambda k: cases[k].title,
                            help="Sets the collection options and the analysis window, as on the Start page.")
    if cases[case_key].summary:
        st.caption(cases[case_key].summary)

    left_out = [text for skipped, text in ((picked_ips and not ips, _plural(len(picked_ips), "ticked IP", "ticked IPs")),
                                           (picked_domains and not domains,
                                            _plural(len(picked_domains), "ticked domain", "ticked domains")))
                if skipped]
    if targets:
        iris = analysis_cost(domains)
        cost = (f"{iris} Iris Investigate quer{'y' if iris == 1 else 'ies'} plus the use case's other lookups per "
                "target (Domain History, risk, passive DNS, certificates, VPNDB)." if domains else
                "The use case's lookups per IP (passive DNS, certificates, VPNDB); no Iris Investigate query.")
        st.markdown(f"**{analyze_label(domains, ips)[len('Analyze '):]} in the run.** {cost}"
                    + (f" Not included: {' and '.join(left_out)}." if left_out else ""))
    else:
        what = {"domains": "domains on the Domains tab", "ips": "IPs on the IPs tab",
                "both": "domains or IPs in the tabs"}[scope]
        st.info(f"Tick {what} above" + (f", or choose another option ({' and '.join(left_out)} ticked)."
                                         if left_out else "."), icon=":material/touch_app:")
    over = len(targets) > SEED_MAX_TARGETS
    if over:
        st.error(f"Select at most {SEED_MAX_TARGETS} targets per run.")
    with st.container(horizontal=True):
        st.button(analyze_label(domains, ips), type="primary", icon=":material/play_arrow:",
                  disabled=over or not targets, key=f"{prefix}_analyze", on_click=on_analyze,
                  args=(targets, case_key, state))
        st.button("Add to the sidebar targets", icon=":material/playlist_add:", disabled=not targets,
                  key=f"{prefix}_add", on_click=on_add, args=(targets, state),
                  help="Adds them to the target box without analyzing, to combine with other targets first.")

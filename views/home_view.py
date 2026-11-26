"""
Start page: pick what you want to do (a use case or a saved profile sets the collection options, the analysis window
and a plan), then Analyze. Each card lists every lookup the run makes and its limit, as saved on Settings.
"""
import streamlit as st

from core.cert_inputs import CERT_PREFIXES
from core.persistence import load_settings
from core.use_cases import (
    OVERRIDES_SETTING,
    PROFILES_SETTING,
    USE_CASES,
    WINDOW_KEY,
    builtin_settings,
    custom_cases,
    effective_settings,
    is_customized,
    plan_lines,
)
from views import navigation
from views.sidebar import EMPTY_TARGETS_KEY, SAVE_OFFLINE_KEY, TARGETS_KEY, apply_use_case, start_analyze

START_TARGETS_KEY = "start_targets"
CLEARED_KEY = "start_targets_cleared"   # the last run's targets when Clear was clicked: the box stays empty for them
_PREFIXES = "  \n".join(f"`{prefix}:` {description}" for prefix, (_, description) in CERT_PREFIXES.items())
TARGETS_HELP = (
    "Domains and IPs: defanged input (hxxp, [.]) and URLs are cleaned; subdomains are analyzed at their apex domain "
    "(vpn.example.com → example.com). IPv4 and IPv6 addresses and **CIDR ranges** (`104.21.59.0/24`, "
    "`2a00:1450::/32`) go to every source that takes addresses: passive DNS (the names on it), Iris (the domains on "
    "it), certificates naming it, BGP routing and VPNDB; certificate events take single addresses only. The *Check IP "
    "addresses* use case asks VPNDB only.  \n\n**Certificates:** SHA-256 / SHA-1 / MD5 fingerprints are recognized "
    "automatically (colons allowed); other hex values are read as serial numbers. Text that is not a domain or IP "
    "(e.g. `DomainTools LLC`) is searched as a certificate organization. Other certificate fields can be given with a "
    f"prefix; the whole line is the value:  \n{_PREFIXES}  \n\nOn **Analyze** you review how each certificate input "
    "will be searched (and can change it), then pick which of the domains and IPs found to analyze. To find targets "
    "first, use **IrisQL** or **CertsQL**; to re-analyze saved data, **Data → Saved datasets**."
)


def clear_targets():
    """Start page Clear callback: the Targets box is emptied (the last run's results stay loaded)."""
    st.session_state[START_TARGETS_KEY] = ""
    st.session_state.pop(EMPTY_TARGETS_KEY, None)
    # the box refills from the last run's targets when the page is drawn again; not these, once cleared
    st.session_state[CLEARED_KEY] = st.session_state.get(TARGETS_KEY, "")


def _initial_targets():
    """What the Targets box starts with: the last run's targets, unless Clear emptied the box since that run."""
    last = st.session_state.get(TARGETS_KEY, "")
    return "" if st.session_state.get(CLEARED_KEY) == last else last


def _card(case, overrides, active):
    settings = effective_settings(case, overrides)
    # a custom profile is its own definition; a use case changed on Settings notes its defaults
    default = None if case.custom else builtin_settings(case)
    customized = is_customized(case, overrides)
    with st.container(border=True, height="stretch"):
        st.markdown(f"#### {case.icon} {case.title}")
        if case.summary:
            st.markdown(case.summary)
        changed = ""
        if customized:
            changed = " · lookups changed on Settings"
            if settings[WINDOW_KEY] != default[WINDOW_KEY]:
                changed = f" · changed on Settings (default: {default[WINDOW_KEY]})"
        st.markdown(f"**Analysis window:** {settings[WINDOW_KEY]}{changed}",
                    help="Filters what the pages show; the lookups below are the same for every window.")
        # the lookups and the plan collapsed, so the cards stay short and easy to compare
        with st.expander("See more details: lookups and next steps", icon=":material/info:"):
            note = " *(default)* is this use case's own setting, before your change on Settings." if customized else ""
            st.caption("**Lookups per domain, with their limits:**" + note + "\n\n"
                       + "\n".join(f"- {line}" for line in plan_lines(settings, default)))
            steps = [(key, text) for key, text in case.steps if navigation.page(key) is not None]
            if steps:
                st.caption("**After Analyze, work through:**\n\n" + "\n".join(
                    f"{number}. **{navigation.title(key)}** — {text}"
                    for number, (key, text) in enumerate(steps, 1)))
        st.button("Selected" if active == case.key else "Use this", key=f"use_case::{case.key}",
                  on_click=apply_use_case, args=(case,), type="primary" if active == case.key else "secondary",
                  icon=":material/check:" if active == case.key else None, width="stretch")


def _grid(cases, overrides, active):
    for row in range(0, len(cases), 3):
        for column, case in zip(st.columns(3), cases[row:row + 3]):
            with column:
                _card(case, overrides, active)


def render_home(has_data, render_recent):
    st.title("DomainTools Analytics and Detection",
             help="Unified digital risk and infrastructure intelligence combining Domain History, Passive DNS (Iris & "
                  "DNSDB Scout), SSL/TLS telemetry, and web analytics attribution.")
    st.markdown("**What do you want to do?** Pick a use case below (optional): it sets the collection options and the "
                "analysis window that suit it, and gives you a short plan. Then enter the targets and click **Analyze**. "
                "You can also go straight to any page in the menu above.")
    with st.container(border=True):
        st.session_state.setdefault(START_TARGETS_KEY, _initial_targets())
        st.text_area("Targets: domains, IPs or certificates (one per line)", key=START_TARGETS_KEY, height=180,
                     placeholder="example.com\n203.0.113.7\ncn:login.example.com", help=TARGETS_HELP)
        with st.container(horizontal=True, vertical_alignment="center"):
            # never disabled: pasted text only reaches the app when the box loses focus, which this click does
            st.button("Analyze", type="primary", icon=":material/play_arrow:", key="start_analyze",
                      on_click=start_analyze, args=(START_TARGETS_KEY,),
                      help="Paste or type the targets, then click: no need to click outside the box first")
            navigation.link("irisql", label="Find targets with IrisQL", icon=":material/manage_search:")
            navigation.link("certsql", label="Find targets with CertsQL", icon=":material/badge:")
            navigation.link("dnsdb_search", label="Search DNSDB", icon=":material/saved_search:")
            navigation.link("recent", label="Runs & Sightings", icon=":material/schedule:")
            st.checkbox("Save offline copy", key=SAVE_OFFLINE_KEY,
                        help="Also saves everything this run collects to dt_offline/ (local, git-ignored) so it can be "
                             "re-analyzed later with a different window, thresholds or filters without API calls. "
                             "Large DNSDB limits produce large datasets. You can also save a run afterwards: *Save "
                             "offline copy* on the status line at the top of every page.")
            st.button("Clear", icon=":material/close:", type="tertiary", key="start_clear", on_click=clear_targets,
                      help="Empties the Targets box. The loaded results stay; Analyze replaces them.")
        if st.session_state.pop(EMPTY_TARGETS_KEY, False):
            st.warning("Enter at least one domain, IP or certificate in the Targets box first.",
                       icon=":material/edit_note:")
    render_recent()
    saved = load_settings()
    overrides, active = saved.get(OVERRIDES_SETTING) or {}, st.session_state.get("use_case")
    _grid(list(USE_CASES), overrides, active)
    profiles = custom_cases(saved.get(PROFILES_SETTING))
    st.subheader("Your profiles", help="Your own sets of collection options, saved on Settings → Collection options.")
    if profiles:
        _grid(profiles, overrides, active)
    else:
        st.caption("No custom profiles yet.")
    navigation.link("settings", label="Change a use case's lookups or create a profile (Settings → Collection "
                                      "options)")
    if active:
        if has_data:
            st.info("Use case selected. Its window applies now; its collection options apply to the next **Analyze**. "
                    "Your plan is on the Summary page.")
            navigation.link("summary", label="Go to the Summary")
        else:
            st.info("Use case selected. Enter targets above and click **Analyze**.")
    elif not has_data:
        st.info("Enter target domains, IPs, or certificates above and click **Analyze** to begin, or load a saved "
                "dataset (Data → Saved datasets).")

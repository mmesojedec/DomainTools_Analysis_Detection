"""
Start page: pick what you want to do (a use case or a saved profile sets the collection options, the analysis window
and a plan), then Analyze. Each card lists every lookup the run makes and its limit, as saved on Settings.
"""
import streamlit as st

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
from views.sidebar import apply_use_case


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
    st.markdown("**What do you want to do?** Pick a use case: it sets the collection options (which lookups run and "
                "their limits) and the analysis window that suit it, and gives you a short plan. Then enter the "
                "targets in the sidebar and click **Analyze**. You can also go straight to any page in the menu above.")
    with st.container(horizontal=True):
        navigation.link("irisql", label="Run lookups with IrisQL", icon=":material/manage_search:")
        navigation.link("certsql", label="Run lookups with CertsQL", icon=":material/badge:")
        navigation.link("recent", label="Recent runs & Sightings", icon=":material/schedule:")
    render_recent()
    saved = load_settings()
    overrides, active = saved.get(OVERRIDES_SETTING) or {}, st.session_state.get("use_case")
    _grid(list(USE_CASES), overrides, active)
    profiles = custom_cases(saved.get(PROFILES_SETTING))
    st.subheader("Your profiles", help="Your own sets of collection options, saved on Settings → Use cases & profiles.")
    if profiles:
        _grid(profiles, overrides, active)
    else:
        st.caption("No custom profiles yet.")
    navigation.link("settings", label="Change a use case's lookups or create a profile (Settings → Use cases & "
                                      "profiles)")
    if active:
        if has_data:
            st.info("Use case selected. Its window applies now; its collection options apply to the next **Analyze**. "
                    "Your plan is on the Summary page.")
            navigation.link("summary", label="Go to the Summary")
        else:
            st.info("Use case selected. Enter targets in the sidebar and click **Analyze**.")
    elif not has_data:
        st.info("Enter target domains, IPs, or certificates in the sidebar and click **Analyze** to begin, or load an "
                "offline dataset.")

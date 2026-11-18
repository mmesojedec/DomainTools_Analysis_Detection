"""
Settings page: collection options, use cases and custom profiles, detection thresholds, the brand watchlist, the
lookup cache and API credentials.
"""
import pandas as pd
import streamlit as st

from core.allowlist import ALLOWLIST_SETTING, parse_allowlist
from core.lookalike import lookalike_candidates, lookalike_query, parse_brand_list, parse_official_domains
from core.persistence import load_settings, save_setting
from core.use_cases import (
    GLOBAL_DEFAULTS,
    OPTION_LABELS,
    OVERRIDES_SETTING,
    PROFILE_KEYS,
    PROFILE_WINDOWS,
    PROFILES_SETTING,
    WINDOW_KEY,
    all_cases,
    builtin_settings,
    changed_options,
    compare_plan,
    effective_settings,
    find_case,
    is_customized,
    profile_key,
    query_plan,
    remove_profile,
    upsert_profile,
)
from views import navigation
from views.history_view import render_retention_settings
from views.query_editor import set_query
from views.sidebar import (
    TOAST_KEY,
    apply_use_case,
    render_cache_settings,
    render_collection_options,
    render_credential_status,
    render_threshold_controls,
)

BRAND_SETTING = "brand_watchlist"   # dt_settings.json: the brand watchlist as typed
BRAND_EDIT_KEY = "brand_watchlist_edit"
CASE_SELECT_KEY = "use_case_edit"
CURRENT_OPTIONS = "Current collection options"


def brand_watchlist():
    """(brands, official domains) of the saved brand watchlist, as the lookalike rules take them."""
    raw = load_settings().get(BRAND_SETTING, "")
    return parse_brand_list(raw), parse_official_domains(raw)


def _prefix(case):
    return f"uc::{case.key}::"


def _edited(case):
    """The options being edited for `case` (its widgets' values)."""
    prefix = _prefix(case)
    return {key: st.session_state[prefix + key] for key in PROFILE_KEYS if prefix + key in st.session_state}


def _forget_edits(case):
    prefix = _prefix(case)
    for key in [k for k in st.session_state if str(k).startswith(prefix)]:
        del st.session_state[key]


def _save_case(case):
    saved = load_settings()
    values = _edited(case)
    if case.custom:
        profiles = upsert_profile(saved.get(PROFILES_SETTING), case.title,
                                  st.session_state.get(_prefix(case) + "description", case.summary), values)
        save_setting(PROFILES_SETTING, profiles)
    else:
        base = builtin_settings(case)
        overrides = dict(saved.get(OVERRIDES_SETTING) or {})
        overrides[case.key] = {key: values[key] for key in changed_options(values, base)}
        if not overrides[case.key]:
            overrides.pop(case.key)
        save_setting(OVERRIDES_SETTING, overrides)
    st.session_state[TOAST_KEY] = f"Saved the options of {case.title}."


def _save_and_use(case):
    _save_case(case)
    saved = load_settings()
    apply_use_case(find_case(case.key, saved.get(PROFILES_SETTING)) or case)
    st.session_state[TOAST_KEY] = f"Saved {case.title} and applied it to the next Analyze."


def _reset_case(case):
    overrides = dict(load_settings().get(OVERRIDES_SETTING) or {})
    overrides.pop(case.key, None)
    save_setting(OVERRIDES_SETTING, overrides)
    _forget_edits(case)
    st.session_state[TOAST_KEY] = f"{case.title} is back to its default options."


def _delete_profile(case):
    save_setting(PROFILES_SETTING, remove_profile(load_settings().get(PROFILES_SETTING), case.key))
    _forget_edits(case)
    if st.session_state.get("use_case") == case.key:
        st.session_state.pop("use_case", None)
    st.session_state.pop(CASE_SELECT_KEY, None)
    st.session_state[TOAST_KEY] = f"Deleted the profile {case.title}."


def _create_profile():
    name = st.session_state.get("new_profile_name", "").strip()
    if not name:
        st.session_state[TOAST_KEY] = "Give the profile a name."
        return
    saved = load_settings()
    source = st.session_state.get("new_profile_source", CURRENT_OPTIONS)
    if source == CURRENT_OPTIONS:
        settings = {key: st.session_state.get(key, GLOBAL_DEFAULTS[key]) for key in PROFILE_KEYS}
    else:
        base = next(case for case in all_cases(saved.get(PROFILES_SETTING)) if case.title == source)
        settings = effective_settings(base, saved.get(OVERRIDES_SETTING))
    profiles = upsert_profile(saved.get(PROFILES_SETTING), name, st.session_state.get("new_profile_description", ""),
                              settings)
    save_setting(PROFILES_SETTING, profiles)
    _forget_edits(find_case(profile_key(name), profiles))
    st.session_state[CASE_SELECT_KEY] = profile_key(name)
    for key in ("new_profile_name", "new_profile_description"):
        st.session_state[key] = ""
    st.session_state[TOAST_KEY] = f"Created the profile {name}. It is on the Start page."


def _shown(value):
    if isinstance(value, bool):
        return "on" if value else "off"
    return f"{value:,}" if isinstance(value, int) else str(value)


def _case_label(case, overrides):
    if case.custom:
        return f"{case.title} (custom profile)"
    return case.title + (" (changed)" if is_customized(case, overrides) else "")


SESSION = "__session__"   # Collection options editing the next Analyze, not a saved use case


def render_options_tab():
    """One editor for every set of collection options: the next Analyze (this session), a use case or a profile."""
    saved = load_settings()
    overrides, profiles = saved.get(OVERRIDES_SETTING) or {}, saved.get(PROFILES_SETTING) or []
    cases = all_cases(profiles)
    keys = [SESSION] + [case.key for case in cases]
    if st.session_state.get(CASE_SELECT_KEY) not in keys:
        st.session_state[CASE_SELECT_KEY] = SESSION
    labels = {SESSION: "The next Analyze (this session)", **{case.key: _case_label(case, overrides) for case in cases}}
    key = st.selectbox("Editing", keys, key=CASE_SELECT_KEY, format_func=labels.get,
                       help="The next Analyze: changes hold for this browser session (picking a use case on the Start "
                            "page sets them). A use case or profile: its saved options, used whenever it is picked; "
                            "**Save** keeps them in dt_settings.json and the Start page applies your version.")
    if key == SESSION:
        render_collection_options()
        st.markdown("**What the next Analyze looks up, per target domain**")
        st.dataframe(pd.DataFrame(query_plan({k: st.session_state.get(k) for k in PROFILE_KEYS})).drop(columns="Key"),
                     hide_index=True, width="stretch")
    else:
        render_use_case_settings(find_case(key, profiles), overrides)
    with st.expander("Create a custom profile", icon=":material/add:"):
        render_new_profile(cases)


def render_use_case_settings(case, overrides):
    st.caption("Every use case on the Start page is a full set of collection options: the **global defaults** (the "
               "app's built-in options, see Settings → Documentation → Reference) with a few changes that suit it. Change "
               "it here and **Save**: the Start page applies your version until you **Reset to default**.")
    current = effective_settings(case, overrides)
    prefix = _prefix(case)
    for option, value in current.items():
        st.session_state.setdefault(prefix + option, value)

    with st.container(border=True):
        if case.custom:
            st.session_state.setdefault(prefix + "description", case.summary)
            st.text_input("Description", key=prefix + "description", help="Shown on the profile's Start page card.")
        else:
            st.markdown(f"{case.icon} **{case.title}** — {case.summary}")
        st.selectbox("Analysis window", PROFILE_WINDOWS, key=prefix + WINDOW_KEY,
                     help="The window this use case sets (sidebar before a run, results toolbar after). It filters what the "
                          "pages show; it changes what is looked up only for Domain History in *Analysis window* mode.")
        render_collection_options(prefix)

    edited = _edited(case)
    unsaved = changed_options(edited, current) or (
        case.custom and st.session_state.get(prefix + "description", case.summary) != case.summary)
    differs = changed_options(edited, builtin_settings(case)) if not case.custom else []
    if unsaved:
        st.warning("Unsaved changes.")
    elif differs:
        default = builtin_settings(case)
        st.caption("Changed from the default: " + ", ".join(
            f"{OPTION_LABELS[key]} {_shown(edited[key])} (default {_shown(default[key])})" for key in differs))
    c1, c2, c3, c4 = st.columns(4)
    c1.button("Save", key="uc_save", type="primary", on_click=_save_case, args=(case,), disabled=not unsaved,
              icon=":material/save:", width="stretch")
    c2.button("Save and use now", key="uc_use", on_click=_save_and_use, args=(case,), icon=":material/check:",
              width="stretch", help="Saves, then sets these options and window for the next Analyze.")
    c3.button("Discard changes", key="uc_discard", on_click=_forget_edits, args=(case,), disabled=not unsaved,
              icon=":material/undo:", width="stretch")
    if case.custom:
        c4.button("Delete profile", key="uc_delete", on_click=_delete_profile, args=(case,), icon=":material/delete:",
                  width="stretch")
    else:
        c4.button("Reset to default", key="uc_reset", on_click=_reset_case, args=(case,),
                  disabled=not is_customized(case, overrides) and not differs, icon=":material/restart_alt:",
                  width="stretch")

    st.markdown("**What a run with these options looks up, per target domain**")
    if case.custom:
        st.dataframe(pd.DataFrame(query_plan(edited)).drop(columns="Key"), hide_index=True, width="stretch")
    else:
        st.dataframe(pd.DataFrame(compare_plan(edited, builtin_settings(case))).drop(columns="Key"), hide_index=True, width="stretch",
                     column_config={"Default": st.column_config.TextColumn(
                         "Default", help="This use case's own limit, before any change on Settings.")})


def render_new_profile(cases):
    c1, c2 = st.columns(2)
    c1.text_input("Name", key="new_profile_name", placeholder="e.g. Quick IP pivot sweep")
    c2.selectbox("Start from", [CURRENT_OPTIONS, *(case.title for case in cases)], key="new_profile_source",
                 help="Copies these options into the new profile; change them afterwards above.")
    st.text_input("Description", key="new_profile_description", placeholder="What you use it for")
    st.button("Create profile", key="new_profile", on_click=_create_profile, icon=":material/add:")


def _save_brands():
    save_setting(BRAND_SETTING, st.session_state.get(BRAND_EDIT_KEY, ""))
    st.session_state[TOAST_KEY] = "Saved the brand watchlist. The lookalike rules use it now."


def render_brand_watchlist():
    st.caption("The brands you protect. The **Lookalike / Brand** detections compare every analyzed domain against "
               "this list: typosquats (one letter off), homoglyphs (look-alike letters such as `paypa1` or Cyrillic "
               "`а`), combosquats (brand plus a word, e.g. `paypal-login`) and the exact brand on another TLD "
               "(`paypal.net`). Without a list only IDN / punycode domains are flagged. Saved in dt_settings.json and "
               "used at once, with no new lookups.")
    st.session_state.setdefault(BRAND_EDIT_KEY, load_settings().get(BRAND_SETTING, ""))
    st.text_area("Brands and official domains (comma or one per line)", key=BRAND_EDIT_KEY, height=140,
                 placeholder="paypal\nacme.com\nacme.co.uk",
                 help="A word (`paypal`) is a brand name. A domain (`acme.com`) adds its first label as a brand and "
                      "marks that domain as the brand's own, so it is never flagged. Names shorter than 4 characters "
                      "are ignored (too many false matches).")
    raw = st.session_state[BRAND_EDIT_KEY]
    brands, official = parse_brand_list(raw), parse_official_domains(raw)
    c1, c2 = st.columns(2)
    c1.markdown("**Brands matched:** " + (", ".join(f"`{b}`" for b in brands) or "none"))
    c2.markdown("**Official domains (never flagged):** " + (", ".join(f"`{d}`" for d in official) or "none"))
    st.button("Save", key="brands_save", type="primary", on_click=_save_brands,
              disabled=raw == load_settings().get(BRAND_SETTING, ""), icon=":material/save:")
    if brands:
        candidates = lookalike_candidates(brands, official)
        if st.button(f"Hunt lookalikes in IrisQL ({len(candidates)} candidate names)", key="brands_hunt",
                     icon=":material/manage_search:",
                     help="Writes an IrisQL query for typos, look-alike characters, other TLDs and brand + phishing "
                          "word names of your brands, and opens it on the IrisQL page. Nothing is searched until you "
                          "click Search there (one Iris Investigate query)."):
            from views.irisql_view import QUERY_KEY  # the IrisQL page imports the settings helpers
            set_query(QUERY_KEY, lookalike_query(candidates))
            navigation.go("irisql")
    st.caption("Separate from this list, Subdomain Triage and the CNAME rules use a built-in list of brands phishing "
               "kits often impersonate (Microsoft, PayPal, DHL, ...); it is listed in Settings → Documentation → Reference.")


ALLOW_EDIT_KEY = "allowlist_edit"


def _save_allowlist():
    save_setting(ALLOWLIST_SETTING, st.session_state.get(ALLOW_EDIT_KEY, ""))
    st.session_state[TOAST_KEY] = "Saved the allowlist. The detections use it now."


def render_allowlist():
    st.caption("Your own (or otherwise known-good) infrastructure. Allowlisted values never link analyzed domains into "
               "clusters, and alerts whose evidence names one are kept at **Low** confidence with the reason. Saved in "
               "dt_settings.json and used at once, with no new lookups.")
    st.session_state.setdefault(ALLOW_EDIT_KEY, load_settings().get(ALLOWLIST_SETTING, ""))
    st.text_area("Allowlist (comma or one per line)", key=ALLOW_EDIT_KEY, height=140,
                 placeholder="ns:corp-dns.example\n203.0.113.0/24\nAS64500\norg:Example Corp\ntracker:G-ABC123\n"
                             "registrar:MarkMonitor",
                 help="IP addresses and ranges, `AS` numbers, `ns:` name servers (a bare host name works too), "
                      "`org:` certificate subject organizations, `tracker:` web tracker IDs, `registrar:` registrars. "
                      "Lines starting with # are ignored.")
    raw = st.session_state[ALLOW_EDIT_KEY]
    parsed = parse_allowlist(raw)
    parts = [(len(parsed.networks), "IP ranges"), (len(parsed.asns), "ASNs"), (len(parsed.name_servers), "name servers"),
             (len(parsed.orgs), "organizations"), (len(parsed.trackers), "trackers"),
             (len(parsed.registrars), "registrars")]
    st.markdown("**Recognized:** " + (", ".join(f"{n} {label}" for n, label in parts if n) or "nothing yet"))
    st.button("Save allowlist", key="allowlist_save", type="primary", on_click=_save_allowlist,
              disabled=raw == load_settings().get(ALLOWLIST_SETTING, ""), icon=":material/save:")


def render_settings():
    st.header("Settings", help="Collection options and thresholds are kept for this browser session; use cases, "
                               "profiles, the brand watchlist and the cache lifetime are saved in dt_settings.json. "
                               "Collection options apply to the next Analyze; thresholds and the brand watchlist "
                               "re-run the detections at once.")
    tabs = st.tabs(["Collection options", "Detection thresholds", "Brands & allowlist", "Storage & cache",
                    "API credentials"])
    with tabs[0]:
        render_options_tab()
    with tabs[1]:
        render_threshold_controls()
    with tabs[2]:
        st.subheader("Brand watchlist")
        render_brand_watchlist()
        st.subheader("Infrastructure allowlist")
        render_allowlist()
    with tabs[3]:
        render_cache_settings()
        st.divider()
        render_retention_settings()
    with tabs[4]:
        render_credential_status()

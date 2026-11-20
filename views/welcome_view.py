"""
First start: a dialog with the disclaimer (this is not an official DomainTools application), which must be accepted
before anything else, then the API credentials (DomainTools username and API key, Certificate API, DNSDB, VPNDB, BGPDB host),
saved to credentials.toml. A service left without a key is not queried until a key is entered (Settings → API
credentials). The acceptance is kept in dt_settings.json; Settings → API credentials can show the dialog again.
"""
import streamlit as st

from core.persistence import load_settings, save_setting
from integrations.credentials import BGPDB, CERT_API, SERVICES, credential_overview, credentials_file, display_path
from views.sidebar import KEY_FIELDS, KEY_HELP, TOAST_KEY, _save_entered_keys

ACCEPTED_SETTING = "disclaimer_accepted"   # dt_settings.json: the disclaimer version accepted
DISCLAIMER_VERSION = 1
STEP_KEY = "welcome_step"     # "disclaimer" / "keys" / "done" for this session
REOPEN_KEY = "welcome_reopen"
PREFIX = "welcome_cred"       # widget keys of the dialog's key fields (apart from the Settings form's)
DISCLAIMER = (
    "**This is not an official DomainTools application.** It is an example of a custom-built application. It shows "
    "how the DomainTools Python SDK and the other DomainTools APIs can be used to get DomainTools data and use it "
    "for analysis and basic detection:\n"
    "- Iris Investigate, Domain History and the Certificates API;\n"
    "- DNSDB Scout (passive DNS);\n"
    "- VPNDB (VPN, residential proxy and Tor attribution).\n\n"
    "It is provided as an example, without support. Its alerts, scores and verdicts are heuristics built on that "
    "data: check the evidence before you act on them.\n\n"
    "Every lookup uses your own API keys and counts against your own quotas. Keys are stored only on this computer, "
    "and investigation data stays in the app's local folders.")


def accepted():
    return int(load_settings().get(ACCEPTED_SETTING) or 0) >= DISCLAIMER_VERSION


def reopen():
    """Button callback (Settings): shows the dialog again, from the disclaimer."""
    st.session_state[STEP_KEY] = "disclaimer"
    st.session_state[REOPEN_KEY] = True


def _accept():
    save_setting(ACCEPTED_SETTING, DISCLAIMER_VERSION)
    st.session_state[STEP_KEY] = "keys"


def _skip():
    st.session_state[STEP_KEY] = "done"


def _save():
    if _save_entered_keys(PREFIX):
        st.session_state[STEP_KEY] = "done"


@st.dialog("Welcome", width="large", dismissible=False)
def _welcome_dialog():
    step = st.session_state.get(STEP_KEY, "disclaimer")
    if step == "done":
        st.session_state.pop(REOPEN_KEY, None)
        st.rerun()   # closes the dialog
    if step == "disclaimer":
        st.markdown("#### DomainTools Analytics and Detection")
        st.warning(DISCLAIMER, icon=":material/info:")
        agree = st.checkbox("I understand that this is not an official DomainTools application", key="welcome_agree")
        st.button("Continue", type="primary", disabled=not agree, on_click=_accept, icon=":material/arrow_forward:")
        return
    overview = {row["Service"]: row for row in credential_overview()["services"]}
    st.markdown("#### API credentials")
    st.caption(f"Saved to `{display_path(credentials_file())}`, outside the project folder and readable only by "
               "your user. Keys are never shown again. **A service left without a key is not queried**; its lookups "
               "are skipped until you add a key on Settings → API credentials.")
    message = st.session_state.pop(TOAST_KEY, None)
    if message:
        st.info(message, icon=":material/info:")
    with st.form("welcome_credentials", border=False, enter_to_submit=False):
        for service, fields in KEY_FIELDS.items():
            row = overview[service]
            state = (f":green[:material/check_circle: ready ({row['Source']})]" if row["Found"]
                     else ":gray[:material/radio_button_unchecked: no key: uses the DomainTools API key once it is "
                          "set]" if service == CERT_API
                     else ":gray[:material/radio_button_unchecked: no host: not queried (internal DomainTools "
                          "service; optional)]" if service == BGPDB
                     else ":gray[:material/radio_button_unchecked: no key: not queried]")
            st.markdown(f"**{service}** · {SERVICES[service]}  \n{state}")
            columns = st.columns(len(fields)) if len(fields) > 1 else [st]
            for column, (key, label, secret) in zip(columns, fields):
                column.text_input(label, key=f"{PREFIX}::{service}::{key}", type="password" if secret else "default",
                                  autocomplete="off", placeholder="already set; leave empty to keep" if row["Found"]
                                  else "", help=KEY_HELP.get(service))
        st.form_submit_button("Save keys and start", type="primary", icon=":material/save:", on_click=_save)
    st.button("Skip for now", on_click=_skip, type="tertiary", icon=":material/skip_next:",
              help="Start without saving keys. Services without a key are not queried; add keys any time on "
                   "Settings → API credentials.")


def render_welcome():
    """Opens the welcome dialog on the first start (disclaimer not accepted yet), or when Settings asks for it."""
    if not st.session_state.get(REOPEN_KEY) and accepted() and st.session_state.get(STEP_KEY) in (None, "done"):
        return
    if not accepted():
        st.session_state.setdefault(STEP_KEY, "disclaimer")
    _welcome_dialog()

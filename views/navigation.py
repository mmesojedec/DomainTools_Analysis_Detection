"""
Top navigation: the app's pages in groups, links and jumps between them. Analyst-only pages are left out in the simple
mode (sidebar: Analyst mode), so links to them are only drawn when they exist.
"""
import json
from dataclasses import dataclass

import streamlit as st


@dataclass(frozen=True)
class PageSpec:
    key: str
    title: str
    icon: str
    analyst_only: bool = False


SECTIONS = {
    "Start": (PageSpec("home", "Start", ":material/home:"),),
    "IrisQL": (PageSpec("irisql", "IrisQL", ":material/manage_search:"),),
    "CertsQL": (PageSpec("certsql", "CertsQL", ":material/badge:"),),
    "Runs": (PageSpec("recent", "Runs", ":material/schedule:"),),
    "Overview": (PageSpec("summary", "Summary", ":material/dashboard:"),
                 PageSpec("profile", "Domain profile", ":material/domain:"),
                 PageSpec("alerts", "Alerts", ":material/warning:")),
    "Infrastructure": (PageSpec("dns", "DNS & Hosting", ":material/dns:"),
                       PageSpec("vpndb", "VPNDB", ":material/vpn_lock:"),
                       PageSpec("tor", "Tor network", ":material/travel_explore:"),
                       PageSpec("bgp", "BGP", ":material/hub:"),
                       PageSpec("cname", "CNAME Chains", ":material/route:"),
                       PageSpec("certs", "Certificates", ":material/verified_user:")),
    "Hunt": (PageSpec("hunt_tree", "Hunt map", ":material/account_tree:", True),
             PageSpec("hostnames", "Hostname Inventory", ":material/list_alt:", True),
             PageSpec("triage", "Subdomain Triage", ":material/filter_alt:", True),
             PageSpec("similarity", "Domain similarity", ":material/join_inner:", True)),
    "Evidence": (PageSpec("evidence", "Evidence", ":material/table_view:", True),),
    "Data": (PageSpec("offline", "Saved datasets", ":material/folder_open:"),
             PageSpec("export", "Export & report", ":material/download:"),
             PageSpec("sources", "Data sources", ":material/fact_check:")),
    "Settings": (PageSpec("settings", "Settings", ":material/settings:"),
                 PageSpec("account", "Account", ":material/account_circle:"),
                 PageSpec("docs", "Documentation", ":material/menu_book:")),
}
DIRECT = ("Start", "IrisQL", "CertsQL", "Runs")   # one-page groups: plain links in the menu, no dropdown
# Pages merged into a tab of another page: links and jumps to the old key open that tab
ALIASES = {
    "history": ("recent", "recent_tab", "Compare & trends", "Compare runs"),
    "pivots": ("hunt_tree", "hunt_map_tab", "All pivots", "All pivots, ranked"),
    "raw": ("evidence", "evidence_tab", "Records", "Raw records"),
    "queries": ("evidence", "evidence_tab", "Lookup queries", "Lookup queries"),
}
SPECS = {spec.key: spec for specs in SECTIONS.values() for spec in specs}
_PAGES = {}   # key -> StreamlitPage of this run
SCROLL_TAB_KEY = "scroll_to_tab"   # a tab label: the next page scrolls its tab row into view once
PENDING_STATE_KEY = "_nav_pending_state"   # state a jump sets on the target page, applied on its first run


def build(functions, analyst=True):
    """st.navigation (top bar) over `functions` ({page key: callable}); the Start page is the default."""
    _PAGES.clear()
    st.session_state.update(st.session_state.pop(PENDING_STATE_KEY, None) or {})
    sections = {}
    for section, specs in SECTIONS.items():
        pages = []
        for spec in specs:
            if spec.analyst_only and not analyst:
                continue
            page = st.Page(functions[spec.key], title=spec.title, icon=spec.icon, url_path=spec.key,
                           default=spec.key == "home")
            _PAGES[spec.key] = page
            pages.append(page)
        if pages:
            sections.setdefault("" if section in DIRECT else section, []).extend(pages)
    return st.navigation(sections, position="top")


def current_key(nav):
    """The page key of the StreamlitPage `nav` returned by build() (the default page has an empty url_path)."""
    return next((key for key, item in _PAGES.items() if item is nav or item.title == nav.title), nav.url_path)


def page(key):
    """The StreamlitPage of `key` (or of the page a merged key lives on), or None when this mode leaves it out."""
    return _PAGES.get(ALIASES[key][0] if key in ALIASES else key)


def title(key):
    return ALIASES[key][3] if key in ALIASES else SPECS[key].title


def go(key, **state):
    """Sets `state` (e.g. a filter of the target page) and opens page `key` (a merged page's tab: ALIASES)."""
    if key in ALIASES:
        target, tabs_key, tab, _ = ALIASES[key]
        state = {tabs_key: tab, SCROLL_TAB_KEY: tab, **state}
        key = target
    # Applied by build() on the next run, before any widget: a jump within the same page (Runs → its own Compare &
    # trends tab) must not set a widget that this run has drawn already (StreamlitAPIException)
    st.session_state[PENDING_STATE_KEY] = {**st.session_state.get(PENDING_STATE_KEY, {}), **state}
    st.switch_page(_PAGES[key])


def open_tab(key, tabs_key, tab, **state):
    """Opens page `key` with tab `tab` of its tab row `tabs_key` selected and scrolled into view (and `state` set)."""
    go(key, **{tabs_key: tab, SCROLL_TAB_KEY: tab, **state})


def scroll_to_tab():
    """
    Scrolls the tab row asked for by open_tab() to the top of the window, once. The frame is same-origin, so it can
    reach the page; it retries for a few seconds because the tabs may be drawn after it.
    """
    tab = st.session_state.pop(SCROLL_TAB_KEY, None)
    if not tab:
        return
    st.iframe(f"<script>const label = {json.dumps(tab)};" + """
      let tries = 0;
      const timer = setInterval(() => {
        const tab = [...window.parent.document.querySelectorAll('[role="tab"]')]
          .find(element => element.innerText.trim() === label);
        if (tab || ++tries > 30) {
          clearInterval(timer);
          const row = tab?.closest('[data-testid="stTabs"]');
          if (row) {   // below the fixed top menu, with a little room for the heading above the tabs
            const header = window.parent.document.querySelector('[data-testid="stHeader"]');
            row.style.scrollMarginTop = `${(header?.offsetHeight || 60) + 16}px`;
            row.scrollIntoView({block: "start"});
          }
        }
      }, 100);
    </script>""", height=1)


def link(key, label=None, container=None, icon=None):
    """A link to page `key` (nothing when the page is not available in this mode)."""
    target = page(key)
    if target is None:
        return
    if key in ALIASES:   # a tab of another page: a button, since a page link cannot pick the tab
        spec = SPECS[ALIASES[key][0]]
        if (container or st).button(label or title(key), key=f"link::{key}::{label}", type="tertiary",
                                    icon=icon or spec.icon):
            go(key)
        return
    (container or st).page_link(target, label=label or SPECS[key].title, icon=icon or SPECS[key].icon)


def jump_button(key, label, state=None, button_key=None, container=None, **kwargs):
    """A button that opens page `key` with `state` set; nothing when the page is not available."""
    if page(key) is None:
        return
    if (container or st).button(label, key=button_key or f"jump::{key}::{label}", **kwargs):
        go(key, **(state or {}))

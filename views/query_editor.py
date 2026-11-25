"""
Query editor with autocomplete for the IrisQL and CertsQL pages: a CodeMirror 5 editor (bundled in views/assets, no
network needed) that suggests the fields at the start of a line, then only the operators that field accepts, then
inserts the empty quotes or brackets the value goes in (or opens a short list to pick from, e.g. true / false),
never a made-up value. Lines a page
warning is about get a marker in the margin. The text reaches Python when the editor loses focus or on Ctrl/Cmd+Enter,
like st.text_area; it is kept in st.session_state[key].
"""
from functools import partial
from pathlib import Path

import streamlit as st

from core.query_assist import catalog, line_marks

_ASSETS = Path(__file__).parent / "assets"
_JS = "\n".join((_ASSETS / "codemirror" / "codemirror.min.js").read_text(encoding="utf-8").splitlines()[2:]) \
    + "\n" + (_ASSETS / "query_editor.js").read_text(encoding="utf-8")
_CSS = (_ASSETS / "codemirror" / "codemirror.css").read_text(encoding="utf-8") + "\n" \
    + (_ASSETS / "query_editor.css").read_text(encoding="utf-8")
_EDITOR = st.components.v2.component("dt_query_editor", css=_CSS, js=_JS, isolate_styles=False)
KEYS_HELP = ("Suggestions appear as you type (or with Ctrl+Space): fields at the start of a line, then the operators "
             "that field accepts, then the quotes or brackets the value goes in (or a short list to pick from, e.g. "
             "true / false). In a list, type a comma after the last value to add the next one. Tab jumps past the "
             "closing quote or bracket, Enter picks a suggestion, Esc closes the list. The version line "
             "(`# IrisQL-1.0` / `# CertsQL-1.0`) stays first: deleting it puts it back. The query is taken when you click outside the editor or press Ctrl+Enter (⌘+Enter).")


def _revision_key(key):
    return f"{key}_revision"


def set_query(key, text):
    """Replace the editor's text from Python (an example, a saved query): the editor drops what was typed for it."""
    st.session_state[key] = text
    st.session_state[_revision_key(key)] = st.session_state.get(_revision_key(key), 0) + 1


def clear_query(key, header, *also):
    """Clear button callback: the editor goes back to the version line alone, and the `also` keys (the last search's
    results, the example picked) are dropped."""
    set_query(key, f"{header}\n")
    for name in also:
        st.session_state.pop(name, None)


def query_actions(key, header, search_help, clear_keys=(), search_label="Search"):
    """
    Search and Clear under the editor. Search is always enabled, like the Start page's Analyze: clicking it is what
    takes the typed query (the editor sends its text when it loses focus), so a query just typed is searched on the
    first click. Returns True when Search was clicked; the page checks the query then.
    """
    row = st.container(horizontal=True, vertical_alignment="center")   # buttons keep their width in a narrow column
    clicked = row.button(search_label, type="primary", icon=":material/manage_search:", help=search_help,
                         width="content")
    typed = bool(str(st.session_state.get(key) or "").strip().removeprefix(header).strip())
    row.button("Clear", icon=":material/close:", type="tertiary", key=f"{key}_clear", width="content",
                   disabled=not typed and not any(st.session_state.get(k) for k in clear_keys),
                   on_click=clear_query, args=(key, header, *clear_keys),
                   help="Empties the query and removes the last search's results from this page (saved runs and "
                        "watches stay).")
    return clicked


def _take(key):
    """on_commit callback (runs before the page script): the typed text becomes the query, so this run's warnings and
    line markers are already about it."""
    committed = (st.session_state.get(f"{key}_editor") or {}).get("commit")
    if committed is not None:
        st.session_state[key] = committed


def query_editor(language, key, label, help=None, height=170):
    """The editor for `language` ("irisql" / "certsql"); returns the current query text (st.session_state[key])."""
    st.markdown(f"**{label}**", help=f"{help}\n\n{KEYS_HELP}" if help else KEYS_HELP)
    text = st.session_state.get(key, "")
    _EDITOR(key=f"{key}_editor", height="content", on_commit_change=partial(_take, key), data={
        "value": text, "revision": st.session_state.get(_revision_key(key), 0), "height": height,
        "catalog": catalog(language), "marks": {str(line): issue for line, issue in line_marks(language, text).items()}})
    return text

"""
Shared layout of the IrisQL and CertsQL pages: the query on the left, the same search as code and the last search's
status on the right, results full width below. The code is built from the editor's text, so it follows what is typed
without any request.
"""
import streamlit as st

CODE_HEIGHT = 330   # about the editor plus its options, so both columns end near the same line


def split():
    """(left, right) columns of the top half; they stack on narrow screens."""
    return st.columns([11, 9], gap="medium")


def code_panel(commands, key, height=CODE_HEIGHT):
    """The same search outside the app: one tab per command (curl first), each scrolling inside a fixed height."""
    st.markdown("**The same search outside the app**",
                help="Built from the query as typed (no request is made). The commands read your key from an "
                     "environment variable; no credential value is shown.")
    order = sorted(commands, key=lambda name: (name != "curl", name))
    for tab, name in zip(st.tabs(order, key=f"{key}_code_tabs"), order):
        with tab, st.container(height=height, border=False):
            python = name == "Python script"
            st.code(commands[name], language="python" if python else "bash", wrap_lines=not python)


def last_search_card(state, typed_query, facts, label):
    """
    The last search in a few words (`facts`: short strings), and a warning when the query was edited since, so the
    results below no longer match the editor.
    """
    with st.container(border=True):
        st.markdown(f"**Last search** · {label}")
        st.caption(" · ".join(facts))
        if typed_query.strip() != state["query"].strip():
            st.caption(":material/warning: The query was edited after this search: the results below are still "
                       "from the earlier query. Click Search to update them.")
        with st.expander("Query of these results", icon=":material/code:"):
            st.code(state["query"], language="text")


def tiles(items, per_row=4):
    """Metric tiles: (label, value, help) items, `per_row` to a row."""
    items = [item for item in items if item is not None]
    for start in range(0, len(items), per_row):
        for column, (label, value, help) in zip(st.columns(per_row), items[start:start + per_row]):
            column.metric(label, value, help=help)

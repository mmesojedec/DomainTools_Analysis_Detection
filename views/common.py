"""Shared Streamlit rendering helpers for all dashboard views."""
import hashlib

import pandas as pd
import streamlit as st

from config import MAX_RAW_DISPLAY_ROWS

PLOTLY_TEMPLATE = "plotly_dark"

def chart(fig, key=None, height=None, selectable=False):
    """
    Renders a Plotly figure with the dashboard theme at full container width.
    With `selectable=True` (requires `key`) clicks/box/lasso selections rerun the app and the selected points are returned.
    """
    layout = {"template": PLOTLY_TEMPLATE}
    if height:
        layout["height"] = height
    fig.update_layout(**layout)
    if selectable:
        event = st.plotly_chart(fig, width="stretch", key=key, on_select="rerun", selection_mode=("points", "box", "lasso"))
        try:
            return list(event.selection.points)
        except AttributeError:
            return list((event or {}).get("selection", {}).get("points", []))
    st.plotly_chart(fig, width="stretch", key=key)
    return []


def render_window_banner(ds, outside_count=0, outside_alerts=None):
    """Shows the active analysis window, how much data it keeps, and how many detections it hides."""
    if ds.window.is_all_time:
        st.caption(f"Analysis window: **{ds.window.describe(ds.timezone)}**")
        return
    kept = ", ".join(f"{name} {inside:,}/{total:,}" for name, (inside, total) in ds.window_stats.items() if total)
    message = f"**Analysis window — {ds.window.describe(ds.timezone)}.** Records in window: {kept or 'none'}."
    if outside_count:
        message += (f"  \n{outside_count} older detection(s) fall outside this window and are hidden from alerts, IOCs, and DIF "
                    "scoring — choose a longer window or *All time* in the sidebar to review them.")
    st.info(message)
    if outside_count and outside_alerts is not None and not outside_alerts.empty:
        with st.expander(f"Detections outside the window ({outside_count})", expanded=False):
            table(outside_alerts[["Domain", "Threat Type", "Severity", "Confidence", "Threat Logic"]])


def table(df, **kwargs):
    """Full-width dataframe without the index."""
    kwargs.setdefault("hide_index", True)
    return st.dataframe(df, width="stretch", **kwargs)


def capped_table(df, label="rows", **kwargs):
    """Renders at most MAX_RAW_DISPLAY_ROWS rows and states when the view is truncated."""
    if len(df) > MAX_RAW_DISPLAY_ROWS:
        st.caption(f"Showing the first {MAX_RAW_DISPLAY_ROWS:,} of {len(df):,} {label}. Narrow the sidebar filters to see the rest.")
        df = df.head(MAX_RAW_DISPLAY_ROWS)
    return table(df, **kwargs)


def selection_key(base, values):
    """
    Key for a selectable table that changes with the rows it shows: Streamlit keeps a keyed table's selection when its
    data changes, so after a filter change the old row positions would point at other rows or past the end.
    """
    digest = hashlib.blake2b("\n".join(map(str, values)).encode(), digest_size=8).hexdigest()
    return f"{base}::{digest}"


def selected_rows(event, frame):
    """Row positions selected in a table showing `frame`, leaving out any that no longer exist."""
    rows = list(event.selection.rows) if event is not None else []
    return [r for r in rows if 0 <= r < len(frame)]


def explainer(title, body):
    with st.expander(title):
        st.markdown(body)


def clean_strings(df):
    """Converts a frame to display strings, blanking missing markers."""
    return df.astype(str).replace({"nan": "", "NaT": "", "None": "", "<NA>": ""})


def format_datetime_columns(df, columns, fmt="%Y-%m-%d %H:%M:%S"):
    for col in columns:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce").dt.strftime(fmt)
    return df


_COPY_FALLBACK = """<script>
(() => {
  // The Copy buttons on code blocks use navigator.clipboard.writeText, which some browsers and embedded browser panes
  // refuse ("Write permission denied", or no navigator.clipboard over plain http on another host). Fall back to the
  // older copy command, which the click that started it still allows.
  if (window.dtCopyFallback) return;
  window.dtCopyFallback = true;
  const legacyCopy = (text) => {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.cssText = "position:fixed;top:-1000px;left:0;opacity:0";
    const active = document.activeElement;
    document.body.appendChild(area);
    area.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch (error) { copied = false; }
    area.remove();
    if (active && active.focus) active.focus({preventScroll: true});
    if (!copied) throw new DOMException("Copy failed", "NotAllowedError");
  };
  if (!navigator.clipboard) {
    try { Object.defineProperty(navigator, "clipboard", {value: {}, configurable: true}); } catch (error) { return; }
  }
  const original = navigator.clipboard.writeText ? navigator.clipboard.writeText.bind(navigator.clipboard) : null;
  navigator.clipboard.writeText = async (text) => {
    if (original) {
      try { return await original(text); } catch (error) { /* refused: use the copy command */ }
    }
    legacyCopy(String(text));
  };
})();
</script>"""


def install_copy_fallback():
    """Makes the Copy buttons of st.code blocks (curl, Python, queries, lists) work where the browser refuses the
    clipboard API; drawn once per run, the script patches the page once."""
    st.html(_COPY_FALLBACK, unsafe_allow_javascript=True)

"""
"Show international domains in Unicode" (sidebar): punycode labels (xn--bcher-kva.de) are drawn as Unicode
(bücher.de) in every table, text and chart, while the data itself stays ASCII. Lookups, filters, exports, downloads and
the copyable queries (st.code) keep the ASCII form the APIs and other tools need.

The conversion happens where Streamlit draws: install() wraps the table, text and chart functions once, and each call
decodes `xn--` labels only while the switch is on. One place covers every page, also tables added later.
"""
import functools
import threading
from contextlib import contextmanager

import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from streamlit.delta_generator import DeltaGenerator

from core.idn import has_ace, to_unicode

UNICODE_KEY = "show_unicode"
TEXT_FUNCTIONS = ("markdown", "caption", "info", "warning", "success", "error")
TABLE_FUNCTIONS = ("dataframe", "table")
CHART_FUNCTIONS = ("plotly_chart",)
_paused = threading.local()   # each session's script runs in its own thread


def enabled():
    return bool(st.session_state.get(UNICODE_KEY)) and not getattr(_paused, "on", False)


@contextmanager
def paused():
    """Draws as is inside the block (the documentation shows xn-- examples on purpose)."""
    _paused.on = True
    try:
        yield
    finally:
        _paused.on = False


def display_name(name):
    """`name` as the analyst wants to read it: Unicode while the switch is on (for widget labels and options)."""
    return to_unicode(name) if enabled() else name


def _cell(value):
    if isinstance(value, str):
        return to_unicode(value)
    if isinstance(value, (list, tuple)):
        return [to_unicode(item) if isinstance(item, str) else item for item in value]
    return value


def _column(series):
    """The column with xn-- labels decoded, or None when it has none (numbers, dates and ASCII-only text)."""
    if not (pd.api.types.is_object_dtype(series) or pd.api.types.is_string_dtype(series)):
        return None
    found = series.astype(str).str.contains("xn--", case=False, regex=False)
    if not found.any():
        return None
    return pd.Series([_cell(v) if hit else v for v, hit in zip(series, found)], index=series.index, dtype=object)


def unicode_frame(frame):
    """A copy of `frame` with every xn-- label in its text cells (lists too) and index decoded; `frame` if none."""
    if not isinstance(frame, pd.DataFrame) or frame.empty:
        return frame
    out = None
    for column in frame.columns:
        decoded = _column(frame[column])
        if decoded is not None:
            out = frame.copy() if out is None else out
            out[column] = decoded
    index = _column(pd.Series(frame.index, index=frame.index)) if not isinstance(frame.index, pd.MultiIndex) else None
    if index is not None:
        out = frame.copy() if out is None else out
        out.index = pd.Index(index.to_list(), name=frame.index.name)
    return frame if out is None else out


def _decoded_strings(values):
    return {v: to_unicode(v) for v in (values if values is not None else ()) if isinstance(v, str) and has_ace(v)}


def unicode_figure(figure):
    """
    A copy of a Plotly figure with xn-- names shown in Unicode: axis tick labels (through labelalias, so the data and
    click selections keep ASCII), legend names, text labels, Sankey nodes and treemap / sunburst labels.
    """
    if not isinstance(figure, go.Figure):
        return figure
    figure = go.Figure(figure)
    axis_x, axis_y = {}, {}
    for trace in figure.data:
        if isinstance(getattr(trace, "name", None), str) and has_ace(trace.name):
            trace.name = to_unicode(trace.name)
        axis_x.update(_decoded_strings(getattr(trace, "x", None)))
        axis_y.update(_decoded_strings(getattr(trace, "y", None)))
        for attribute in ("text", "hovertext"):
            value = getattr(trace, attribute, None)
            if isinstance(value, str):
                setattr(trace, attribute, to_unicode(value))
            elif value is not None and _decoded_strings(value):
                setattr(trace, attribute, [_cell(v) for v in value])
        # labels are display only when ids carry the hierarchy (plotly express sets them)
        if getattr(trace, "labels", None) is not None and (getattr(trace, "ids", None) is not None
                                                          or getattr(trace, "parents", None) is None):
            if _decoded_strings(trace.labels):
                trace.labels = [_cell(v) for v in trace.labels]
        if trace.type == "sankey" and trace.node.label is not None and _decoded_strings(trace.node.label):
            trace.node.label = [_cell(v) for v in trace.node.label]
    if axis_x:
        figure.update_xaxes(labelalias=axis_x)
    if axis_y:
        figure.update_yaxes(labelalias=axis_y)
    return figure


def _convert(value):
    if isinstance(value, str):
        return to_unicode(value)
    if isinstance(value, pd.DataFrame):
        return unicode_frame(value)
    if isinstance(value, go.Figure):
        return unicode_figure(value)
    return value


def _wrap(function):
    @functools.wraps(function)
    def drawn(*args, **kwargs):
        if enabled():
            args = tuple(_convert(arg) for arg in args)
            kwargs = {key: _convert(value) if key in ("body", "data", "figure_or_data", "help") else value
                      for key, value in kwargs.items()}
        return function(*args, **kwargs)
    drawn.idn_wrapped = True
    return drawn


def install():
    """Wraps the drawing functions once per process (st.xxx and every container's .xxx)."""
    for name in TEXT_FUNCTIONS + TABLE_FUNCTIONS + CHART_FUNCTIONS:
        for owner in (DeltaGenerator, st):
            function = getattr(owner, name)
            if not getattr(function, "idn_wrapped", False):
                setattr(owner, name, _wrap(function))

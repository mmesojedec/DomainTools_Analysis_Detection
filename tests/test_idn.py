import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

import views.idn_display as idn_display
from core.cert_inputs import idn_conversions, parse_inputs
from core.helpers import normalize_to_apex
from core.idn import has_ace, to_ascii, to_unicode, unicode_label


def test_unicode_names_become_punycode_and_back():
    assert to_ascii("Bücher.DE") == "xn--bcher-kva.de"
    assert to_ascii("*.shop.münchen.de") == "*.shop.xn--mnchen-3ya.de"
    assert to_ascii("аpple.com") == "xn--pple-43d.com"   # Cyrillic а
    assert to_ascii("example.com") == "example.com"
    assert to_unicode("CN=xn--bcher-kva.de; *.XN--MNCHEN-3YA.de, xn--zz-bad") == "CN=bücher.de; *.münchen.de, xn--zz-bad"
    assert to_unicode(42) == 42 and not has_ace("example.com")
    assert unicode_label("xn--bcher-kva.de") == "xn--bcher-kva.de (bücher.de)" and unicode_label("a.com") == "a.com"


def test_unicode_targets_are_looked_up_in_punycode():
    raw = "bücher.de\nshop.münchen.de, example.com\nsan:*.bücher.de\ncn:bücher.de"
    items = {(item.kind, item.value) for item in parse_inputs(raw)}
    assert {("domain", "xn--bcher-kva.de"), ("domain", "shop.xn--mnchen-3ya.de"), ("domain", "example.com"),
            ("san", "*.xn--bcher-kva.de"), ("cn", "xn--bcher-kva.de")} <= items
    assert normalize_to_apex(["shop.xn--mnchen-3ya.de"])[0] == ["xn--mnchen-3ya.de"]
    assert idn_conversions(raw)[:2] == [("bücher.de", "xn--bcher-kva.de"), ("shop.münchen.de", "shop.xn--mnchen-3ya.de")]
    assert idn_conversions("example.com xn--bcher-kva.de") == []


def test_frames_are_decoded_for_display_only():
    frame = pd.DataFrame({"Domain": ["xn--bcher-kva.de", "a.com"], "Names": [["*.xn--bcher-kva.de"], []],
                          "Count": [1, 2]}).set_index(pd.Index(["xn--bcher-kva.de", "a.com"]))
    shown = idn_display.unicode_frame(frame)
    assert list(shown["Domain"]) == ["bücher.de", "a.com"] and shown["Names"].iloc[0] == ["*.bücher.de"]
    assert list(shown.index) == ["bücher.de", "a.com"] and list(shown["Count"]) == [1, 2]
    assert frame["Domain"].iloc[0] == "xn--bcher-kva.de"   # the data itself is untouched
    plain = pd.DataFrame({"Domain": ["a.com"]})
    assert idn_display.unicode_frame(plain) is plain


def test_figures_show_unicode_labels_but_keep_the_data():
    figure = px.bar(pd.DataFrame({"Domain": ["xn--bcher-kva.de", "a.com"], "Alerts": [2, 1]}), x="Domain", y="Alerts",
                    color="Domain")
    figure.add_trace(go.Sankey(node={"label": ["xn--bcher-kva.de", "1.1.1.1"]}, link={"source": [0], "target": [1],
                                                                                       "value": [1]}))
    shown = idn_display.unicode_figure(figure)
    assert shown.layout.xaxis.labelalias == {"xn--bcher-kva.de": "bücher.de"}
    assert shown.data[0].name == "bücher.de" and list(shown.data[0].x) == ["xn--bcher-kva.de"]
    assert list(shown.data[-1].node.label) == ["bücher.de", "1.1.1.1"]
    assert figure.data[0].name == "xn--bcher-kva.de"   # the original figure is untouched


def test_drawing_functions_decode_only_while_the_switch_is_on(monkeypatch):
    drawn = []
    wrapped = idn_display._wrap(lambda body, help=None: drawn.append((body, help)))
    state = {}
    monkeypatch.setattr(st, "session_state", state)
    wrapped("on xn--bcher-kva.de", help="xn--bcher-kva.de")
    state[idn_display.UNICODE_KEY] = True
    wrapped("on xn--bcher-kva.de", help="xn--bcher-kva.de")
    with idn_display.paused():
        wrapped("docs xn--bcher-kva.de")
    assert drawn == [("on xn--bcher-kva.de", "xn--bcher-kva.de"), ("on bücher.de", "bücher.de"),
                     ("docs xn--bcher-kva.de", None)]
    assert idn_display.display_name("xn--bcher-kva.de") == "bücher.de"
    idn_display.install()
    idn_display.install()   # once: a second call does not wrap again
    assert st.dataframe.idn_wrapped and not getattr(st.dataframe.__wrapped__, "idn_wrapped", False)

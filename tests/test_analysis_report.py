"""Analysis report: HTML blocks (escaping, tables, charts by mode, graphs), the header and section isolation."""
from types import SimpleNamespace

import pandas as pd
import plotly.express as px

from core import analysis_report as report
from core.report_html import CHARTS_CDN, CHARTS_EMBED, CHARTS_NONE, Builder, frame_table


def test_tables_escape_and_cap_rows():
    frame = pd.DataFrame({"Domain": ["<b>x</b>.com", "y.com"], "Severity": ["High", "Low"], "Hash": ["ab", "cd"],
                          "Flag": [True, False], "Score": [1.0, 2.5]})
    out = frame_table(frame, max_rows=1)
    assert "&lt;b&gt;x&lt;/b&gt;.com" in out and "<b>x" not in out
    assert 'class="pill"' in out and 'class="mono"' in out and "✓" in out
    assert "The first 1 of 2 rows" in out and "y.com" not in out
    assert "No rows" in frame_table(pd.DataFrame())


def test_charts_follow_the_mode_and_contents_list_sections():
    fig = px.bar(pd.DataFrame({"a": [1], "b": [2]}), x="a", y="b")
    pages = {}
    for mode in (CHARTS_EMBED, CHARTS_CDN, CHARTS_NONE):
        b = Builder(charts=mode)
        b.part("Overview")
        b.section("Summary")
        b.figure(fig)
        b.dot("digraph { a -> b }")
        pages[mode] = b.html("T", "<h1>T</h1>")
    assert len(pages[CHARTS_EMBED]) > 1_000_000 and "Plotly.newPlot" in pages[CHARTS_EMBED]
    assert "cdn.plot.ly/plotly-" in pages[CHARTS_CDN] and len(pages[CHARTS_CDN]) < 100_000
    assert "Plotly" not in pages[CHARTS_NONE] and "viz-standalone" not in pages[CHARTS_NONE]
    assert 'href="#summary"' in pages[CHARTS_CDN] and 'data-dot="digraph { a -&gt; b }"' in pages[CHARTS_CDN]


def test_header_has_analyst_window_sources_and_summary():
    ds = SimpleNamespace(selected_domains=["a.com", "b.com"], events_utc=pd.DataFrame(
        {"Date": ["2026-01-02", "2026-03-04"]}), pdns_utc=pd.DataFrame())
    collected = SimpleNamespace(statuses=[{"Source": "Passive DNS", "Status": "OK", "Detail": "From cache"},
                                          {"Source": "Iris Investigate", "Status": "Error", "Detail": ""}])
    ctx = report.ReportContext(ds=ds, collected=collected, alerts=pd.DataFrame(), profiles=pd.DataFrame(),
                               window="Last 90 days", origin="live lookups", created="2026-03-05T10:00:00")
    out = report.header_html({"title": "Case <1>", "analyst": "Team Blue", "summary": "We found it."}, ctx)
    assert "Case &lt;1&gt;" in out and "Team Blue" in out and "Last 90 days" in out
    assert "2026-01-02 → 2026-03-04" in out and "Passive DNS: 1 lookup(s), 1 from cache" in out
    assert "Iris Investigate: 1 lookup(s), 1 failed" in out and "We found it." in out


def test_a_failing_section_does_not_lose_the_report(monkeypatch):
    from views import report_sections

    def boom(b, ctx):
        raise ValueError("broken")
    monkeypatch.setattr(report_sections, "section_tor", boom)
    ds = SimpleNamespace(selected_domains=["a.com"], events_utc=pd.DataFrame(), pdns_utc=pd.DataFrame(),
                         tor_overview={})
    ctx = report.ReportContext(ds=ds, collected=SimpleNamespace(statuses=[]), alerts=pd.DataFrame(),
                               profiles=pd.DataFrame())
    out = report.build_analysis_report(ctx, {"title": "R"}, ["tor", "hunt_map"], charts=CHARTS_NONE)
    assert "could not be built: ValueError: broken" in out and "not part of a saved hunt" in out
    assert out.index("Infrastructure") < out.index("Hunt map")


def test_every_section_has_a_builder():
    from views import report_sections
    assert all(hasattr(report_sections, f"section_{s.key}") for s in report.SECTIONS)
    assert {s.part for s in report.SECTIONS} == set(report.PARTS)


def test_streamlit_placeholder_colours_become_the_app_palette():
    from core.report_html import CATEGORICAL, SEQUENTIAL, app_colors
    fig = px.bar(pd.DataFrame({"a": [1, 2], "b": ["x", "y"]}), x="a", y="b", color="b",
                 color_discrete_sequence=["#000001", "#000002"])
    b = Builder(charts=CHARTS_CDN)
    b.figure(fig)
    b.dot('digraph { node [fillcolor="#2f2f2f"]; a -> b }')
    page = b.html("T", "")
    assert "#000001" not in page and "#000002" not in page
    assert CATEGORICAL[0] in page and CATEGORICAL[1] in page and "#2f2f2f" not in page and "#607d8b" in page
    assert app_colors('"#000011" "#000040" "#0000ff" "#00001a"') == f'"{SEQUENTIAL[0]}" "#f0f2f6" "#0000ff" "#00001a"'


def test_iocs_take_the_most_severe_alert_behind_them():
    iocs = pd.DataFrame({"Type": ["ipv4-addr", "ipv4-addr", "domain-name", "ipv4-addr"],
                         "Value": ["1.2.3.4", "5.6.7.8", "b.com", "9.9.9.9"],
                         "Domain": ["a.com", "a.com", "b.com", "c.com"], "Source": "DNSDB"})
    alerts = pd.DataFrame([
        {"Domain": "a.com", "Severity": "Medium", "Threat Type": "x", "Triggering IOCs": "IP 1.2.3.4, NS y"},
        {"Domain": "a.com", "Severity": "Critical", "Threat Type": "y", "Triggering IOCs": "",
         "Evidence": [{"Field": "A", "Artifact": "5.6.7.8"}]},
        {"Domain": "b.com", "Severity": "High", "Threat Type": "z", "Triggering IOCs": "(1.2.3.4)"}])
    ranked = report.ioc_severity(iocs, alerts)
    assert list(ranked["Value"]) == ["5.6.7.8", "1.2.3.4", "b.com", "9.9.9.9"]
    by_value = ranked.set_index("Value")
    assert by_value.loc["5.6.7.8", "Basis"] == "Alert evidence"
    # cited by a Medium and a High alert, but its domain has a Critical one: the domain wins
    assert (by_value.loc["1.2.3.4", "Severity"], by_value.loc["1.2.3.4", "Basis"]) == ("Critical", "Domain alert")
    assert by_value.loc["b.com", "Severity"] == "High" and by_value.loc["9.9.9.9", "Severity"] == ""
    assert list(ranked.columns[:3]) == ["Severity", "Type", "Value"]
    assert len(report.report_iocs(iocs, alerts, ("Critical",), limit=1)) == 1
    assert report.ioc_severity(pd.DataFrame(), alerts).empty


def test_levels_set_how_many_rows_tables_show():
    frame = pd.DataFrame({"n": range(40)})
    short, normal, full = (Builder(charts=CHARTS_NONE, row_cap=15), Builder(charts=CHARTS_NONE),
                           Builder(charts=CHARTS_NONE, unlimited=True))
    for b in (short, normal, full):
        b.section("S")
        b.table(frame, max_rows=20)
        b.table(frame, max_rows=5, exact=True)
    assert "The first 15 of 40" in "".join(short.parts) and "The first 20 of 40" in "".join(normal.parts)
    assert "The first 20" not in "".join(full.parts) and all("The first 5 of 40" in "".join(b.parts)
                                                              for b in (short, normal, full))
    fig = px.bar(pd.DataFrame({"a": [1], "b": [2]}), x="a", y="b")
    short.detail = False
    short.figure(fig, secondary=True)
    assert short.figures == 0
    assert {level.key for level in report.LEVELS.values()} == {report.HIGH, report.DETAILED, report.COMPLETE}


def test_report_page_has_sidebar_sections_and_level():
    from views import report_sections
    ds = SimpleNamespace(selected_domains=["a.com"], events_utc=pd.DataFrame(), pdns_utc=pd.DataFrame(),
                         tor_overview={})
    ctx = report.ReportContext(ds=ds, collected=SimpleNamespace(statuses=[]), alerts=pd.DataFrame(),
                               profiles=pd.DataFrame(), level=report.LEVELS[report.HIGH])
    out = report.build_analysis_report(ctx, {"title": "R"}, ["hunt_map", "tor"], charts=CHARTS_NONE)
    assert 'class="side"' in out and 'href="#sec-tor"' in out and 'id="sec-hunt-map"' in out
    assert "High level overview" in out and out.count('<section class="sec"') == out.count("</section>") == 2
    assert hasattr(report_sections, "section_attention")


def test_report_building_makes_no_streamlit_call(caplog):
    """The report is built on the download click, outside the script run: Streamlit would warn 'missing
    ScriptRunContext' for any session-state read on that path."""
    import logging

    from views.idn_display import display_name
    from views.similarity_view import indicator_graph
    with caplog.at_level(logging.WARNING):
        assert display_name("xn--bcher-kva.de") == "xn--bcher-kva.de"
        indicators = pd.DataFrame([{"Category": "Hosting", "Type": "IP", "Indicator": "1.2.3.4", "Source": "Iris",
                                    "Domains": 2, "Share %": 100, "Seen On": "", "Rarity": None,
                                    "Domain List": ["a.com", "b.com"]}])
        indicator_graph(["a.com", "b.com"], indicators)
    assert "ScriptRunContext" not in caplog.text

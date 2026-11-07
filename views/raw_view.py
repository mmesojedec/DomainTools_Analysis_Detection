"""Lens 4: Forensic raw records review."""
import json

import pandas as pd
import streamlit as st

from config import CACHE_LIFETIMES
from core.anonymizers import answer_tables as response_tables
from core.api_usage import cache_group, failed_lookups
from core.dataset import expand_multiline_rows
from core.offline import format_size
from core.timezone import format_in_tz
from integrations.cache import cache_ttl, cache_usage, group_ttl
from views.common import capped_table, clean_strings, format_datetime_columns, selected_rows, selection_key, table

CERT_COLUMNS = [
    "Domain", "Source", "Common Name", "Issuer", "Duration", "Validation Level", "Is Self Signed", "Hash",
    "Public Key SHA256", "Subject Key ID", "Authority Key ID", "Is Precertificate", "Signature Algo",
    "Alt Names List", "Not Before Date", "Not After Date",
]
PDNS_COLUMNS = ["First Seen", "Last Seen", "Domain", "RRName", "Source", "Field", "Count", "Bailiwick", "Value", "Lifespan Days"]


def _join_list(value):
    return ", ".join(str(v) for v in value) if isinstance(value, list) else ("" if value is None else str(value))


def _render_txt(ds):
    if ds.txt_apps.empty:
        return
    st.subheader("Raw TXT Records")
    cols = ["Domain", "Source", "Application / Tag", "Category", "First Seen", "Last Seen", "Query Count", "Lifespan (Days)", "Original Payload", "Note"]
    view = ds.txt_apps[[c for c in cols if c in ds.txt_apps.columns]].rename(columns={
        "Domain": "Domain / IP",
        "First Seen": f"First Seen ({ds.timezone})",
        "Last Seen": f"Last Seen ({ds.timezone})",
    })
    capped_table(view, label="TXT records")


def _render_certs(ds):
    if ds.ssl.empty:
        return
    st.subheader("Raw Certificate Logs")
    view = ds.ssl[[c for c in CERT_COLUMNS if c in ds.ssl.columns]].copy()
    if "Alt Names List" in view.columns:
        view["Alt Names List"] = view["Alt Names List"].map(_join_list)
    view = clean_strings(format_datetime_columns(view, ["Not Before Date", "Not After Date"]))
    view = view.rename(columns={
        "Domain": "Domain / IP",
        "Alt Names List": "Subject Alternative Names (SANs)",
        "Not Before Date": f"Valid From ({ds.timezone})",
        "Not After Date": f"Valid To ({ds.timezone})",
    })
    capped_table(view, label="certificates")

    obs = ds.cert_observations
    if obs.empty or "Cert_SHA256" not in obs.columns:
        return
    obs = obs[obs["Cert_SHA256"].isin(set(ds.ssl["Hash"].dropna()))].copy()
    if obs.empty:
        return
    time_col = f"Timestamp ({ds.timezone})"
    obs[time_col] = format_in_tz(obs["Timestamp"], ds.timezone)
    st.markdown("##### Certificate Co-occurrence (Observed Infrastructure via `/events/sha256`)",
                help="Other domains, hostnames, and IPs observed presenting the same certificate SHA-256 fingerprint.")
    with st.expander(f"View {len(obs)} Extended Host/IP Observations for Analyzed Certificates", expanded=False):
        capped_table(obs[["Cert_SHA256", "Observed Domain", "Observed Hostname", "Observed IP", time_col]], label="observations")


def _render_domain_history(ds):
    if ds.dh.empty:
        return
    st.subheader("Domain History Logs")
    time_col = f"Timestamp ({ds.timezone})"
    base = ds.dh[["Domain", "Date", "Field", "Before", "After", "Day of Week", "Days Since Previous Event"]].copy()
    base = clean_strings(format_datetime_columns(base, ["Date"])).rename(columns={"Date": time_col, "Domain": "Domain / IP"})
    expanded = expand_multiline_rows(
        base, split_cols=["Before", "After"],
        blank_cols=["Domain / IP", time_col, "Field", "Day of Week", "Days Since Previous Event"],
    )
    capped_table(expanded, label="history lines")


def _render_pdns(ds):
    if ds.pdns.empty:
        return
    st.subheader("Passive DNS Logs")
    cols = [c for c in PDNS_COLUMNS if c in ds.pdns.columns]
    base = clean_strings(format_datetime_columns(ds.pdns[cols].copy(), ["First Seen", "Last Seen"]))
    expanded = expand_multiline_rows(base, split_cols=["Value"], blank_cols=[c for c in cols if c != "Value"])
    first_col, last_col = f"First Seen ({ds.timezone})", f"Last Seen ({ds.timezone})"
    expanded = expanded.rename(columns={
        "Domain": "Domain / IP", "Field": "Type", "Value": "Response", "First Seen": first_col, "Last Seen": last_col,
    })
    final_cols = [first_col, last_col, "Domain / IP", "RRName", "Source", "Type", "Count", "Bailiwick", "Response", "Lifespan Days"]
    capped_table(expanded[[c for c in final_cols if c in expanded.columns]], label="pDNS response lines")


def _render_vpndb(ds):
    raw = ds.vpndb_raw
    if raw is None or raw.empty:
        return
    st.subheader("VPNDB Responses", help="Every VPNDB answer of the run as received, one row per lookup. Select one to "
                                         "see it as tables: its fields, then each list it holds (the bulk results, "
                                         "a range's addresses, an exit's weekly history ...). Lookup Queries → VPNDB has "
                                         "the requests to send again.")
    view = raw[["Endpoint", "Target", "Status", "Records", "Detail", "Cached At"]]
    event = st.dataframe(view, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                         key=selection_key("raw_vpndb", raw["Endpoint"] + raw["Target"].astype(str)),
                         column_config={"Cached At": st.column_config.DatetimeColumn("Cached at (UTC)",
                                                                                     format="YYYY-MM-DD HH:mm")})
    rows = selected_rows(event, raw)
    if not rows:
        st.caption(f"{len(raw):,} VPNDB lookup(s). Select one to see its answer.")
        return
    row = raw.iloc[rows[0]]
    response = json.loads(row["Response"]) if row["Response"] else None
    st.markdown(f"**{row['Endpoint']}** `{row['Target']}`")
    for name, frame in response_tables(response).items():
        if frame.empty:
            continue
        st.markdown(f"**{name}** ({len(frame):,})" if name != "Fields" else "**Fields**")
        capped_table(frame.astype(str), label=f"{name} rows")
    with st.expander("As received (JSON)"):
        st.json(response, expanded=False)
    st.download_button("Download this answer (JSON)", row["Response"], key="raw_vpndb_download", mime="application/json",
                       file_name=f"vpndb_{row['Endpoint'].strip('/').replace('/', '_').replace('{', '').replace('}', '')}"
                                 f"_{str(row['Target']).replace('/', '_')}.json")


def render_raw_lens(ds):
    st.markdown("### Analyst Raw Records Review",
                help="Full raw logs with untruncated payloads and timezone-aligned timestamps.")
    _render_txt(ds)
    _render_certs(ds)
    _render_domain_history(ds)
    _render_pdns(ds)
    _render_vpndb(ds)


CACHE_SOURCE_COLUMNS = ["Source", "Lookups", "From Cache", "Live", "Oldest Cached At", "Newest Cached At",
                        "Expires At"]


def cache_summary(statuses, lifetime, run_time=None):
    """
    Per source (CACHE_SOURCE_COLUMNS): lookups of the run, how many came from the cache, the oldest and newest cached
    result, and when the first of them expires (`lifetime` seconds after it was fetched; for live lookups,
    `lifetime` after `run_time`). `lifetime` may be a function of the Source (each source's own cache lifetime).
    Summary rows ("3 domain(s)") are not lookups and are left out.
    """
    if not statuses:
        return pd.DataFrame(columns=CACHE_SOURCE_COLUMNS)
    df = pd.DataFrame(statuses).reindex(columns=["Source", "Target", "Status", "Detail", "Cached At"])
    df = df[~df["Target"].astype(str).str.contains(" ") & (df["Status"] != "Error")]
    if df.empty:
        return pd.DataFrame(columns=CACHE_SOURCE_COLUMNS)
    cached_at = pd.to_datetime(df["Cached At"], errors="coerce")
    run_time = pd.to_datetime(run_time, errors="coerce", utc=True)
    run_time = run_time.tz_localize(None) if pd.notna(run_time) else pd.NaT
    fetched = cached_at.fillna(run_time)
    rows = []
    for source, group in df.assign(_cached=cached_at, _fetched=fetched).groupby("Source", sort=False):
        hits = group["_cached"].notna()
        first = group["_fetched"].min()
        seconds = lifetime(source) if callable(lifetime) else lifetime
        rows.append({"Source": source, "Lookups": len(group), "From Cache": int(hits.sum()), "Live": int((~hits).sum()),
                     "Oldest Cached At": group["_cached"].min(), "Newest Cached At": group["_cached"].max(),
                     "Expires At": first + pd.Timedelta(seconds=seconds) if seconds and pd.notna(first) else pd.NaT})
    return pd.DataFrame(rows, columns=CACHE_SOURCE_COLUMNS).sort_values("From Cache", ascending=False, kind="stable") \
        .reset_index(drop=True)


def _until(ts):
    if pd.isna(ts):
        return "–"
    seconds = (ts - pd.Timestamp.now("UTC").tz_localize(None)).total_seconds()
    if seconds <= 0:
        return "expired"
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size:
            return f"in {seconds / size:.0f} {unit}"
    return "in < 1 min"


def render_cache_panel(statuses, timezone, run_time=None, can_rerun=True, expanded=False):
    """
    Cached details: how much of the run came from the lookup cache, how old it is and when it expires, with buttons to
    analyze the same targets again. Returns "fresh" (re-run with fresh lookups), "cached" (re-run, cache allowed) or
    None.
    """
    lifetime = cache_ttl()
    summary = cache_summary(statuses, lambda source: group_ttl(cache_group(source)), run_time)
    failed = failed_lookups(statuses)
    hits, total = int(summary["From Cache"].sum()), int(summary["Lookups"].sum())
    label = "Cached details" + (f" — {hits:,} of {total:,} lookup(s) from the cache" if total else "")
    choice = None
    with st.expander(label, expanded=expanded):
        files, size = cache_usage()
        lifetime_label = next((k for k, v in CACHE_LIFETIMES.items() if v == lifetime), f"{lifetime / 3600:g} h")
        oldest = summary["Oldest Cached At"].min() if not summary.empty else pd.NaT
        expires = summary["Expires At"].min() if not summary.empty else pd.NaT
        metrics = [
            ("Cache lifetime", lifetime_label, "Settings → Lookup cache. How long a successful lookup is reused; "
                                               "sources with their own lifetime are listed there"),
            ("From cache", f"{hits:,} of {total:,}", "Lookups of this run served from the cache (no API query)"),
            ("API queries", f"{total - hits:,}", "Lookups of this run that queried the APIs (now cached too)"),
            ("Oldest cached data", _ago(oldest), "Age of the oldest cached result this run used"),
            ("First expiry", _until(expires), "When the first result of this run leaves the cache; a later run then "
                                              "queries it again"),
            ("Cache on disk", f"{files:,} · {format_size(size)}", "Cached lookups in dt_cache/ for every target"),
        ]
        for col, (name, value, help_text) in zip(st.columns(len(metrics)), metrics):
            col.metric(name, value, help=help_text)
        created = pd.to_datetime(run_time, errors="coerce", utc=True)
        if pd.notna(created):
            st.caption(f"For the lookups of the run collected {created.tz_convert(timezone):%Y-%m-%d %H:%M} "
                       f"({timezone}); expiry counts the Cache lifetime (Settings) from when each result was fetched.")
        if lifetime == 0:
            st.caption("The cache is off (Settings → Lookup cache), so every lookup queries the APIs.")
        if not summary.empty:
            view = summary.assign(**{c: _local(summary[c], timezone)
                                     for c in ("Oldest Cached At", "Newest Cached At", "Expires At")},
                                  **{"Valid For": summary["Expires At"].map(_until)})
            st.dataframe(view, hide_index=True, width="stretch", column_config={
                "Lookups": st.column_config.NumberColumn("Lookups", help="Lookups of this run from that source"),
                "From Cache": st.column_config.NumberColumn("From cache", help="Served from the cache, no API query"),
                "Live": st.column_config.NumberColumn("API queries", help="Queried the API in this run"),
                "Oldest Cached At": st.column_config.DatetimeColumn("Oldest cached at", format="YYYY-MM-DD HH:mm"),
                "Newest Cached At": st.column_config.DatetimeColumn("Newest cached at", format="YYYY-MM-DD HH:mm"),
                "Expires At": st.column_config.DatetimeColumn(
                    "First expiry", format="YYYY-MM-DD HH:mm",
                    help="When this source's oldest result of the run leaves the cache"),
                "Valid For": st.column_config.Column("Valid for", help="Time left until that expiry"),
            })
        if can_rerun:
            st.caption("Analyze the same targets again with the collection settings of this run. *Fresh lookups* queries "
                       "every source again and refreshes these targets' cache entries (other targets' cache is kept); "
                       "*Re-run* reuses whatever is still cached, like **Analyze**. Certificate inputs are not "
                       "searched again: their derived domains and IPs are re-run.")
            c_fresh, c_cached, c_retry, _ = st.columns([1, 1, 1, 1])
            if c_fresh.button("Re-run with fresh lookups", key="rerun_fresh", icon=":material/refresh:", type="primary",
                              help="Uses API quota for every lookup"):
                choice = "fresh"
            if c_cached.button("Re-run (use cache)", key="rerun_cached", icon=":material/replay:"):
                choice = "cached"
            if c_retry.button(f"Retry {failed:,} failed lookup(s)", key="rerun_failed", icon=":material/restart_alt:",
                              disabled=not failed or lifetime <= 0,
                              help="Analyzes the same targets again: the lookups that worked come from the lookup "
                                   "cache (no query), so only the failed ones query the APIs. Needs the cache on."):
                choice = "retry"
        else:
            st.caption("This dataset has no recorded collection settings, so it cannot be re-run from here; use "
                       "**Analyze** in the sidebar.")
    return choice


def _ago(ts):
    if pd.isna(ts):
        return "–"
    seconds = max(0, (pd.Timestamp.now("UTC").tz_localize(None) - ts).total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if seconds >= size:
            return f"{seconds / size:.0f} {unit} old"
    return "< 1 min old"


def _local(series, tz):
    return pd.to_datetime(series, errors="coerce").dt.tz_localize("UTC").dt.tz_convert(tz).dt.tz_localize(None)


def render_status_panel(statuses, expanded=False):
    """Per-source collection outcome so authentication errors and truncation are never silent."""
    if not statuses:
        return
    status_df = pd.DataFrame(statuses).drop(columns="Request", errors="ignore")   # requests: Lookup Queries page
    problems = status_df[status_df["Status"].isin(["Error", "Partial"])]
    label = "Data Source Status"
    if not problems.empty:
        label += f" — {int((problems['Status'] == 'Error').sum())} error(s), {int((problems['Status'] == 'Partial').sum())} partial"
    with st.expander(label, expanded=expanded):
        summary = status_df.groupby(["Source", "Status"]).size().reset_index(name="Lookups")
        table(summary)
        table(status_df.sort_values(["Status", "Source"]))

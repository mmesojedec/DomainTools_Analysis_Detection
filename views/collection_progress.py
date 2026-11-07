"""
The lookup checklist of a collection run: drawn live in the Analyze status box, and kept (collapsed) on the Summary
once the run is done. One row per lookup of the run's query plan, as listed on the Start page cards: finished rows
first, in the order they finished, then the running ones, then what is still to come.
"""
import time

import pandas as pd
import streamlit as st

from core.use_cases import query_plan
from integrations.cache import age_text, cache_ttl
from integrations.progress import DONE, RUNNING, SKIPPED, WAITING, CollectionProgress

PROGRESS_KEY = "collection_progress"   # session state: the last run's checklist rows
STATE_HELP = ("Each lookup shows how much of it is done and how long it took. **skipped**: not needed, or nothing "
              "to look up.")


def plan_settings(settings):
    """The query-plan options of a run's LookupSettings."""
    return {"opt_pdns_provider": settings.pdns_provider, "opt_dnsdb_limit": settings.dnsdb_limit,
            "opt_txt": settings.txt_records > 0, "opt_txt_records": settings.txt_records or 1,
            "opt_caa": settings.caa_lookup, "opt_cname": settings.cname_lookup, "opt_pivot": settings.pivot_ips,
            "opt_pivot_max": settings.pivot_max_ips, "opt_ct": settings.include_ct, "opt_ct_max": settings.ct_max_hashes,
            "opt_vpndb": settings.vpndb_check, "opt_vpndb_only": settings.vpndb_only,
            "opt_vpndb_max_ips": settings.vpndb_max_ips, "opt_vpndb_details": settings.vpndb_details,
            "opt_vpndb_context": settings.vpndb_context, "opt_history_mode": "days" if settings.history_days else "all",
            "opt_history_days": settings.history_days or 1,
            "opt_pdns_incremental": settings.pdns_incremental}


def _counts(row):
    if not row.total:
        return ""
    parts = [f"{row.done:,}/{row.total:,} lookup{'s' if row.total != 1 else ''}"]
    if row.started > row.done:
        parts.append(f"{row.started - row.done} running")
    if row.cached:
        parts.append(cache_text(row))
    if row.failed:
        parts.append(f":red[{row.failed:,} failed]")
    if row.records:
        parts.append(f"{row.records:,} record{'s' if row.records != 1 else ''}")
    return " · ".join(parts)


def _expiry(seconds):
    return f"expires in {age_text(seconds)}" if seconds > 0 else "expired"


def cache_text(row, lifetime=None, now=None):
    """How many of the row's lookups came from the lookup cache, how old they are and when the first one expires."""
    lifetime = _lifetime(row, lifetime)
    now = time.time() if now is None else now
    fetched = [at for _, at in row.cache_hits]
    if not fetched:
        return f":violet[{row.cached:,} from cache]"
    oldest = min(fetched)
    if row.cached == 1:
        return f":violet[from cache]: fetched {age_text(now - oldest)} ago, {_expiry(oldest + lifetime - now)}"
    return (f":violet[{row.cached:,} from cache]: up to {age_text(now - oldest)} old, "
            f"first {_expiry(oldest + lifetime - now)}")


def cache_table(rows, lifetime=None, now=None):
    """One row per cached result of the run: which lookup, which target, when it was fetched and when it expires."""
    now = time.time() if now is None else now
    table = [{"Lookup": f"{row.source}: {row.lookup.split(' (')[0]}", "Target": target,
              "Fetched": pd.to_datetime(at, unit="s"), "Age": age_text(now - at),
              "Expires": _expiry(at + _lifetime(row, lifetime) - now).removeprefix("expires ")}
             for row in rows for target, at in row.cache_hits]
    return pd.DataFrame(table, columns=["Target", "Age", "Expires", "Lookup", "Fetched"])


def _lifetime(row, lifetime=None):
    """`lifetime`, else how long the row's source keeps cached results, else the cache lifetime."""
    if lifetime is not None:
        return lifetime
    return getattr(row, "cache_lifetime", None) or cache_ttl()


def clock(seconds):
    seconds = int(seconds)
    return f"{seconds // 60}:{seconds % 60:02d}" if seconds >= 60 else f"{seconds} s"


def ordered(rows):
    """Finished rows in the order they finished, then running rows in the order they started, then waiting rows."""
    finished = sorted((row for row in rows if row.state in (DONE, SKIPPED)), key=lambda row: row.ended or 0)
    running = sorted((row for row in rows if row.state == RUNNING), key=lambda row: row.began or 0)
    return finished + running + [row for row in rows if row.state == WAITING]


def _badge(row):
    if row.state == SKIPPED:
        return ":gray-badge[skipped]"
    if row.state == DONE:
        return ":green-badge[100%]"
    return f":blue-badge[{int(100 * row.done / row.total) if row.total else 0}%]"


def _name(row):
    return f"**{row.source}**: {row.lookup.split(' (')[0]}"   # "(only when ... hit its limit)" is in the note instead


def checklist_lines(rows, now=None):
    """One line per started or finished row, finished first; waiting rows are left to `up_next`."""
    now = time.monotonic() if now is None else now
    lines = []
    for row in ordered(rows):
        if row.state == WAITING:
            continue
        took = clock(row.took(now)) if row.began is not None else ""
        details = [text for text in (_counts(row), took, f"*{row.note}*" if row.note else "") if text]
        lines.append(f"{_badge(row)} {_name(row)}" + (f" — {' · '.join(details)}" if details else ""))
    return lines


def up_next(rows):
    waiting = [_name(row) for row in rows if row.state == WAITING]
    return "Up next: " + ", ".join(waiting) if waiting else ""


def completed_share(rows):
    if not rows:
        return 1.0
    share = sum(1.0 if row.state in (DONE, SKIPPED) else (row.done / row.total if row.total else 0) * 0.95
                for row in rows)
    return min(1.0, share / len(rows))


def summary(rows):
    run = sum(row.state == DONE for row in rows)
    skipped = sum(row.state == SKIPPED for row in rows)
    lookups = sum(row.done for row in rows)
    failed = sum(row.failed for row in rows)
    text = f"{run} lookup type(s) run ({lookups:,} lookups), {skipped} skipped"
    began = [row.began for row in rows if row.began is not None]
    ended = [row.ended for row in rows if row.ended is not None]
    took = f" in {clock(max(ended) - min(began))}" if began and ended else ""
    cached = sum(row.cached for row in rows)
    return text + (f", {cached:,} from cache" if cached else "") + (f", {failed:,} failed" if failed else "") + took


def live_progress(settings):
    """A CollectionProgress for `settings` that redraws a checklist and a progress bar here, in the calling thread."""
    bar, box, began = st.progress(0.0), st.empty(), time.monotonic()

    def render(tracker):
        rows, now = tracker.snapshot(), time.monotonic()
        share = completed_share(rows)
        bar.progress(share, text=f"{int(100 * share)}% complete · {clock(now - began)} elapsed")
        with box.container():
            st.caption(STATE_HELP)
            st.markdown("  \n".join(checklist_lines(rows, now)) or "Starting...")
            cached = sum(row.cached for row in rows)
            if cached:
                st.caption(f"{cached:,} lookup(s) answered from the lookup cache, with no API query. Each source keeps "
                           "cached results for its lifetime on Settings → Lookup cache.")
            if up_next(rows):
                st.caption(up_next(rows))
    tracker = CollectionProgress(query_plan(plan_settings(settings)), render)
    tracker.tick(force=True)   # the whole list, waiting, before the first lookup
    return tracker


def render_last_collection():
    """Summary page: the last run's checklist, collapsed."""
    rows = st.session_state.get(PROGRESS_KEY)
    if not rows:
        return
    with st.expander(f"Lookups of the last Analyze: {summary(rows)}", icon=":material/checklist:"):
        st.caption(STATE_HELP + " The Data sources page has every lookup's status.")
        st.markdown("  \n".join(checklist_lines(rows)))
        cached = cache_table(rows)
        if not cached.empty:
            st.markdown("**From the lookup cache** (each source's lifetime is on Settings → Lookup cache; *Re-run with "
                        "fresh lookups* on the Data sources page refreshes them)")
            st.dataframe(cached, hide_index=True, width="stretch", column_config={
                "Fetched": st.column_config.DatetimeColumn("Fetched (UTC)", format="YYYY-MM-DD HH:mm"),
                "Expires": st.column_config.Column("Expires", help="When the cached result leaves the cache; the "
                                                   "next lookup after that queries the API again"),
                "Lookup": st.column_config.Column("Lookup", width="medium")})

#!/usr/bin/env python3
"""DomainTools Analytics & Detection - Streamlit entry point (collection, filtering, and lens dispatch)."""
import dataclasses
import hashlib
import pickle
from contextlib import nullcontext

import pandas as pd
import streamlit as st

from core.account import unavailable_stages
from core.api_usage import queries_by_product
from core.cert_inputs import idn_conversions, parse_inputs, run_key_labels
from core.dataset import build_dataset
from core.helpers import md_escape, normalize_to_apex
from core.offline import format_size, incremental_base, load_offline_dataset, save_offline_dataset, update_offline_manifest
from core.persistence import (
    apply_suppressions,
    collect_run_artifacts,
    load_runs,
    load_suppressions,
    new_alert_mask,
    runs_before,
    save_snapshot,
    target_set_key,
)
from core.risk_profile import generate_digital_risk_profile
from core.run_history import alert_lifecycle, diff_artifacts, first_detected_mask, format_created, resolved_since
from core.threat_detection import detect_threat_flags
from core.triage import attach_status, load_triage
from core.window import resolve_window
from integrations.account import account_products
from integrations.cache import clear_all_caches, prune_cache, refreshing
from integrations.collector import collect_all, resolve_seeds, restore_cached_chases
from integrations.credentials import clear_credential_cache
from integrations.http import StatusLog
from integrations.progress import tracking
from views import idn_display, navigation
from views.account_view import render_account_page
from views.alert_tools import AlertView
from views.anonymizer_view import render_anonymizer_summary
from views.api_usage_view import skipped_products_note
from views.campaign_view import render_campaign_lens
from views.certsql_view import ORIGIN_KEY as CERTSQL_ORIGIN_KEY
from views.certsql_view import render_certsql_page
from views.cname_view import render_cname_lens
from views.collection_progress import PROGRESS_KEY, live_progress
from views.collection_progress import summary as collection_summary
from views.common import install_copy_fallback, render_window_banner
from views.docs_view import DOCS_PATH, doc_url, render_doc_page
from views.export_view import render_export_lens
from views.history_view import OFFLINE_SAVED_KEY, render_run_history
from views.home_view import render_home
from views.hostname_view import render_hostname_lens
from views.infra_view import render_infra_lens
from views.irisql_view import ORIGIN_KEY as IRISQL_ORIGIN_KEY
from views.irisql_view import render_irisql_page
from views.pivot_view import render_pivot_lens
from views.profile_view import render_profile
from views.query_view import render_query_lens
from views.raw_view import render_cache_panel, render_raw_lens, render_status_panel
from views.risk_view import render_risk_lens
from views.seed_view import render_seed_preview, render_seed_provenance, render_seed_query_step
from views.settings_view import brand_watchlist, render_settings
from views.sidebar import (
    DATA_MODE_KEY,
    HISTORY_TAB_KEY,
    HUNT_KEY,
    LAST_PAGE_KEY,
    LIVE_MODE,
    OFFLINE_ARRIVE_KEY,
    OFFLINE_MODE,
    OFFLINE_SELECT_KEY,
    OFFLINE_TAB,
    QUERY_MODES,
    LookupSettings,
    current_thresholds,
    init_state,
    is_analyst,
    render_analysis_window,
    render_apex_notice,
    render_global_filters,
    render_idn_notice,
    render_logo,
    render_lookup_controls,
    render_timezone_selector,
    show_pending_toast,
)
from views.sources_view import render_data_sources
from views.ssl_view import render_ssl_lens
from views.summary_view import render_summary
from views.triage_view import render_triage_lens
from views.vpndb_page import render_vpndb_page

st.set_page_config(layout="wide", page_title="DomainTools Analytics and Detection")
idn_display.install()   # "Show international domains in Unicode": decodes xn-- names where tables, text and charts are drawn
OFFLINE_SAVE_ERROR = "offline_save_error"   # why the last "Save offline copy" click failed
LAST_SETTINGS_KEY = "last_live_settings"   # LookupSettings of the last live run (Cached details re-runs it)
RERUN_KEY = "queued_rerun"                 # LookupSettings of a re-run asked for in Cached details
ANALYZING_KEY = "analysis_pending"         # a run was just loaded: its first build_context shows its steps
HUNT_PARENT_KEY = "hunt_parent"            # {"id", "via"} of a run started from a lead, saved with its snapshot


def _frame_digest(df):
    """Cache key for frames holding list/dict cells (which Streamlit's default DataFrame hasher cannot hash)."""
    try:
        row_hashes = pd.util.hash_pandas_object(df, index=True).to_numpy().tobytes()
        return hashlib.sha256(row_hashes + repr((tuple(df.columns), df.shape)).encode()).hexdigest()
    except TypeError:
        return hashlib.sha256(pickle.dumps(df, protocol=pickle.HIGHEST_PROTOCOL)).hexdigest()


CACHE_HASH_FUNCS = {pd.DataFrame: _frame_digest}

@st.cache_data(show_spinner=False, max_entries=16, hash_funcs=CACHE_HASH_FUNCS)
def run_threat_engine(events, thresholds, risk, ssl, enrichment, cert_events, ip_observations, brands, official_domains,
                      window_start=None, cname_chases=None, cname_rdata=None, anonymizers=None, exit_weeks=None,
                      neighbour_ranges=None, hosting_asns=None, tor_overview=None):
    return detect_threat_flags(
        events, thresholds, risk_df=risk, ssl_df=ssl, enrichment_data=enrichment, cert_events_df=cert_events,
        ip_observations=ip_observations, brands=brands, official_domains=official_domains,
        history_gaps=True, window_start=window_start, cname_chases=cname_chases, cname_rdata=cname_rdata,
        anonymizers=anonymizers, vpndb_context={"exit_weeks": exit_weeks, "neighbour_ranges": neighbour_ranges,
                                                "hosting_asns": hosting_asns, "tor_overview": tor_overview},
    )


def vpndb_frames(ds):
    """The VPNDB context frames the anonymizer rules read (see collector.collect_anonymizer_context)."""
    return {"exit_weeks": ds.exit_weeks, "neighbour_ranges": ds.neighbour_ranges, "hosting_asns": ds.hosting_asns,
            "tor_overview": ds.tor_overview}


def count_alerts_outside_window(ds, thresholds, windowed_alerts, suppressions):
    """(domain, threat type) detections that only exist on full history, i.e. hidden by the analysis window."""
    if ds.window.is_all_time:
        return 0, pd.DataFrame()
    full = run_threat_engine(ds.events_all_utc, thresholds, ds.risk, ds.ssl_all_utc, ds.enrichment, ds.cert_hostnames_all,
                             ds.ip_observations, *brand_watchlist(), cname_chases=ds.cname_chases, cname_rdata=ds.cname_rdata,
                             anonymizers=ds.anonymizers,
                             **vpndb_frames(ds))
    full_active, _ = apply_suppressions(full.alerts, suppressions)
    if full_active.empty:
        return 0, full_active
    in_window = set(zip(windowed_alerts["Domain"], windowed_alerts["Threat Type"])) if not windowed_alerts.empty else set()
    outside = full_active[[key not in in_window for key in zip(full_active["Domain"], full_active["Threat Type"])]]
    return len(outside), outside


@st.cache_data(show_spinner=False, max_entries=16, hash_funcs=CACHE_HASH_FUNCS)
def build_risk_profiles(domains, alerts, risk, ssl, pdns, enrichment):
    return generate_digital_risk_profile(domains, alerts, risk, ssl, pdns, enrichment)


def reuse_dataset(collected, selected_domains, selected_dh, selected_pdns, timezone, window, host_focus):
    """
    build_dataset() for these filters, rebuilt only when the loaded run or a filter changes: switching lenses and
    clicking widgets reuse the dataset instead of rebuilding it (and the hostname inventory) on every rerun.
    """
    key = (id(collected), tuple(selected_domains), tuple(selected_dh), tuple(selected_pdns), timezone, window.label,
           window.start, window.end, repr(sorted((host_focus or {}).items())))
    memo = st.session_state.get("dataset_memo")
    if memo and memo[0] == key and memo[1] is collected:
        return memo[2]
    ds = build_dataset(collected, selected_domains, selected_dh, selected_pdns, timezone, window, host_focus)
    st.session_state.dataset_memo = (key, collected, ds)   # holding `collected` keeps its id from being reused
    return ds


def run_key(collected):
    """Run-history key: the analyzed targets plus the certificate inputs they were derived from."""
    return target_set_key(run_key_labels(collected.targets, getattr(collected, "seed_inputs", None) or []))


def run_collection(settings):
    """
    Analyze clicked: plain domains / IPs are collected directly. Certificate inputs first go through two steps in the
    main area: review the recognized searches (no API calls), then pick the derived domains / IPs to analyze.
    """
    items = parse_inputs(settings.raw_input)
    st.session_state.idn_conversions = idn_conversions(settings.raw_input)
    plain, st.session_state.apex_conversions = normalize_to_apex([i.value for i in items if not i.is_certificate])
    seeds = [i for i in items if i.is_certificate]
    if not plain and not seeds:
        st.sidebar.warning("Enter at least one domain, IP address, or certificate.")
        return
    st.session_state[LAST_SETTINGS_KEY] = settings
    if settings.force_refresh:
        clear_all_caches()
        clear_credential_cache()
    else:
        prune_cache()
    st.session_state.pop("seed_preview", None)
    if not seeds:
        collect_targets(settings, plain)
        return
    st.session_state.pop("seed_query_editor", None)
    st.session_state.seed_queries = {"settings": settings, "plain": plain, "items": seeds}


def search_seeds(state, items):
    """Runs the reviewed certificate searches and moves on to choosing the derived targets."""
    with st.status(f"Searching certificates for {len(items)} input(s)...", expanded=False) as status:
        resolution = resolve_seeds(items, max_selected=state["settings"].seed_preselect)
        status.update(label=f"Certificate inputs resolved: {len(resolution.derived)} domain(s) / IP(s) found", state="complete")
    st.session_state.pop("seed_preview_editor", None)
    st.session_state.seed_preview = {"settings": state["settings"], "plain": state["plain"],
                                     "seeds": [i.label for i in resolution.items], "resolution": resolution}


def collect_targets(settings, targets, seed_inputs=(), resolution=None, selected=(), host_focus=None):
    """
    Collects all telemetry for `targets` and activates it; certificate-input provenance is attached when given.
    `host_focus` ({apex: [hostnames]}) is the initial hostname focus; those hostnames are looked up on their own only
    where an apex lookup stopped at its limit.
    """
    products = account_products() if not settings.vpndb_only else None   # at most one query an hour
    with st.status("Collecting telemetry...", expanded=True) as status:
        skipped = skipped_products_note(products)
        if skipped:
            st.warning(skipped + ". See the Account page.", icon=":material/block:")
        auth_box = st.empty()
        tracker = live_progress(settings)
        with refreshing() if settings.fresh else nullcontext(), tracking(tracker):   # fresh: refresh cached results
            collected = collect_all(
                targets,
                settings.pdns_provider,
                settings.dnsdb_limit,
                include_ct=settings.include_ct,
                ct_max_hashes=settings.ct_max_hashes,
                progress=lambda label: status.update(label=label, expanded=True),   # keeps the checklist in view
                on_auth_required=lambda target: auth_box.info(
                    f"Iris authentication required for {md_escape(target)}. Log in via the browser window that opened, "
                    "then **close the window manually once Iris has loaded.**"
                ),
                on_auth_done=auth_box.empty,
                pivot_ips=settings.pivot_ips,
                pivot_max_ips=settings.pivot_max_ips,
                txt_records=settings.txt_records,
                caa_lookup=settings.caa_lookup,
                cname_lookup=settings.cname_lookup,
                vpndb_check=settings.vpndb_check,
                vpndb_only=settings.vpndb_only,
                vpndb_max_ips=settings.vpndb_max_ips,
                vpndb_details=settings.vpndb_details,
                vpndb_context=settings.vpndb_context,
                seed_hits=resolution.hits if resolution is not None else None,
                host_focus=host_focus,
                history_days=settings.history_days,
                history_max=settings.history_max,
                pdns_base=incremental_base(target_set_key(run_key_labels(targets, seed_inputs)), "DNSDB Scout",
                                           settings.dnsdb_limit) if settings.pdns_incremental else None,
                unavailable=unavailable_stages(products),
            )
        tracker.close()
        st.session_state[PROGRESS_KEY] = tracker.snapshot()
        errors = sum(1 for row in collected.statuses if row["Status"] == "Error")
        done = f"Collection complete: {collection_summary(st.session_state[PROGRESS_KEY])}"
        status.update(
            label=f"{done} ({errors} source error(s) - see Data Source Status)" if errors else done,
            state="error" if errors and not collected.has_data else "complete",
            expanded=False,
        )
    if resolution is not None:
        collected.seed_inputs = list(seed_inputs)
        collected.seeds = resolution.seeds
        derived = resolution.derived
        collected.derived = derived[derived["Target"].isin(selected)].drop(columns="Analyze").reset_index(drop=True) \
            if not derived.empty else derived
        collected.statuses = list(resolution.statuses) + list(collected.statuses)
    for origin_key in (IRISQL_ORIGIN_KEY, CERTSQL_ORIGIN_KEY):   # targets picked from an IrisQL / CertsQL search
        origin = st.session_state.pop(origin_key, None)
        if origin:
            collected.statuses = [origin] + list(collected.statuses)
    created = pd.Timestamp.now(tz="UTC").isoformat()
    key = run_key(collected)
    st.session_state.offline_pending_id = None
    origin = {"mode": "live", "created": created}
    if settings.save_offline:
        try:
            manifest = save_offline_dataset(collected, settings.collection_summary(), run_key=key)
        except OSError as exc:
            st.sidebar.error(f"Offline copy could not be saved: {exc}")
        else:
            st.session_state.offline_pending_id = manifest["id"]
            origin["offline_id"] = manifest["id"]
            st.toast(f"Offline copy saved ({format_size(manifest['size_bytes'])}).")
    _activate_dataset(collected, key, created, origin, save_run=True)


def load_offline(settings):
    """Loads a saved offline dataset: no API calls; window, thresholds, and filters then re-analyze it."""
    try:
        collected, manifest = load_offline_dataset(settings.offline_id)
    except (OSError, ValueError) as exc:
        st.sidebar.error(f"Offline dataset could not be loaded: {exc}")
        return
    st.session_state.pop(PROGRESS_KEY, None)   # the checklist belongs to the last live run
    key = run_key(collected)
    origin = {"mode": "offline", "created": manifest.get("created"), "offline_id": manifest["id"], "manifest": manifest}
    _activate_dataset(collected, key, manifest.get("created"), origin, save_run=False)
    st.session_state.current_run_id = manifest.get("run_id")


def _activate_dataset(collected, key, created, origin, save_run):
    """
    Makes `collected` the active dataset. Lifecycle history = earlier runs (from any target list) covering these
    targets; 'Changes Since Last Run' compares against the previous run of this exact target list.
    CNAME chases still in the lookup cache are restored first (no API calls).
    """
    log = StatusLog()
    if restore_cached_chases(collected, log):
        collected.statuses = list(collected.statuses) + log.rows
    st.session_state.collected = collected
    st.session_state.data_origin = origin
    st.session_state.run_history_before = runs_before(created, domains=collected.targets)
    same_list = [r for r in load_runs(key) if pd.to_datetime(r.get("created"), utc=True, errors="coerce") < pd.to_datetime(created, utc=True)]
    st.session_state.previous_snapshot = same_list[-1] if same_list else None
    st.session_state.run_artifacts = collect_run_artifacts(collected)
    st.session_state.run_created = created
    st.session_state.snapshot_pending = key if save_run else None
    st.session_state.current_run_id = None
    st.session_state[ANALYZING_KEY] = True


def build_alert_view(threats):
    """Suppressions, run-to-run comparison, and alert lifecycle (first detected / runs seen) for the current run."""
    suppressions = load_suppressions()
    active, suppressed = apply_suppressions(threats.alerts, suppressions)
    previous = st.session_state.get("previous_snapshot")
    history = st.session_state.get("run_history_before", [])
    current_artifacts = st.session_state.get("run_artifacts", {})

    lifecycle = alert_lifecycle(history, active, st.session_state.get("run_created"))
    if not active.empty:
        active = active.copy()
        keys = list(zip(active["Domain"].astype(str), active["Threat Type"].astype(str)))
        first = lifecycle["First Detected"].to_dict()
        runs_seen = lifecycle["Runs Seen"].to_dict()
        active["First Detected"] = pd.to_datetime([first.get(k) for k in keys], utc=True).tz_localize(None)
        active["Runs Seen"] = [runs_seen.get(k, 1) for k in keys]
        active = attach_status(active, load_triage())
    return AlertView(
        active=active, suppressed=suppressed, suppressions=suppressions, previous_snapshot=previous,
        new_mask=new_alert_mask(active, previous),
        artifact_diff=diff_artifacts(previous.get("artifacts", {}), current_artifacts) if previous else pd.DataFrame(),
        first_detected_mask=first_detected_mask(active, lifecycle) if history else None,
        resolved=resolved_since(previous, active),
        history_runs=len(history),
    )


def save_pending_snapshot(view, profiles, host_focus=None):
    """Saves the freshly collected run once (first render after Analyze), including alerts, risk, and DIF."""
    pending = st.session_state.pop("snapshot_pending", None)
    if not pending:
        return
    collected = st.session_state.collected
    snapshot = save_snapshot(pending, collected.targets, st.session_state.get("run_artifacts", {}), view.active,
                             window_label=st.session_state.get("window_label"), profiles=profiles,
                             seeds=getattr(collected, "seed_inputs", None), host_focus=host_focus,
                             parent=st.session_state.pop(HUNT_PARENT_KEY, None),
                             queries=queries_by_product(collected.statuses))
    st.session_state.current_run_id = snapshot["id"]
    offline_id = st.session_state.pop("offline_pending_id", None)
    if offline_id:
        update_offline_manifest(offline_id, run_id=snapshot["id"])


def save_offline_now():
    """Button callback: saves the run on screen as an offline dataset (no API calls), linked to its saved run."""
    collected = st.session_state.get("collected")
    origin = st.session_state.get("data_origin") or {}
    if collected is None or origin.get("mode") != "live" or origin.get("offline_id"):
        return
    settings = st.session_state.get(LAST_SETTINGS_KEY)
    try:
        manifest = save_offline_dataset(collected, settings.collection_summary() if settings else {},
                                        run_key=run_key(collected))
    except OSError as exc:
        st.session_state[OFFLINE_SAVE_ERROR] = str(exc)
        return
    origin["offline_id"] = manifest["id"]
    if st.session_state.get("current_run_id"):   # already in Run History: link the dataset to that run
        update_offline_manifest(manifest["id"], run_id=st.session_state.current_run_id)
    else:
        st.session_state.offline_pending_id = manifest["id"]
    st.toast(f"Offline copy saved ({format_size(manifest['size_bytes'])}): Data source → Offline dataset, or Run "
             "History → Offline datasets.")


def render_origin_banner():
    origin = st.session_state.get("data_origin") or {}
    if origin.get("mode") == "offline":
        manifest = origin.get("manifest", {})
        settings = manifest.get("settings", {})
        st.info(f"**Offline dataset** collected {format_created(manifest.get('created'), 'UTC')} UTC "
                f"({manifest.get('provider')}" + (f", DNSDB limit {int(settings['dnsdb_limit']):,}" if settings.get("dnsdb_limit") else "")
                + ") — no API calls are made. Change the analysis window, thresholds, or filters to re-analyze it.")


def rerun_settings(collected, fresh):
    """
    LookupSettings to analyze `collected`'s targets again: an offline dataset's recorded collection settings, else
    the last live run's; None when neither is known.
    """
    origin = st.session_state.get("data_origin") or {}
    recorded = origin.get("manifest", {}).get("settings") or {} if origin.get("mode") == "offline" else {}
    base = st.session_state.get(LAST_SETTINGS_KEY)
    if recorded:
        names = {f.name for f in dataclasses.fields(LookupSettings)}
        try:
            base = LookupSettings(raw_input="", force_refresh=False, run=False,
                                  **{k: v for k, v in recorded.items() if k in names and k not in ("raw_input", "run")})
        except TypeError:   # an older dataset that did not record every setting
            pass
    if base is None:
        return None
    return dataclasses.replace(base, raw_input="\n".join(collected.targets), run=True, mode="live", force_refresh=False,
                               fresh=fresh, save_offline=False)


def _render_cache_details(collected, timezone):
    """Cached details panel; a re-run asked for there is queued and picked up at the top of the next app run."""
    can_rerun = rerun_settings(collected, False) is not None
    choice = render_cache_panel(collected.statuses, timezone, st.session_state.get("run_created"), can_rerun,
                                expanded=True)
    if choice:
        st.session_state[RERUN_KEY] = rerun_settings(collected, choice == "fresh")
        st.rerun()


def render_docs_link():
    st.sidebar.caption(f"See the **[Documentation]({doc_url()})**.")


@dataclasses.dataclass
class Context:
    """What every page of this run works from (empty before an analysis is loaded)."""
    timezone: str = "UTC"
    window: object = None
    thresholds: dict = None
    collected: object = None
    ds: object = None
    threats: object = None
    view: object = None
    profiles: pd.DataFrame = None
    outside: tuple = (0, None)


CTX = Context()


def build_context(collected, timezone, window, thresholds, step=lambda label: None):
    """
    Dataset, detections, alert view and risk profiles of the loaded run, for the selected filters and window.
    `step(label)` is told what runs next.
    """
    selected_domains, selected_dh, selected_pdns, host_focus = render_global_filters(collected)
    step("Building the timelines, passive DNS and certificate tables...")
    ds = reuse_dataset(collected, selected_domains, selected_dh, selected_pdns, timezone, window, host_focus)
    step("Running the detection rules...")
    threats = run_threat_engine(ds.events_utc, thresholds, ds.risk, ds.ssl_utc, ds.enrichment, ds.cert_hostnames,
                                ds.ip_observations, *brand_watchlist(), window.start,
                                cname_chases=ds.cname_chases, cname_rdata=ds.cname_rdata, anonymizers=ds.anonymizers,
                             **vpndb_frames(ds))
    step("Comparing with earlier runs and building the risk profiles...")
    view = build_alert_view(threats)
    profiles = build_risk_profiles(ds.selected_domains, view.active.drop(columns=["Evidence"], errors="ignore"), ds.risk,
                                   ds.ssl, ds.pdns, ds.enrichment)
    save_pending_snapshot(view, profiles, ds.host_focus)
    outside = count_alerts_outside_window(ds, thresholds, view.active, view.suppressions)
    return Context(timezone, window, thresholds, collected, ds, threats, view, profiles, outside)


def _pending_step(key, page):
    """
    The certificate-input step `key` (seed_queries / seed_preview) waiting in the main area, or None. It belongs to
    the page it opened on: opening another page from the menu cancels it (as its Cancel button does), so the menu is
    never stuck behind it.
    """
    state = st.session_state.get(key)
    if not state:
        return None
    opened_on = state.setdefault("page", page)
    if opened_on == page:
        return state
    st.session_state.pop(key, None)
    st.toast("Certificate search cancelled: you opened another page. Click Analyze again to start it over.",
             icon=":material/cancel:")
    return None


def render_status_chip():
    """One line on top of every data page: where the data comes from and how its lookups went."""
    collected = CTX.collected
    origin = st.session_state.get("data_origin") or {}
    where = f"Offline dataset {format_created(origin.get('manifest', {}).get('created'), 'UTC')} UTC" \
        if origin.get("mode") == "offline" else "Live run"
    statuses = pd.DataFrame(collected.statuses) if collected.statuses else pd.DataFrame(columns=["Status", "Detail"])
    cached = int(statuses["Detail"].astype(str).str.contains("From cache").sum()) if "Detail" in statuses else 0
    errors, partial = int((statuses["Status"] == "Error").sum()), int((statuses["Status"] == "Partial").sum())
    c_text, c_save, c_link = st.columns([4.2, 1.8, 1], vertical_alignment="center")
    if origin.get("mode") == "live" and not origin.get("offline_id"):
        c_save.button("Save offline copy", key="save_offline_now", on_click=save_offline_now, type="tertiary",
                      icon=":material/save:",
                      help="Saves everything this run collected, with the lookups made since (CNAME chases ...), to "
                           "dt_offline/ (local, git-ignored), so it can be re-analyzed later without API calls.")
    elif origin.get("mode") == "live":
        c_save.caption(":material/check: Offline copy saved")
    if st.session_state.get(OFFLINE_SAVE_ERROR):
        st.error(f"Offline copy could not be saved: {st.session_state.pop(OFFLINE_SAVE_ERROR)}")
    c_text.caption(f"{where} · {', '.join(collected.targets[:4])}{' …' if len(collected.targets) > 4 else ''} · "
                   f"{CTX.window.label} · {len(statuses):,} lookups, {cached:,} from cache"
                   + (f" · :red[{errors} error(s)]" if errors else "") + (f" · :orange[{partial} partial]" if partial else ""))
    navigation.link("sources", label="Data sources", container=c_link)
    if CTX.ds.host_focus:
        st.info("**Hostname focus:** " + md_escape("; ".join(f"{apex}: {', '.join(hosts)}"
                                                           for apex, hosts in CTX.ds.host_focus.items()))
                + ". Passive DNS, certificates and certificate events of these domains are limited to these hostnames; "
                  "clear *Focus on hostnames* in the sidebar to see everything.")


def _window_banner():
    render_window_banner(CTX.ds, *CTX.outside)


def data_page(render):
    """A page that needs a loaded analysis: the status line, then `render`; a pointer to Start before that."""
    def page():
        if CTX.ds is None:
            collected = st.session_state.get("collected")
            if collected is not None and not collected.has_data:
                render_status_panel(collected.statuses, expanded=True)
                st.warning("Analysis completed, but no telemetry or historical data was returned for the provided targets.")
            else:
                st.info("No analysis loaded yet. Enter targets in the sidebar and click **Analyze**, or load an offline "
                        "dataset.")
            navigation.link("home", label="Pick a use case on the Start page")
            return
        render_status_chip()
        render()
    return page


def page_home():
    render_home(CTX.ds is not None, lambda: render_run_history(None, CTX.timezone))


def page_alerts():
    _window_banner()
    render_risk_lens(CTX.ds, CTX.profiles, CTX.threats, CTX.thresholds, CTX.view)


def page_dns():
    render_anonymizer_summary(CTX.ds)
    render_infra_lens(CTX.ds)
    render_campaign_lens(CTX.ds, CTX.threats, CTX.view.active)


def page_sources():
    st.header("Data sources", help="How every lookup of this run went, and how much of it came from the lookup cache.")
    render_origin_banner()
    render_apex_notice(st.session_state.get("apex_conversions"))
    render_idn_notice(st.session_state.get("idn_conversions"))
    live = (st.session_state.get("data_origin") or {}).get("mode") == "live"   # timings belong to the last Analyze
    render_data_sources(CTX.collected.statuses, st.session_state.get(PROGRESS_KEY) if live else None)
    _render_cache_details(CTX.collected, CTX.timezone)
    render_seed_provenance(CTX.collected)


def page_save():
    """Top menu *Save offline copy*: saves the run on screen (no API calls), then opens Run History's Offline Datasets
    with it selected so it can be named."""
    collected = st.session_state.get("collected")
    origin = st.session_state.get("data_origin") or {}
    st.header("Save offline copy")
    if collected is None:
        st.info("Nothing to save yet: analyze some targets first. Saved datasets are listed under Run History → "
                "Offline Datasets.")
        navigation.link("history", label="Open Run History")
        return
    if origin.get("mode") == "live" and not origin.get("offline_id"):
        save_offline_now()
    error = st.session_state.pop(OFFLINE_SAVE_ERROR, None)
    if error:
        st.error(f"The offline copy could not be saved: {error}")
        return
    dataset_id = origin.get("offline_id") or (origin.get("manifest") or {}).get("id")
    navigation.open_tab("history", HISTORY_TAB_KEY, OFFLINE_TAB, **({OFFLINE_SELECT_KEY: dataset_id,
                                                                      OFFLINE_SAVED_KEY: dataset_id} if dataset_id
                                                                     else {}))


def page_history():
    collected = st.session_state.get("collected")
    render_run_history(run_key(collected) if collected is not None else None, CTX.timezone,
                       st.session_state.get("current_run_id"))


PAGE_FUNCTIONS = {
    "home": page_home,
    "irisql": render_irisql_page,
    "certsql": render_certsql_page,
    "summary": data_page(lambda: render_summary(CTX, _window_banner)),
    "profile": data_page(lambda: render_profile(CTX)),
    "alerts": data_page(page_alerts),
    "dns": data_page(page_dns),
    "vpndb": data_page(lambda: render_vpndb_page(CTX.ds)),
    "cname": data_page(lambda: render_cname_lens(CTX.ds, CTX.collected)),
    "certs": data_page(lambda: render_ssl_lens(CTX.ds, CTX.threats, CTX.thresholds)),
    "pivots": data_page(lambda: render_pivot_lens(CTX.ds)),
    "hostnames": data_page(lambda: render_hostname_lens(CTX.ds)),
    "triage": data_page(lambda: render_triage_lens(CTX.ds)),
    "sources": data_page(page_sources),
    "raw": data_page(lambda: render_raw_lens(CTX.ds)),
    "queries": data_page(lambda: render_query_lens(CTX.collected, st.session_state.get("run_created"))),
    "export": data_page(lambda: render_export_lens(CTX.ds, CTX.collected, CTX.view.active.reset_index(drop=True),
                                                   CTX.profiles, st.session_state.get("run_created"))),
    "history": page_history,
    "save": page_save,
    "settings": render_settings,
    "account": render_account_page,
    "docs": lambda: render_doc_page(st.query_params.get("doc"), st.query_params.get("topic", "")),
}


def main():
    global CTX
    init_state()
    nav = navigation.build(PAGE_FUNCTIONS, is_analyst())
    render_logo()
    install_copy_fallback()
    show_pending_toast()
    if nav.url_path == DOCS_PATH:   # the documentation draws its own sidebar (topic tree and search)
        with idn_display.paused():
            nav.run()
        return
    render_docs_link()
    query_pages = {page: mode for mode, page in QUERY_MODES.items()}   # irisql -> IrisQL, certsql -> CertsQL
    last_page = st.session_state.get(LAST_PAGE_KEY)
    if st.session_state.pop(OFFLINE_ARRIVE_KEY, False):   # sent to Run History by Data source → Offline dataset
        st.session_state[DATA_MODE_KEY] = OFFLINE_MODE
    elif nav.url_path in query_pages and nav.url_path != last_page:   # Data source follows the query pages:
        st.session_state[DATA_MODE_KEY] = query_pages[nav.url_path]      # selected on one, back to live off it
    elif last_page in query_pages and nav.url_path not in query_pages \
            and st.session_state.get(DATA_MODE_KEY) == query_pages[last_page]:
        st.session_state[DATA_MODE_KEY] = LIVE_MODE
    elif st.session_state.get(LAST_PAGE_KEY) == "history" and nav.url_path != "history" \
            and st.session_state.get(DATA_MODE_KEY) == OFFLINE_MODE:   # Offline dataset lives on Run History
        st.session_state[DATA_MODE_KEY] = LIVE_MODE
    st.session_state[LAST_PAGE_KEY] = nav.url_path

    settings = render_lookup_controls(navigation.page("settings"))
    settings = st.session_state.pop(RERUN_KEY, None) or settings   # a re-run asked for on the Data sources page
    hunt = st.session_state.pop(HUNT_KEY, None)   # "Analyze as a new run" on a lead: targets are in the box already
    if hunt and not settings.run and settings.mode == "live" and settings.raw_input.strip():
        settings = dataclasses.replace(settings, run=True)
        st.session_state[HUNT_PARENT_KEY] = hunt
    elif settings.run:
        st.session_state.pop(HUNT_PARENT_KEY, None)
    st.sidebar.divider()
    window_choice = render_analysis_window()
    timezone = render_timezone_selector()
    window = resolve_window(window_choice.preset, window_choice.custom_range, timezone)
    st.session_state.window_label = window.label
    thresholds = current_thresholds()
    CTX = Context(timezone, window, thresholds)

    before = st.session_state.get("collected")
    if settings.run:
        if settings.mode == "offline":
            st.session_state.apex_conversions = []
            st.session_state.idn_conversions = []
            load_offline(settings)
        else:
            run_collection(settings)
        if st.session_state.get("collected") is not before and not st.session_state.get("seed_queries"):
            navigation.go("summary")   # a new analysis opens on its Summary
    render_apex_notice(st.session_state.get("apex_conversions"))
    render_idn_notice(st.session_state.get("idn_conversions"))

    queries = _pending_step("seed_queries", nav.url_path)
    if queries:
        action, items = render_seed_query_step(queries)
        if action is None:
            return
        st.session_state.pop("seed_queries", None)
        if action == "search":
            search_seeds(queries, items)
        st.rerun()

    preview = _pending_step("seed_preview", nav.url_path)
    if preview:
        action, choice = render_seed_preview(preview)
        if action is None:
            return
        st.session_state.pop("seed_preview", None)
        if action == "analyze":
            selected, host_focus = choice
            targets = list(dict.fromkeys(preview["plain"] + selected))
            collect_targets(preview["settings"], targets, preview["seeds"], preview["resolution"], selected, host_focus)
            navigation.go("summary")
        st.rerun()

    collected = st.session_state.get("collected")
    if collected is not None and collected.has_data:
        if st.session_state.pop(ANALYZING_KEY, False):
            box = st.empty()
            with box.status("Analyzing the collected data...", expanded=True) as status:
                CTX = build_context(collected, timezone, window, thresholds, step=st.write)
                status.update(label="Analysis complete", state="complete")
            box.empty()
        else:
            CTX = build_context(collected, timezone, window, thresholds)
    nav.run()


main()

"""3-tier Sankey diagram (Hostname ➔ Cert SHA256 ➔ IP) and step navigation inside a Streamlit fragment."""
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import pytz
import streamlit as st

from config import DT_ORANGE


@st.fragment
def render_sankey_fragment(valid_df, target_tz):
    """Renders step navigation, cert hash filtering, and Sankey flow inside an isolated fragment."""
    tz_obj = pytz.timezone(target_tz)
    valid_df = valid_df.copy()

    valid_df["Date_TZ"] = valid_df["Date_UTC"].dt.tz_convert(tz_obj)
    valid_df["Formatted_Time"] = valid_df["Date_TZ"].apply(lambda d: d.strftime('%Y-%m-%d %H:%M:%S %Z'))
    valid_df["Date_Display"] = valid_df["Date_TZ"].dt.tz_localize(None)

    valid_df["Cert_Node"] = valid_df["Cert_SHA256"].apply(lambda x: f"Cert: {x[:12]}..." if len(x) > 12 else f"Cert: {x}")
    valid_df["IP_Node"] = valid_df["IP"].apply(lambda x: f"IP: {x}")

    # --- 1. CERT HASH MULTISELECT (ALL CERT HASHES SELECTED BY DEFAULT) ---
    all_certs = list(valid_df["Cert_Node"].unique())

    # Automatically re-anchor to ALL certs whenever available certs change or on first load
    if ("sankey_all_certs_signature" not in st.session_state or
        st.session_state.sankey_all_certs_signature != sorted(all_certs) or
        "sankey_cert_filter_multiselect" not in st.session_state or
        not st.session_state.sankey_cert_filter_multiselect):
        st.session_state.sankey_cert_filter_multiselect = all_certs
        st.session_state.sankey_all_certs_signature = sorted(all_certs)

    col_cf1, col_cf2 = st.columns([4.2, 0.8])
    with col_cf1:
        selected_certs = st.multiselect(
            "Filter Flow Window by Certificate Hash:",
            options=all_certs,
            key="sankey_cert_filter_multiselect"
        )
    with col_cf2:
        st.write("")
        st.write("")
        if st.button("Select All", key="btn_select_all_certs", help="Reset certificate filter to select all hashes"):
            st.session_state.sankey_cert_filter_multiselect = all_certs
            st.rerun(scope="fragment")

    if not selected_certs:
        st.warning("No Certificate Hashes selected. Please select at least one Certificate Hash above.")
        return

    filtered_df = valid_df[valid_df["Cert_Node"].isin(selected_certs)].copy()
    if filtered_df.empty:
        st.warning("No telemetry available for the selected Certificate Hashes.")
        return

    unique_hostnames = list(filtered_df["Hostname"].unique())
    unique_certs = list(filtered_df["Cert_Node"].unique())
    unique_ips = list(filtered_df["IP_Node"].unique())

    host_palette = ["#3B82F6", "#06B6D4", "#6366F1", "#10B981", "#8B5CF6", "#0284C7"]
    cert_palette = ["#F76509", "#EF4444", "#EC4899", "#D97706", "#F59E0B", "#B91C1C"]
    ip_palette   = ["#91D117", "#10B981", "#84CC16", "#059669", "#15803D", "#047857"]

    host_color_map = {h: host_palette[i % len(host_palette)] for i, h in enumerate(unique_hostnames)}
    cert_color_map = {c: cert_palette[i % len(cert_palette)] for i, c in enumerate(unique_certs)}
    ip_color_map   = {ip: ip_palette[i % len(ip_palette)] for i, ip in enumerate(unique_ips)}

    # Ensure chronological order and strictly unique display options
    time_options_df = filtered_df.drop_duplicates(subset=["Formatted_Time"]).sort_values("Date_UTC").reset_index(drop=True)
    formatted_options = time_options_df["Formatted_Time"].tolist()
    total_events = len(formatted_options)

    # Manage version counter for key-bumping so programmatic updates sync widget cleanly
    if "sankey_version" not in st.session_state:
        st.session_state.sankey_version = 0

    # Initialize or re-align range state if timezone or filter changed
    if ("sankey_range" not in st.session_state or
        not isinstance(st.session_state.sankey_range, (list, tuple)) or
        len(st.session_state.sankey_range) != 2 or
        st.session_state.sankey_range[0] not in formatted_options or
        st.session_state.sankey_range[1] not in formatted_options):
        st.session_state.sankey_range = (formatted_options[0], formatted_options[-1])
        st.session_state.sankey_version += 1

    _, sel_end_fmt = st.session_state.sankey_range
    curr_end_idx = formatted_options.index(sel_end_fmt)

    # --- 2. OBSERVED INFRASTRUCTURE EVENT SCATTER PLOT ---
    st.markdown("##### Observed Infrastructure Event Markers")
    current_end_row = filtered_df[filtered_df["Formatted_Time"] == sel_end_fmt]
    current_selection_dt_display = current_end_row["Date_Display"].iloc[-1] if not current_end_row.empty else filtered_df["Date_Display"].iloc[-1]

    fig_dots = px.scatter(
        filtered_df,
        x="Date_Display",
        y="Hostname",
        color="Cert_Node",
        color_discrete_map=cert_color_map,
        hover_data={"Date_Display": False, "Formatted_Time": True, "IP": True, "Cert_SHA256": True}
    )
    fig_dots.update_traces(marker=dict(size=13, opacity=0.9, line=dict(width=1, color="white")))

    selected_end_str = current_selection_dt_display.strftime('%Y-%m-%d %H:%M:%S')
    fig_dots.add_vline(x=selected_end_str, line_width=2, line_dash="dash", line_color=DT_ORANGE)
    fig_dots.add_annotation(
        x=selected_end_str, y=1, yref="paper",
        text=f"Current Selection ({sel_end_fmt})",
        showarrow=False, font=dict(color=DT_ORANGE, size=11), xanchor="left", yanchor="top"
    )

    fig_dots.update_layout(
        template="plotly_dark",
        height=220 + max(0, (len(unique_hostnames) - 2) * 25),
        margin=dict(t=30, b=25, l=10, r=10),
        xaxis_title=f"Observation Timestamp ({target_tz})",
        yaxis_title="Hostname",
        legend=dict(title_text="Cert Hash", orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_dots, width="stretch")

    # --- 3. PLAYBACK MODE CONTROLS (INSTANT SEAMLESS SWITCHING) ---
    col_m1, col_m2 = st.columns([1.8, 2.2])
    with col_m1:
        playback_mode = st.radio(
            "Playback Mode:",
            [
                "Cumulative (Add/Remove Infrastructure)",
                "Single Step (Isolate Event)"
            ],
            index=0,
            horizontal=True,
            key="sankey_playback_mode_radio",
            help="Cumulative keeps the start of the timeline fixed and adds infrastructure as you step forward. Single Step isolates only the exact nodes observed at that single timestamp snapshot."
        )

    # Detect immediate mode switch and instantly re-anchor the range
    if "sankey_last_mode" not in st.session_state:
        st.session_state.sankey_last_mode = playback_mode

    if st.session_state.sankey_last_mode != playback_mode:
        st.session_state.sankey_last_mode = playback_mode
        if playback_mode.startswith("Single"):
            # Instant collapse: snap both boundaries to current end event
            st.session_state.sankey_range = (formatted_options[curr_end_idx], formatted_options[curr_end_idx])
        else:
            # Instant expansion: expand from event 0 up to current end event
            st.session_state.sankey_range = (formatted_options[0], formatted_options[curr_end_idx])
        st.session_state.sankey_version += 1
        st.rerun(scope="fragment")

    with col_m2:
        st.markdown(f"**Step Position:** Event **{curr_end_idx + 1}** of **{total_events}** (`{formatted_options[curr_end_idx]}`)")

    # --- 4. STEP NAVIGATION BUTTONS ---
    prev_disabled = (curr_end_idx <= 0)
    next_disabled = (curr_end_idx >= total_events - 1)

    col_b1, col_b2, col_b3 = st.columns([1, 1, 1])

    with col_b1:
        if st.button("Previous Event", disabled=prev_disabled, key="btn_sankey_prev"):
            if playback_mode.startswith("Single"):
                new_idx = max(0, curr_end_idx - 1)
                st.session_state.sankey_range = (formatted_options[new_idx], formatted_options[new_idx])
            else:
                new_end = max(0, curr_end_idx - 1)
                st.session_state.sankey_range = (formatted_options[0], formatted_options[new_end])
            st.session_state.sankey_version += 1
            st.rerun(scope="fragment")

    with col_b2:
        if st.button("Next Event", disabled=next_disabled, key="btn_sankey_next"):
            if playback_mode.startswith("Single"):
                new_idx = min(total_events - 1, curr_end_idx + 1)
                st.session_state.sankey_range = (formatted_options[new_idx], formatted_options[new_idx])
            else:
                new_end = min(total_events - 1, curr_end_idx + 1)
                # In Cumulative mode, anchor at event 0 so all previous infrastructure remains included
                st.session_state.sankey_range = (formatted_options[0], formatted_options[new_end])
            st.session_state.sankey_version += 1
            st.rerun(scope="fragment")

    with col_b3:
        if st.button("Reset Range", key="btn_sankey_reset"):
            st.session_state.sankey_range = (formatted_options[0], formatted_options[-1])
            st.session_state.sankey_version += 1
            st.rerun(scope="fragment")

    # --- 5. SNAP SLIDER WIDGET ---
    if total_events > 1:
        slider_widget_key = f"sankey_slider_v_{st.session_state.sankey_version}"
        selected_slider_range = st.select_slider(
            f"Snap Slider to Filter Infrastructure Flow Window ({target_tz}):",
            options=formatted_options,
            value=st.session_state.sankey_range,
            key=slider_widget_key
        )
        if selected_slider_range != st.session_state.sankey_range:
            st.session_state.sankey_range = selected_slider_range
            st.rerun(scope="fragment")

    # Filter Sankey flow strictly by the active window bounds
    sel_start, sel_end = st.session_state.sankey_range
    start_utc = time_options_df[time_options_df["Formatted_Time"] == sel_start]["Date_UTC"].min()
    end_utc = time_options_df[time_options_df["Formatted_Time"] == sel_end]["Date_UTC"].max()

    sankey_df = filtered_df[(filtered_df["Date_UTC"] >= start_utc) & (filtered_df["Date_UTC"] <= end_utc)]

    if sankey_df.empty:
        st.warning("No telemetry events found within the selected time window.")
        return

    unique_hostnames_sankey = list(sankey_df["Hostname"].unique())
    unique_certs_sankey = list(sankey_df["Cert_Node"].unique())
    unique_ips_sankey = list(sankey_df["IP_Node"].unique())

    all_nodes = unique_hostnames_sankey + unique_certs_sankey + unique_ips_sankey
    node_index_map = {node: idx for idx, node in enumerate(all_nodes)}

    sources, targets, values, customdata = [], [], [], []

    tier1 = sankey_df.groupby(["Hostname", "Cert_Node"]).agg(
        count=("IP", "count"),
        first_seen=("Formatted_Time", "min"),
        last_seen=("Formatted_Time", "max")
    ).reset_index()

    for _, row in tier1.iterrows():
        sources.append(node_index_map[row["Hostname"]])
        targets.append(node_index_map[row["Cert_Node"]])
        values.append(row["count"])
        customdata.append([row["first_seen"], row["last_seen"]])

    tier2 = sankey_df.groupby(["Cert_Node", "IP_Node"]).agg(
        count=("Hostname", "count"),
        first_seen=("Formatted_Time", "min"),
        last_seen=("Formatted_Time", "max")
    ).reset_index()

    for _, row in tier2.iterrows():
        sources.append(node_index_map[row["Cert_Node"]])
        targets.append(node_index_map[row["IP_Node"]])
        values.append(row["count"])
        customdata.append([row["first_seen"], row["last_seen"]])

    node_colors = (
        [host_color_map[h] for h in unique_hostnames_sankey] +
        [cert_color_map[c] for c in unique_certs_sankey] +
        [ip_color_map[ip] for ip in unique_ips_sankey]
    )

    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15, thickness=20, line=dict(color="black", width=0.5),
            label=all_nodes, color=node_colors
        ),
        link=dict(
            source=sources, target=targets, value=values, customdata=customdata,
            hovertemplate="<b>%{source.label} ➔ %{target.label}</b><br>" +
                          "Observations: %{value}<br>" +
                          "First Seen: %{customdata[0]}<br>" +
                          "Last Seen: %{customdata[1]}<extra></extra>",
            color="rgba(116, 133, 144, 0.35)"
        )
    )])

    fig.update_layout(
        title_text="Active Infrastructure Flow — (Hostname ➔ Cert Hash ➔ IP Address)",
        font_size=11, template="plotly_dark",
        height=max(450, len(unique_hostnames_sankey) * 20 + 200),
        margin=dict(t=40, l=10, r=10, b=10)
    )

    st.plotly_chart(fig, width="stretch")

def render_hostname_sankey_flow(df_hostnames, target_tz="UTC"):
    """Wrapper function to prepare datetime-aligned DataFrame and render Sankey fragment."""
    if df_hostnames.empty:
        st.info("No Hostname Event telemetry available to generate the mapping flow.")
        return

    missing = {"", "N/A", "None", "nan"}
    hostnames = df_hostnames.copy()
    for col in ("Hostname", "IP", "Cert_SHA256"):
        hostnames[col] = hostnames[col].fillna("").astype(str).str.strip()
    valid_df = hostnames[
        ~hostnames["Hostname"].isin(missing) &
        ~hostnames["IP"].isin(missing) &
        ~hostnames["Cert_SHA256"].isin(missing)
    ].copy()

    if valid_df.empty:
        st.info("Insufficient mapping telemetry (missing IP or Cert SHA256) to plot Sankey diagram.")
        return

    if "Timestamp" in valid_df.columns:
        valid_df["Date_UTC"] = pd.to_datetime(valid_df["Timestamp"], errors="coerce", utc=True)
    elif "First Seen" in valid_df.columns:
        valid_df["Date_UTC"] = pd.to_datetime(valid_df["First Seen"], errors="coerce", utc=True)
    else:
        valid_df["Date_UTC"] = pd.NaT

    valid_df = valid_df.dropna(subset=["Date_UTC"]).sort_values("Date_UTC").reset_index(drop=True)

    if valid_df.empty:
        st.info("No valid timestamped telemetry available for timezone conversion.")
        return

    render_sankey_fragment(valid_df, target_tz)

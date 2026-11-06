"""Analysis window: restricts dashboards, detections, IOCs, and DIF scoring to recently active records."""
from dataclasses import dataclass

import pandas as pd

ALL_TIME = "All time"
CUSTOM_RANGE = "Custom range"
WINDOW_PRESETS = {
    "Last 7 days": 7,
    "Last 14 days": 14,
    "Last 30 days": 30,
    "Last 60 days": 60,
    "Last 90 days": 90,
    "Last 180 days": 180,
    "Last 365 days": 365,
    ALL_TIME: None,
    CUSTOM_RANGE: None,
}
DEFAULT_WINDOW = "Last 30 days"


def _utc_now():
    return pd.Timestamp.now(tz="UTC").tz_localize(None)


@dataclass(frozen=True)
class AnalysisWindow:
    """[start, end] in tz-naive UTC. start=None means unbounded (All time)."""
    label: str = ALL_TIME
    start: pd.Timestamp = None
    end: pd.Timestamp = None

    @property
    def is_all_time(self):
        return self.start is None and self.end is None

    def describe(self, timezone="UTC"):
        if self.is_all_time:
            return "All time (full history)"

        def fmt(ts):
            return pd.Timestamp(ts).tz_localize("UTC").tz_convert(timezone).strftime("%Y-%m-%d %H:%M")
        start = fmt(self.start) if self.start is not None else "beginning"
        end = fmt(self.end) if self.end is not None else "now"
        return f"{self.label}: {start} → {end} ({timezone})"

    def active_mask(self, first_seen, last_seen=None):
        """Records active during the window: (last seen, or first seen) >= start and first seen <= end."""
        first = pd.to_datetime(first_seen, errors="coerce")
        index = first.index if hasattr(first, "index") else None
        if self.is_all_time:
            return pd.Series(True, index=index)
        last = pd.to_datetime(last_seen, errors="coerce").fillna(first) if last_seen is not None else first
        mask = pd.Series(True, index=index)
        if self.start is not None:
            mask &= last >= self.start
        if self.end is not None:
            mask &= first.isna() | (first <= self.end)
        return mask.fillna(False)

    def contains(self, timestamp):
        if self.is_all_time:
            return True
        ts = pd.to_datetime(timestamp, errors="coerce")
        if pd.isna(ts):
            return False
        return (self.start is None or ts >= self.start) and (self.end is None or ts <= self.end)


def preset_window(label, now=None):
    """Rolling window ending now. The start is floored to the hour so reruns within the hour reuse cached results."""
    days = WINDOW_PRESETS.get(label)
    if days is None:
        return AnalysisWindow(label=ALL_TIME)
    now = now or _utc_now()
    return AnalysisWindow(label=label, start=(now - pd.Timedelta(days=days)).floor("h"), end=None)


def resolve_window(preset, custom_range=None, timezone="UTC"):
    if preset == CUSTOM_RANGE:
        return custom_window(custom_range[0], custom_range[1], timezone) if custom_range else AnalysisWindow(label=ALL_TIME)
    return preset_window(preset)


def custom_window(start_date, end_date, timezone="UTC"):
    """Calendar dates in the display timezone -> UTC window covering whole days [start 00:00, end+1 00:00)."""
    start = pd.Timestamp(start_date).tz_localize(timezone).tz_convert("UTC").tz_localize(None)
    end = (pd.Timestamp(end_date) + pd.Timedelta(days=1)).tz_localize(timezone).tz_convert("UTC").tz_localize(None) - pd.Timedelta(seconds=1)
    return AnalysisWindow(label=f"{pd.Timestamp(start_date):%Y-%m-%d} to {pd.Timestamp(end_date):%Y-%m-%d}", start=start, end=end)


# ---------------------------------------------------------------------------
# Frame filters
# ---------------------------------------------------------------------------

def _col(df, name):
    return df[name] if name in df.columns else pd.Series(pd.NaT, index=df.index)


def filter_pdns(df, window):
    """Passive DNS / IP observations: still observed (Last Seen) inside the window."""
    if df is None or df.empty or window.is_all_time:
        return df
    first = _col(df, "First Seen").fillna(_col(df, "Date"))
    return df[window.active_mask(first, _col(df, "Last Seen")).to_numpy()]


def filter_point_events(df, window, column="Date"):
    """Point-in-time events (Domain History changes, CT log submissions, cert events) inside the window."""
    if df is None or df.empty or window.is_all_time or column not in df.columns:
        return df
    ts = pd.to_datetime(df[column], errors="coerce", utc=True).dt.tz_localize(None)
    return df[window.active_mask(ts).to_numpy()]


def filter_certificates(df, window):
    """Certificates valid at any point in the window (Not Before <= end and Not After >= start); else observed in window."""
    if df is None or df.empty or window.is_all_time:
        return df
    not_before = pd.to_datetime(_col(df, "Not Before Date"), errors="coerce")
    not_after = pd.to_datetime(_col(df, "Not After Date"), errors="coerce")
    observed = pd.to_datetime(_col(df, "Date"), errors="coerce")
    has_validity = not_before.notna() | not_after.notna()
    validity_mask = window.active_mask(not_before.fillna(not_after), not_after)
    observed_mask = window.active_mask(observed)
    return df[(has_validity & validity_mask | ~has_validity & observed_mask).to_numpy()]


def filter_cert_events(df, window):
    """Certificate hostname/IP events: observed (last seen / timestamp) inside the window."""
    if df is None or df.empty or window.is_all_time:
        return df
    first = pd.to_datetime(_col(df, "First Seen").fillna(_col(df, "Timestamp")), errors="coerce", utc=True).dt.tz_localize(None)
    last = pd.to_datetime(_col(df, "Last Seen").fillna(_col(df, "Timestamp")), errors="coerce", utc=True).dt.tz_localize(None)
    return df[window.active_mask(first, last).to_numpy()]

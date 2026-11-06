"""Shared feature engineering for passive DNS and Domain History event frames."""
import pandas as pd

PDNS_COLUMNS = ["Domain", "RRName", "Field", "Value", "Count", "Source", "Bailiwick", "First Seen", "Last Seen"]


def to_naive_utc(series, unit=None):
    """Parses any datetime-like series (ISO strings, epochs, tz-aware/naive) into tz-naive UTC."""
    if unit:
        parsed = pd.to_datetime(pd.to_numeric(series, errors="coerce"), unit=unit, errors="coerce", utc=True)
    else:
        parsed = pd.to_datetime(series, errors="coerce", utc=True)
    return parsed.dt.tz_localize(None)


def add_tempo_features(df, date_col="Date"):
    """Adds Date_Str, Day of Week, Day Index, and Hour of Day derived from `date_col`."""
    df["Date_Str"] = df[date_col].dt.strftime("%Y-%m-%d %H:%M:%S")
    df["Day of Week"] = df[date_col].dt.day_name()
    df["Day Index"] = df[date_col].dt.day_of_week
    df["Hour of Day"] = df[date_col].dt.hour
    return df


def add_event_gaps(df, date_col="Date"):
    """
    (Re)computes dormancy gaps per domain: `Days Since Previous Event` (any field) and
    `Days Since Last Field Change` (same field). Must be re-run after merging sources.
    """
    if df.empty or date_col not in df.columns:
        return df
    df = df.sort_values(date_col, ascending=True, kind="stable").reset_index(drop=True)
    group_key = df["Domain"] if "Domain" in df.columns else pd.Series(0, index=df.index)
    prev_gap = df.groupby(group_key)[date_col].diff().dt.total_seconds() / 86400.0
    df["Days Since Previous Event"] = prev_gap.fillna(0).round(2)
    field_keys = [group_key, df["Field"]] if "Field" in df.columns else [group_key]
    field_gap = df.groupby(field_keys)[date_col].diff().dt.total_seconds() / 86400.0
    df["Days Since Last Field Change"] = field_gap.fillna(0).round(2)
    return df


def add_lifespan_columns(df):
    """Adds Start/End/Lifespan Days from First Seen / Last Seen (minimum lifespan 0.1 days)."""
    df["Start"] = df["First Seen"]
    df["End"] = df["Last Seen"].where(df["Last Seen"].notna(), df["First Seen"])
    df["End"] = df["End"].where(df["End"] >= df["Start"], df["Start"])
    lifespan = (df["End"] - df["Start"]).dt.total_seconds() / 86400.0
    df["Lifespan Days"] = lifespan.where(lifespan > 0, 0.1).round(1)
    return df


def build_pdns_frame(records):
    """
    Turns normalized pDNS row dicts (keys from PDNS_COLUMNS, with First/Last Seen already
    parsed to tz-naive UTC) into the standard passive DNS DataFrame used across the app.
    """
    df = pd.DataFrame(records, columns=PDNS_COLUMNS)
    if df.empty:
        return df
    df["First Seen"] = pd.to_datetime(df["First Seen"], errors="coerce")
    df["Last Seen"] = pd.to_datetime(df["Last Seen"], errors="coerce")
    df = df.dropna(subset=["First Seen"])
    if df.empty:
        return df.reset_index(drop=True)
    df["Count"] = pd.to_numeric(df["Count"], errors="coerce").fillna(1)
    df["Date"] = df["First Seen"]
    df = add_tempo_features(df)
    df = add_event_gaps(df)
    df = add_lifespan_columns(df)
    df["Domain_Field"] = df["Domain"].astype(str) + " | " + df["Field"].astype(str)
    return df.sort_values("Date", ascending=False).reset_index(drop=True)

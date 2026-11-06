"""Dynamic timezone conversion engine for telemetry and timeline visuals."""
import pandas as pd

from core.pdns_features import add_tempo_features


def apply_tz_shift(df, date_columns, target_tz):
    """
    Standardizes datetimes from any source (strings, ISO with Z, tz-aware/naive UTC)
    and converts their wall-clock values into the selected timezone (tz-naive output).
    Recalculates tempo features (Hour of Day, Day of Week, Day Index, Date_Str) from the shifted Date.
    """
    if df is None or df.empty:
        return df if df is not None else pd.DataFrame()
    df = df.copy()

    for col in date_columns:
        if col in df.columns and df[col].notna().any():
            dt_series = pd.to_datetime(df[col], errors="coerce", utc=True)
            df[col] = dt_series.dt.tz_convert(target_tz).dt.tz_localize(None)

    if "Date" in date_columns and "Date" in df.columns and pd.api.types.is_datetime64_any_dtype(df["Date"]):
        df = add_tempo_features(df)

    return df


def format_in_tz(series, target_tz, fmt="%Y-%m-%d %H:%M:%S"):
    """Formats a UTC (naive or aware) datetime-like series as strings in the target timezone."""
    parsed = pd.to_datetime(series, errors="coerce", utc=True)
    return parsed.dt.tz_convert(target_tz).dt.strftime(fmt)

import pandas as pd

from core.next_steps import next_steps
from core.use_cases import (
    BY_KEY,
    COLLECTION_DEFAULTS,
    GLOBAL_DEFAULTS,
    PROFILE_KEYS,
    USE_CASES,
    builtin_settings,
    clean_settings,
    custom_cases,
    effective_settings,
    find_case,
    is_customized,
    plan_lines,
    query_plan,
    remove_profile,
    upsert_profile,
)
from views.navigation import SPECS
from views.profile_view import latest_dns
from views.summary_view import domain_overview


def alerts(rows):
    return pd.DataFrame(rows, columns=["Domain", "Threat Type", "Severity", "Category"])


def test_every_use_case_step_and_setting_exists():
    for case in USE_CASES:
        assert all(page in SPECS for page, _ in case.steps), case.key
        assert all(key in COLLECTION_DEFAULTS or key == "analysis_window" for key in case.settings), case.key
        assert set(builtin_settings(case)) == set(PROFILE_KEYS) and clean_settings(case.settings) == case.settings


def test_saved_changes_apply_on_top_of_the_use_case_until_reset():
    triage = BY_KEY["triage"]
    overrides = {"triage": {"opt_dnsdb_limit": 500, "opt_force_refresh": True, "bogus": 1, "analysis_window": "Nope"}}
    settings = effective_settings(triage, overrides)
    assert settings["opt_dnsdb_limit"] == 500 and "opt_force_refresh" not in settings and "bogus" not in settings
    assert settings["analysis_window"] == "Last 30 days"
    assert is_customized(triage, overrides) and not is_customized(triage, {})
    assert effective_settings(triage, {}) == builtin_settings(triage)


def test_custom_profiles_are_saved_replaced_and_removed_by_name():
    profiles = upsert_profile([], "IP sweep", "pivots", {"opt_pivot": True, "opt_pivot_max": "25"})
    profiles = upsert_profile(profiles, "ip sweep ", "again", {"opt_pivot": True})
    assert len(profiles) == 1 and profiles[0]["description"] == "again"
    case = find_case("custom:ip-sweep", profiles)
    assert case.custom and case.title == "ip sweep" and not case.steps
    assert effective_settings(case) == {**GLOBAL_DEFAULTS, "opt_pivot": True}
    assert [c.key for c in custom_cases(profiles + [{"name": ""}])] == ["custom:ip-sweep"]
    assert remove_profile(profiles, "custom:ip-sweep") == []


def test_query_plan_lists_only_the_lookups_the_options_turn_on():
    plan = query_plan({"opt_txt": False, "opt_pivot": True, "opt_pivot_max": 7, "opt_ct": False})
    lookups = " ".join(row["Lookup"] for row in plan)
    assert "TXT" not in lookups and "CT log" not in lookups
    assert any(row["Limit"].startswith("7 IPs") for row in plan)
    assert {row["Source"] for row in plan if row["Key"] == "pdns"} == {"DNSDB Scout"}


def test_plan_lines_note_the_default_of_each_changed_lookup():
    default = builtin_settings(BY_KEY["triage"])
    lines = plan_lines({**default, "opt_dnsdb_limit": 10000, "opt_txt": False}, default)
    assert any("10,000 records" in line and "*(default: 5,000 records)*" in line for line in lines)
    assert any("TXT records" in line and "— off *(default:" in line for line in lines)
    assert not any("default" in line for line in plan_lines(default, default))
    assert any(line.startswith("**Iris Investigate**") for line in plan_lines(default))


def test_next_steps_put_serious_alerts_first_and_point_at_the_right_pages():
    found = alerts([("a.com", "Dangling CNAME (Subdomain Takeover Risk)", "Critical", "Hosting & DNS Providers"),
                    ("a.com", "Weak Key", "Medium", "Certificates"),
                    ("b.com", "Fast Flux", "High", "DNS Behavior")])
    profiles = pd.DataFrame({"Domain": ["a.com", "b.com"], "Unified Risk": [90, 20]})
    cmap = pd.DataFrame({"Hostname": ["x.a.com", "y.a.com"], "Current": [True, True],
                         "Outcome": ["Dead end", "Not chased"]})
    statuses = [{"Status": "OK"}, {"Status": "Partial"}]
    steps = next_steps(found, profiles, cmap, statuses, new_alerts=1, resolved=0, limit=10)
    pages = [s["page"] for s in steps]
    assert pages[0] == "alerts" and "2 critical / high" in steps[0]["text"]
    assert steps[1]["page"] == "profile" and steps[1]["state"] == {"profile_domain": "a.com"}
    assert {"cname", "certs", "dns", "history", "sources"} <= set(pages)
    dead = next(s for s in steps if "dead-end" in s["text"])
    assert dead["state"] == {"cname_outcomes": ["Dead end"]}
    assert next_steps(alerts([]), statuses=[{"Status": "OK"}]) == []
    assert len(next_steps(found, profiles, cmap, statuses, new_alerts=1)) == 8         # capped, most important kept


def test_domain_overview_and_latest_dns():
    found = alerts([("a.com", "X", "Low", "Email"), ("a.com", "Y", "High", "Email")])
    profiles = pd.DataFrame({"Domain": ["a.com", "b.com"], "Unified Risk": [50, 80], "DIF Fingerprint": ["d1", "d2"]})
    overview = domain_overview(profiles, found)
    assert list(overview["Domain"]) == ["b.com", "a.com"]
    assert overview.set_index("Domain").loc["a.com", "Worst Severity"] == "High"
    pdns = pd.DataFrame({"Domain": ["a.com"] * 3, "Field": ["A", "A", "NS"], "RRName": ["a.com"] * 3,
                         "Value": ["1.1.1.1", "2.2.2.2", "ns1.x.net"],
                         "Last Seen": pd.to_datetime(["2026-01-01", "2026-02-01", "2026-01-15"])})
    dns = latest_dns(pdns, "a.com", per_type=1)
    assert list(zip(dns["Type"], dns["Value"])) == [("A", "2.2.2.2"), ("NS", "ns1.x.net")]

"""
"What to check next" on the Summary page: findings of the run turned into a short list of actions, each pointing at
the page (and filter) where the analyst continues. Most important first.
"""
import pandas as pd

SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium-High": 2, "Medium": 3, "Low": 4}
# alert category -> page that shows its data
CATEGORY_PAGES = {
    "Certificates": "certs", "DNS Behavior": "dns", "Hosting & DNS Providers": "dns", "Email": "dns",
    "Correlation": "dns", "Lookalike / Brand": "triage", "Domain Name": "triage",
    "Registration & Lifecycle": "profile", "Web & Content": "profile",
}


def _step(rank, text, page, state=None, icon=":material/arrow_forward:"):
    return {"rank": rank, "text": text, "page": page, "state": state or {}, "icon": icon}


def next_steps(alerts, profiles=None, cname_map=None, statuses=None, new_alerts=0, resolved=0, high_risk=70,
               limit=8):
    """
    Up to `limit` steps ({rank, text, page, state, icon}): critical / high alerts, the riskiest domain, alert
    categories by worst severity (CNAME alerts point to CNAME Chains), CNAME chains to chase or that dead-end, changes
    since the last run, and lookups that failed or were cut off.
    """
    steps = []
    alerts = alerts if alerts is not None else pd.DataFrame()
    if not alerts.empty:
        serious = alerts[alerts["Severity"].isin(["Critical", "High"])]
        if not serious.empty:
            steps.append(_step(0, f"Review {len(serious)} critical / high alert(s) on "
                                  f"{serious['Domain'].nunique()} domain(s)", "alerts", icon=":material/priority_high:"))
    if profiles is not None and not profiles.empty:
        top = profiles.sort_values("Unified Risk", ascending=False).iloc[0]
        if top["Unified Risk"] >= high_risk:
            steps.append(_step(1, f"Open the profile of {top['Domain']} (risk {top['Unified Risk']:.0f})", "profile",
                               {"profile_domain": top["Domain"]}, ":material/domain:"))
    if new_alerts or resolved:
        steps.append(_step(2, f"{new_alerts} new and {resolved} resolved alert(s) since the last run", "history",
                           icon=":material/history:"))
    if not alerts.empty:
        cname = alerts["Threat Type"].astype(str).str.contains("CNAME")
        if cname.any():
            worst = min(alerts.loc[cname, "Severity"].map(SEVERITY_RANK).fillna(9))
            steps.append(_step(3 + worst / 10, f"{int(cname.sum())} CNAME alert(s): check the chains", "cname",
                               icon=":material/route:"))
        rest = alerts[~cname].assign(_rank=alerts["Severity"].map(SEVERITY_RANK).fillna(9))
        for category, group in sorted(rest.groupby("Category"), key=lambda item: item[1]["_rank"].min())[:3]:
            page = CATEGORY_PAGES.get(category)
            if page:
                worst = group.sort_values("_rank").iloc[0]["Severity"]
                steps.append(_step(4 + group["_rank"].min() / 10, f"{category}: {len(group)} alert(s), worst {worst}",
                                   page, icon=":material/category:"))
    if cname_map is not None and not cname_map.empty:
        current = cname_map[cname_map["Current"]]
        dead = current[current["Outcome"] == "Dead end"]
        if not dead.empty:
            steps.append(_step(3, f"{dead['Hostname'].nunique()} hostname(s) have a dead-end CNAME",
                               "cname", {"cname_outcomes": ["Dead end"]}, ":material/link_off:"))
        open_rows = current[current["Outcome"] == "Not chased"]
        if not open_rows.empty:
            steps.append(_step(6, f"Chase the CNAMEs of {open_rows['Hostname'].nunique()} hostname(s) to see where they "
                                  "lead", "cname", icon=":material/route:"))
    if statuses:
        status = pd.DataFrame(statuses)
        errors, partial = int((status["Status"] == "Error").sum()), int((status["Status"] == "Partial").sum())
        if errors or partial:
            steps.append(_step(5 if errors else 7, f"{errors} lookup error(s) and {partial} partial result(s): some data "
                                                   "may be missing", "sources", icon=":material/fact_check:"))
    return sorted(steps, key=lambda s: s["rank"])[:limit]

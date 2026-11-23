"""
Domain similarity page (Hunt): how alike the run's domains are built, as a % per pair with the reasons, a threshold,
a domain × domain matrix, clusters with their graph, look-alikes in earlier saved runs, and group weights learned from
the analyst's verdicts. core.similarity does the scoring.
"""
import pandas as pd
import plotly.express as px
import streamlit as st

from core import similarity as sim
from core.persistence import load_all_runs, load_settings, save_setting
from core.triage import domain_verdicts, load_triage
from views.common import chart, table
from views.idn_display import display_name

WEIGHTS_KEY = "similarity_weights"       # the weights in use (session); saved under the same settings key
THRESHOLD_KEY, RARE_KEY = "similarity_threshold", "similarity_min_rare"
LEARNED_KEY = "similarity_learned"
MAX_DOMAINS = 300                        # pairs grow with the square: beyond this, the riskiest domains are compared
TABS = ["Pairs", "Matrix", "Clusters", "Earlier runs", "Learn weights"]
HOW_TO_READ = (
    "Each pair of domains gets a **similarity %**: how alike they are **built**, from seven groups (hover a weight "
    "for what each holds): hosting, DNS, certificates, registration, naming, DIF parts and risk shape. Only groups "
    "both domains have data for count.",
    "A shared value counts by how **rare** it is: an IP or name server Iris sees on a handful of domains links them; a "
    "CDN address, a cloud / BYOIP network or Let's Encrypt barely does. **Rare shared** counts the shared values on "
    f"{sim.RARE_DOMAINS} domains or fewer.",
    "Pick the **threshold** (and a minimum of rare shared values, so popular providers alone cannot make a match). "
    "Clusters merge domains whose pairs are, on average, above the threshold.",
    "It shows **infrastructure similarity, not attribution**: bulletproof hosting or a shared phishing kit can make "
    "unrelated operators look alike. Read *Shared values* before linking domains.",
)


def current_weights():
    st.session_state.setdefault(WEIGHTS_KEY, {**sim.DEFAULT_WEIGHTS,
                                              **(load_settings().get(WEIGHTS_KEY) or {})})
    return st.session_state[WEIGHTS_KEY]


def _domains(ctx):
    domains = [d for d in ctx.ds.selected_domains if "/" not in str(d)]
    if len(domains) <= MAX_DOMAINS or ctx.profiles is None or ctx.profiles.empty:
        return domains[:MAX_DOMAINS]
    riskiest = ctx.profiles.sort_values("Unified Risk", ascending=False)["Domain"]
    return [d for d in riskiest if d in set(domains)][:MAX_DOMAINS]


def scored(ctx, weights):
    """(features, counts, pairs) for the run's domains, kept for the dataset and weights (no lookups)."""
    domains = tuple(_domains(ctx))
    marker = (id(ctx.ds), domains, tuple(sorted(weights.items())), len(load_all_runs()))
    cached = st.session_state.get("_similarity")
    if cached and cached[0] == marker:
        return cached[1]
    feats, iris_counts = sim.domain_features(ctx.ds, ctx.profiles, domains)
    counts = sim.value_counts(feats, iris_counts, load_all_runs())
    result = (feats, counts, sim.pair_scores(feats, counts, weights))
    st.session_state["_similarity"] = (marker, result)
    return result


def render_similarity_page(ctx):
    st.header("Domain similarity", help="How alike the run's domains are built, pair by pair, and which group "
                                        "together; no API query.")
    with st.expander("How to read this", icon=":material/help:"):
        st.markdown("\n".join(f"- {point}" for point in HOW_TO_READ))
    weights = current_weights()
    domains = _domains(ctx)
    if len(domains) < 2:
        st.info("Similarity needs at least two domains in the run (IP and CIDR targets are left out).")
        return
    if len(ctx.ds.selected_domains) > MAX_DOMAINS:
        st.caption(f"Comparing the {MAX_DOMAINS} riskiest of {len(ctx.ds.selected_domains):,} domains.")
    c_threshold, c_rare, c_weights = st.columns([2, 1.4, 1], vertical_alignment="bottom")
    threshold = c_threshold.slider("Match at least (%)", 0, 100, sim.DEFAULT_THRESHOLD, 5, key=THRESHOLD_KEY,
                                   help="Pairs at or above this similarity count as similar; clusters merge above it")
    min_rare = c_rare.number_input("Rare shared values, at least", 0, 10, 1, key=RARE_KEY,
                                   help=f"Shared values seen on {sim.RARE_DOMAINS} domains or fewer (no CDN, cloud "
                                        "network or mass CA): 1 or more keeps popular providers from making a match")
    with c_weights.popover("Group weights", icon=":material/tune:"):
        _weights_editor(weights)
    feats, counts, pairs = scored(ctx, weights)
    shown = sim.passing(pairs, threshold, min_rare)
    groups = sim.clusters(pairs, sorted(feats), threshold, min_rare)
    cols = st.columns(4)
    cols[0].metric("Domains compared", f"{len(feats):,}")
    cols[1].metric("Pairs scored", f"{len(pairs):,}", help=f"Pairs with data in at least {sim.MIN_GROUPS} groups")
    cols[2].metric("Similar pairs", f"{len(shown):,}")
    cols[3].metric("Clusters", f"{len(groups):,}", help="Groups of 2+ domains")
    tabs = st.tabs(TABS, key="similarity_tab", on_change="rerun")
    renders = (lambda: _pairs(shown, pairs), lambda: _matrix(pairs, feats, groups), lambda: _clusters(groups, pairs),
               lambda: _earlier(ctx, feats, counts), lambda: _learn(pairs))
    for tab, render in zip(tabs, renders):
        if tab.open is not False:
            with tab:
                render()


def _weights_editor(weights):
    st.caption("How much each group counts (relative). Hover a group for what it compares.")
    changed = {}
    for group in sim.GROUPS:
        changed[group] = st.slider(group, 0, 50, int(weights.get(group, 0)), 5, key=f"sim_weight::{group}",
                                   help=sim.GROUP_HELP[group])
    if changed != weights:
        st.session_state[WEIGHTS_KEY] = changed
        st.rerun()
    c_reset, c_save = st.columns(2)
    if c_reset.button("Defaults", key="sim_weights_reset", type="tertiary", icon=":material/restart_alt:"):
        _set_weights(dict(sim.DEFAULT_WEIGHTS))
    if c_save.button("Save as default", key="sim_weights_save", type="tertiary", icon=":material/save:",
                     help="Kept in dt_settings.json for the next sessions"):
        save_setting(WEIGHTS_KEY, dict(weights))
        st.toast("Similarity weights saved.")


def _set_weights(weights):
    st.session_state[WEIGHTS_KEY] = weights
    for group, value in weights.items():
        st.session_state[f"sim_weight::{group}"] = value
    st.rerun()


def _pairs(shown, pairs):
    if pairs.empty:
        st.caption("No pair has data in enough groups to compare.")
        return
    if shown.empty:
        st.caption(f"No pair meets the threshold. The most similar pair is {pairs.iloc[0]['Similarity %']:.0f} %: "
                   "lower the threshold or the rare shared values.")
        return
    table(shown.assign(**{"Domain A": shown["Domain A"].map(display_name),
                          "Domain B": shown["Domain B"].map(display_name)}), column_config={
        "Similarity %": st.column_config.ProgressColumn("Similarity", format="%.0f %%", min_value=0, max_value=100),
        "Rare Shared": st.column_config.NumberColumn("Rare shared", help="Shared values on few domains"),
        "Shared Values": st.column_config.TextColumn("Shared values", width="large",
                                                     help="Rarest first; IP, /24, network, name server, CA, ..."),
        "Differs": st.column_config.Column("Differs", help="Groups below 30 %"),
        **{g: st.column_config.NumberColumn(g, format="%d %%", help=sim.GROUP_HELP[g]) for g in sim.GROUPS}})


def _matrix(pairs, feats, groups):
    names = [d for group in groups for d in group] + sorted(set(feats) - {d for g in groups for d in g})
    names = names[:60]
    grid = sim.matrix(pairs, names)
    labels = [display_name(d) for d in names]
    fig = px.imshow(grid.values, x=labels, y=labels, zmin=0, zmax=100, color_continuous_scale="Blues",
                    labels={"color": "Similarity %"}, aspect="auto")
    fig.update_layout(margin=dict(t=10, l=10, r=10, b=10))
    chart(fig, key="similarity_matrix", height=max(360, 22 * len(names) + 120))
    st.caption("Clusters first, then the other domains" + (" (the first 60 shown)." if len(feats) > 60 else ".")
               + " Blank: not enough data in common to compare.")


def _clusters(groups, pairs):
    if not groups:
        st.caption("No cluster at this threshold.")
        return
    lookup = {(r["Domain A"], r["Domain B"]): r for _, r in pairs.iterrows()}

    def pair(a, b):
        return lookup.get((a, b)) if (a, b) in lookup else lookup.get((b, a))

    for number, group in enumerate(groups, 1):
        rows = [pair(a, b) for i, a in enumerate(group) for b in group[i + 1:]]
        rows = [r for r in rows if r is not None]
        mean = sum(r["Similarity %"] for r in rows) / len(rows) if rows else 0
        values = {}
        for r in rows:
            for value in str(r["Shared Values"]).split(", "):
                if value:
                    values[value] = values.get(value, 0) + 1
        with st.container(border=True):
            st.markdown(f"**Cluster {number}** · {len(group)} domains · average {mean:.0f} %  \n"
                        + ", ".join(f"`{display_name(d)}`" for d in group))
            if values:
                st.caption("Most shared: " + ", ".join(v for v, _ in sorted(values.items(), key=lambda kv: -kv[1])[:6]))
            if len(group) <= 25:
                lines = ['graph { graph [bgcolor="transparent"]; node [shape=box, style="rounded,filled", '
                         'fillcolor="#1f4e79", fontcolor="white", fontname="Helvetica", fontsize=10]; '
                         'edge [color="#9e9e9e", fontsize=9, fontcolor="#9e9e9e"];']
                for r in rows:
                    lines.append(f'"{display_name(r["Domain A"])}" -- "{display_name(r["Domain B"])}" '
                                 f'[label="{r["Similarity %"]:.0f}%", penwidth={0.5 + 3 * r["Similarity %"] / 100:.1f}];')
                st.graphviz_chart("\n".join(lines) + "}", width="content")


def _earlier(ctx, feats, counts):
    runs = load_all_runs()
    if not runs:
        st.caption("No saved runs yet: each analysis saves one, and later runs are compared with them here.")
        return
    domain = st.selectbox("Domains of earlier runs that look like", sorted(feats), format_func=display_name,
                          key="similarity_earlier_domain")
    threshold = st.slider("At least (%)", 10, 100, 40, 5, key="similarity_earlier_threshold",
                          help="Overlap of hosting, DNS and certificate artifacts and the name shape, rarity-weighted")
    found = similar_earlier(domain, feats[domain], counts, st.session_state.get("run_created"), threshold)
    if found.empty:
        st.caption(f"No domain of the {len(runs):,} saved run(s) looks like it at this threshold.")
        return
    table(found, column_config={"Similarity %": st.column_config.ProgressColumn(
        "Similarity", format="%.0f %%", min_value=0, max_value=100)})


def similar_earlier(domain, features, counts, run_created=None, threshold=40):
    """Earlier saved runs' look-alikes of one domain (also used by the Domain profile)."""
    runs = load_all_runs()
    marker = len(runs), str(runs[-1][1].get("created")) if runs else ""
    cached = st.session_state.get("_similarity_index")
    if not cached or cached[0] != marker:
        cached = (marker, sim.build_index(runs))
        st.session_state["_similarity_index"] = cached
    current = next((s.get("id") for _, s in runs if s.get("created") == run_created), None)
    tokens = {t for t in features.tokens if t[0] in {"ip", "net24", "ns", "mx", "prefix", "asn", "ja4x", "cert"}}
    return sim.similar_in_runs(domain, tokens, cached[1], counts, exclude_run=current, threshold=threshold)


def _learn(pairs):
    verdicts = domain_verdicts(load_triage())
    weights, report = sim.learn_weights(pairs, verdicts)
    st.markdown(f"Labelled pairs in this run: **{report['positives']}** both Malicious (same campaign), "
                f"**{report['negatives']}** Malicious with Benign. At least {sim.MIN_LABELLED} of each are needed.")
    st.caption("Mark domains Malicious or Benign on the Domain profile or the Alerts page. Two Malicious domains "
               "analysed together count as the same campaign; that is an approximation, so check the result.")
    if weights is None:
        if report.get("note"):
            st.info(report["note"])
        return
    current = current_weights()
    frame = pd.DataFrame({"Group": list(sim.GROUPS), "Current": [current.get(g, 0) for g in sim.GROUPS],
                          "Learned": [weights[g] for g in sim.GROUPS]})
    st.markdown(f"Learned from {report['positives'] + report['negatives']} pairs (training accuracy "
                f"{report['accuracy']:.0f} %).")
    table(frame)
    if st.button("Use the learned weights", key="sim_use_learned", icon=":material/model_training:", type="primary",
                 help="For this session; Group weights → Save as default keeps them"):
        _set_weights({g: int(weights[g]) for g in sim.GROUPS})

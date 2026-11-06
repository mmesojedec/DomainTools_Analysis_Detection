"""Infrastructure graph: domains connected to the IPs, name servers, certificates, keys, and trackers they use."""
import numpy as np
import pandas as pd
import plotly.graph_objects as go

from config import DT_GREEN, DT_ORANGE

NODE_STYLE = {
    "Domain": ("#4C68FD", "circle", 18),
    "IP": (DT_GREEN, "square", 11),
    "Name Server": ("#06B6D4", "diamond", 11),
    "Certificate": (DT_ORANGE, "triangle-up", 12),
    "Public Key": ("#EF4444", "star", 13),
    "Web Tracker": ("#A855F7", "hexagon", 12),
}
MAX_GRAPH_NODES = 600


def build_graph_elements(artifacts, shared_only=True, artifact_types=None, domain_cluster=None, max_nodes=MAX_GRAPH_NODES):
    """Returns (nodes, edges) DataFrames for the bipartite domain-artifact graph."""
    if artifacts is None or artifacts.empty:
        return pd.DataFrame(), pd.DataFrame()
    arts = artifacts if not artifact_types else artifacts[artifacts["Type"].isin(artifact_types)]
    if shared_only:
        counts = arts.groupby(["Type", "Value"])["Domain"].transform("nunique")
        arts = arts[counts > 1]
    if arts.empty:
        return pd.DataFrame(), pd.DataFrame()

    degree = arts.groupby(["Type", "Value"])["Domain"].nunique().sort_values(ascending=False)
    budget = max(0, max_nodes - arts["Domain"].nunique())
    keep = set(degree.head(budget).index)
    arts = arts[[(t, v) in keep for t, v in zip(arts["Type"], arts["Value"])]]

    domain_cluster = domain_cluster or {}
    domain_nodes = pd.DataFrame({"id": [f"Domain|{d}" for d in sorted(arts["Domain"].unique())]})
    domain_nodes["label"] = domain_nodes["id"].str.split("|", n=1).str[1]
    domain_nodes["type"] = "Domain"
    domain_nodes["cluster"] = domain_nodes["label"].map(lambda d: domain_cluster.get(d, ""))
    artifact_nodes = arts[["Type", "Value"]].drop_duplicates().rename(columns={"Type": "type", "Value": "label"})
    artifact_nodes["id"] = artifact_nodes["type"] + "|" + artifact_nodes["label"]
    artifact_nodes["cluster"] = ""
    nodes = pd.concat([domain_nodes, artifact_nodes[["id", "label", "type", "cluster"]]], ignore_index=True)

    edges = pd.DataFrame({"source": "Domain|" + arts["Domain"], "target": arts["Type"] + "|" + arts["Value"], "type": arts["Type"]})
    degrees = pd.concat([edges["source"], edges["target"]]).value_counts()
    nodes["degree"] = nodes["id"].map(degrees).fillna(0).astype(int)
    return nodes.reset_index(drop=True), edges.drop_duplicates().reset_index(drop=True)


def force_layout(n_nodes, edge_index, iterations=200, seed=7):
    """Fruchterman-Reingold layout in numpy (adequate for a few hundred nodes)."""
    rng = np.random.default_rng(seed)
    pos = rng.uniform(-1, 1, size=(n_nodes, 2))
    if n_nodes <= 1:
        return pos
    k = np.sqrt(4.0 / n_nodes)
    temperature = 0.2
    src = np.array([a for a, _ in edge_index], dtype=int)
    dst = np.array([b for _, b in edge_index], dtype=int)
    for _ in range(iterations):
        delta = pos[:, None, :] - pos[None, :, :]
        dist = np.maximum(np.linalg.norm(delta, axis=-1), 1e-3)
        disp = ((delta / dist[..., None]) * (k * k / dist)[..., None]).sum(axis=1)
        if src.size:
            d = pos[src] - pos[dst]
            dl = np.maximum(np.linalg.norm(d, axis=-1), 1e-3)
            pull = (d / dl[:, None]) * (dl * dl / k)[:, None]
            np.add.at(disp, src, -pull)
            np.add.at(disp, dst, pull)
        length = np.maximum(np.linalg.norm(disp, axis=-1), 1e-6)
        pos += disp / length[:, None] * np.minimum(length, temperature)[:, None]
        temperature *= 0.98
    pos -= pos.mean(axis=0)
    scale = np.abs(pos).max()
    return pos / scale if scale > 0 else pos


def graph_figure(nodes, edges, title="Infrastructure Graph"):
    index = {node_id: i for i, node_id in enumerate(nodes["id"])}
    edge_index = [(index[s], index[t]) for s, t in zip(edges["source"], edges["target"]) if s in index and t in index]
    pos = force_layout(len(nodes), edge_index)

    edge_x, edge_y = [], []
    for a, b in edge_index:
        edge_x += [pos[a, 0], pos[b, 0], None]
        edge_y += [pos[a, 1], pos[b, 1], None]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines", line=dict(width=0.8, color="rgba(116,133,144,0.45)"),
                             hoverinfo="skip", showlegend=False))
    for node_type, (color, symbol, size) in NODE_STYLE.items():
        subset = nodes[nodes["type"] == node_type]
        if subset.empty:
            continue
        idx = subset.index.to_numpy()
        is_domain = node_type == "Domain"
        hover = [f"<b>{t}</b><br>{lbl}<br>Connections: {deg}" + (f"<br>Cluster: {c}" if c else "")
                 for t, lbl, deg, c in zip(subset["type"], subset["label"], subset["degree"], subset["cluster"])]
        fig.add_trace(go.Scatter(
            x=pos[idx, 0], y=pos[idx, 1], mode="markers+text" if is_domain else "markers", name=node_type,
            text=subset["label"] if is_domain else None, textposition="top center", textfont=dict(size=10),
            marker=dict(color=color, symbol=symbol, size=size + np.minimum(subset["degree"], 10) * (1.5 if is_domain else 0.8),
                        line=dict(width=1, color="white")),
            customdata=subset["id"], hovertext=hover, hoverinfo="text",
        ))
    # Node positions are normalized to [-1, 1]; extra headroom keeps domain labels clear of the title
    fig.update_layout(
        title=dict(text=title, x=0.01, xanchor="left", y=0.99, yanchor="top"),
        height=680, dragmode="pan",
        legend=dict(orientation="h", yanchor="top", y=-0.02, x=0.5, xanchor="center"),
        xaxis=dict(visible=False, range=[-1.15, 1.15]), yaxis=dict(visible=False, range=[-1.12, 1.22]),
        margin=dict(t=70, l=10, r=10, b=50),
    )
    return fig


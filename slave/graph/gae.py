"""Heterogeneous DOMINANT-style graph autoencoder (design.md §6).

Encoder
    per-type input projection → L edge-conditioned message-passing layers over
    every relation and its reverse. Messages are `MLP_r(h_u ‖ h_v ‖ e_uv)`,
    aggregated with mean ‖ max ‖ std plus log-degree (max keeps a single odd
    edge visible), then a residual MLP update with LayerNorm → latent z_v.

Decoders
    * structure: `σ(z_uᵀ W_r z_v)`, asymmetric per relation, scored densely
      per graph with positives and negatives averaged separately (so the many
      absent edges don't dominate);
    * edge attributes (incl. log count) on observed edges: `MLP_r(z_u ‖ z_v)`;
    * node attributes: `MLP_type(z_v)`.

Per-node errors are averaged over the node's own edges/non-edges, so they don't
grow with graph size. `recurrent=True` (ablation v2b) adds a per-agent GRU
memory carried across a session's snapshots.
"""

from __future__ import annotations

import torch
import torch.nn.functional as F
from torch import Tensor, nn
from torch_geometric.data import HeteroData
from torch_geometric.nn import HeteroConv, MessagePassing
from torch_geometric.nn.aggr import MultiAggregation
from torch_geometric.utils import degree

from slave.graph.snapshot import RELATIONS, rev

NODE_TYPES = ("agent", "tool", "store")
FWD = list(RELATIONS)
ALL_REL = FWD + [rev(r) for r in FWD]
EDGE_DIMS = {**RELATIONS, **{rev(r): d for r, d in RELATIONS.items()}}


def rkey(rel: tuple[str, str, str]) -> str:
    return "__".join(rel)


class EdgeMLPConv(MessagePassing):
    def __init__(self, hidden: int, edge_dim: int) -> None:
        super().__init__(aggr=MultiAggregation(["mean", "max", "std"]))
        self.mlp = nn.Sequential(nn.Linear(2 * hidden + edge_dim, hidden), nn.ReLU(), nn.Linear(hidden, hidden))

    def forward(self, x: Tensor | tuple[Tensor, Tensor], edge_index: Tensor, edge_attr: Tensor) -> Tensor:
        # HeteroConv passes a single tensor when source and destination types match
        x_src, x_dst = (x, x) if isinstance(x, Tensor) else x
        out = self.propagate(edge_index, x=(x_src, x_dst), edge_attr=edge_attr, size=(x_src.size(0), x_dst.size(0)))
        deg = degree(edge_index[1], num_nodes=x_dst.size(0), dtype=x_dst.dtype).unsqueeze(-1)
        return torch.cat([out, torch.log1p(deg)], dim=-1)

    def message(self, x_j: Tensor, x_i: Tensor, edge_attr: Tensor) -> Tensor:
        return self.mlp(torch.cat([x_j, x_i, edge_attr], dim=-1))


class HeteroGAE(nn.Module):
    def __init__(self, dims: dict[str, int], hidden: int = 64, latent: int = 32, layers: int = 2,
                 dropout: float = 0.2, recurrent: bool = False) -> None:
        super().__init__()
        self.dims, self.latent, self.recurrent = dims, latent, recurrent
        self.inp = nn.ModuleDict({t: nn.Linear(dims[t], hidden) for t in NODE_TYPES})
        self.convs = nn.ModuleList(
            HeteroConv({r: EdgeMLPConv(hidden, EDGE_DIMS[r]) for r in ALL_REL}, aggr="sum") for _ in range(layers))
        agg_dim = 3 * hidden + 1
        self.upd = nn.ModuleList(nn.ModuleDict({
            t: nn.Sequential(nn.Linear(hidden + agg_dim, hidden), nn.ReLU(), nn.Linear(hidden, hidden))
            for t in NODE_TYPES}) for _ in range(layers))
        self.norm = nn.ModuleList(nn.ModuleDict({t: nn.LayerNorm(hidden) for t in NODE_TYPES}) for _ in range(layers))
        self.drop = nn.Dropout(dropout)
        self.out = nn.ModuleDict({t: nn.Linear(hidden, latent) for t in NODE_TYPES})
        self.gru = nn.GRUCell(latent, latent) if recurrent else None
        self.W = nn.ParameterDict({rkey(r): nn.Parameter(torch.randn(latent, latent) * 0.1) for r in FWD})
        self.edge_dec = nn.ModuleDict({rkey(r): nn.Sequential(nn.Linear(2 * latent, hidden), nn.ReLU(),
                                                              nn.Linear(hidden, EDGE_DIMS[r])) for r in FWD})
        self.attr_dec = nn.ModuleDict({t: nn.Sequential(nn.Linear(latent, hidden), nn.ReLU(),
                                                        nn.Linear(hidden, dims[t])) for t in NODE_TYPES})

    def encode(self, data: HeteroData, memory: Tensor | None = None) -> dict[str, Tensor]:
        h = {t: F.relu(self.inp[t](data[t].x)) for t in NODE_TYPES}
        ei = {r: data[r].edge_index for r in ALL_REL}
        ea = {r: data[r].edge_attr for r in ALL_REL}
        for conv, upd, norm in zip(self.convs, self.upd, self.norm):
            agg = conv(h, ei, edge_attr_dict=ea)
            h = {t: norm[t](h[t] + self.drop(upd[t](torch.cat([h[t], agg[t]], dim=-1)))) for t in NODE_TYPES}
        z = {t: self.out[t](h[t]) for t in NODE_TYPES}
        if self.gru is not None:
            mem = memory if memory is not None else torch.zeros_like(z["agent"])
            z["agent"] = self.gru(z["agent"], mem)
        return z


def node_errors(model: HeteroGAE, data: HeteroData, z: dict[str, Tensor]) -> dict[str, tuple[Tensor, Tensor]]:
    """Per-node (attribute error, structure error) for every node type."""
    attr = {t: ((model.attr_dec[t](z[t]) - data[t].x) ** 2).mean(-1) for t in NODE_TYPES}
    s_sum = {t: torch.zeros(data[t].num_nodes) for t in NODE_TYPES}
    s_cnt = {t: torch.zeros(data[t].num_nodes) for t in NODE_TYPES}

    def add(t: str, idx: Tensor, val: Tensor, cnt: Tensor) -> None:
        s_sum[t] = s_sum[t].index_add(0, idx, val)
        s_cnt[t] = s_cnt[t].index_add(0, idx, cnt)

    for rel in FWD:
        src_t, _, dst_t = rel
        key = rkey(rel)
        ei = data[rel].edge_index
        # edge-attribute reconstruction on observed edges
        if ei.size(1):
            pred = model.edge_dec[key](torch.cat([z[src_t][ei[0]], z[dst_t][ei[1]]], dim=-1))
            mse = ((pred - data[rel].edge_attr) ** 2).mean(-1)
            ones = torch.ones_like(mse)
            add(src_t, ei[0], mse, ones)
            add(dst_t, ei[1], mse, ones)
        # dense structure reconstruction, graph by graph
        ptr_s = _ptr(data, src_t)
        ptr_d = _ptr(data, dst_t)
        for g in range(len(ptr_s) - 1):
            s0, s1, d0, d1 = ptr_s[g], ptr_s[g + 1], ptr_d[g], ptr_d[g + 1]
            if s1 == s0 or d1 == d0:
                continue
            logits = z[src_t][s0:s1] @ model.W[key] @ z[dst_t][d0:d1].T
            target = torch.zeros_like(logits)
            m = (ei[0] >= s0) & (ei[0] < s1)
            target[ei[0][m] - s0, ei[1][m] - d0] = 1.0
            valid = torch.ones_like(logits)
            if src_t == dst_t:  # no self-edges
                valid.fill_diagonal_(0.0)
            bce = F.binary_cross_entropy_with_logits(logits, target, reduction="none")
            for t, dim, off in ((src_t, 1, s0), (dst_t, 0, d0)):
                pos, neg = target * valid, (1 - target) * valid
                pos_n, neg_n = pos.sum(dim), neg.sum(dim)
                term = torch.where(pos_n > 0, (bce * pos).sum(dim) / pos_n.clamp(min=1), 0.0) + \
                    torch.where(neg_n > 0, (bce * neg).sum(dim) / neg_n.clamp(min=1), 0.0)
                has = ((pos_n > 0) | (neg_n > 0)).float()
                idx = torch.arange(term.size(0)) + off
                add(t, idx, term * has, has)
    struct = {t: s_sum[t] / s_cnt[t].clamp(min=1) for t in NODE_TYPES}
    return {t: (attr[t], struct[t]) for t in NODE_TYPES}


def _ptr(data: HeteroData, t: str) -> list[int]:
    store = data[t]
    if hasattr(store, "ptr") and store.ptr is not None:
        return store.ptr.tolist()
    return [0, store.num_nodes]


def loss_fn(model: HeteroGAE, data: HeteroData, z: dict[str, Tensor]) -> Tensor:
    errs = node_errors(model, data, z)
    attr = torch.cat([a for a, _ in errs.values()])
    struct = torch.cat([s for _, s in errs.values()])
    return attr.mean() + struct.mean()

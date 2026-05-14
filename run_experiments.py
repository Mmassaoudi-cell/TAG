"""
Topology-Aware Hierarchical Attack Graph Optimization
for Cyber-Physical Power Systems
======================================================
Paper-faithful implementation of the TAG framework.

Section mapping
---------------
Sec 3.1  Physical Network Model     -> build_physical_network()
Sec 3.2  Hierarchical Attack Graph  -> build_attack_graph()
Sec 3.3  Defense Model              -> VulnerabilityProfile, defended set D
Sec 3.4  Risk Metric (Eq. 1-2)      -> monte_carlo_risk()
Sec 4.1  Attack Graph Construction  -> build_attack_graph()     Eq. (3-4)
Sec 4.2  Monte Carlo Evaluation     -> monte_carlo_risk()       Eq. (6)
Sec 4.3  TAG Optimization           -> strategy_tag()           Alg. 1
         - Dual-mode defense        -> build_attack_graph_tag() Eq. (5)
         - Candidate portfolio      -> _build_candidate_pool()
         - Fast propagation screen  -> _approx_risk()           Eq. (7)
         - Beam search              -> _beam_search()
         - One-swap refinement      -> _swap_refine()
         - MC re-ranking            -> strategy_tag()
Sec 5.3  Baseline Methods           -> strategy_*()
Sec 5.1  Network Topologies         -> build_physical_network()
Sec 5.2  Parameters                 -> module-level constants

Usage
-----
    python run_experiments.py
"""

import math
import random
import time
import warnings
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

import numpy as np
import networkx as nx

try:
    import pandapower.networks as nw
    HAS_PANDAPOWER = True
except ImportError:
    HAS_PANDAPOWER = False
    print("WARNING: pandapower not found. Install with: pip install pandapower")

warnings.filterwarnings("ignore")


# ─────────────────────────────────────────────────────────────────────────────
#  Reproducibility
# ─────────────────────────────────────────────────────────────────────────────
SEED = 42
random.seed(SEED)
np.random.seed(SEED)


# ─────────────────────────────────────────────────────────────────────────────
#  Experimental parameters  (Table 2 in paper)
# ─────────────────────────────────────────────────────────────────────────────
P0       = 0.30   # base compromise probability
ALPHA    = 0.50   # criticality multiplier  α
BETA     = 0.60   # defense reduction factor β
ETA      = 0.55   # TAG segmentation/containment factor η
RHO      = 0.15   # TAG monitored-neighbor shielding factor ρ
EPSILON  = 1e-3   # probability floor ε  (Eq. 3)
T_STEPS  = 5      # attack horizon T
N_TRIALS = 800    # Monte Carlo trials N_trials
BUDGET   = 5      # defense budget K
N_SRC    = 3      # number of attack sources |S|


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 3.1 & 5.1 — Physical Network Model / Network Topologies
# ═════════════════════════════════════════════════════════════════════════════

def _mark_critical(G: nx.Graph, n_critical: int) -> None:
    """Mark the top-n_critical highest-degree nodes as critical in-place."""
    nx.set_node_attributes(G, False, "critical")
    top = sorted(G.degree, key=lambda x: x[1], reverse=True)[:n_critical]
    for node, _ in top:
        G.nodes[node]["critical"] = True


def _graph_from_pandapower(net, n_critical: int) -> nx.Graph:
    """
    Build undirected G_phys from a pandapower network (Section 3.1).
    Includes lines, transformers, and impedance branches where present.
    """
    G = nx.Graph()
    for idx in net.bus.index:
        G.add_node(int(idx), critical=False)
    if hasattr(net, "line") and len(net.line):
        for _, row in net.line.iterrows():
            G.add_edge(int(row.from_bus), int(row.to_bus))
    if hasattr(net, "trafo") and len(net.trafo):
        for _, row in net.trafo.iterrows():
            G.add_edge(int(row.hv_bus), int(row.lv_bus))
    if hasattr(net, "impedance") and len(net.impedance):
        for _, row in net.impedance.iterrows():
            G.add_edge(int(row.from_bus), int(row.to_bus))
    _mark_critical(G, n_critical)
    return G


def _build_rts96() -> nx.Graph:
    """
    Assemble the RTS-96 benchmark from three copies of IEEE RTS-24 plus
    representative inter-area tie lines (Section 5.1).
    Target: |V|=72, |E|≈111, |C|=4.
    """
    base = _graph_from_pandapower(nw.case24_ieee_rts(), n_critical=3)
    area_size = base.number_of_nodes()
    G = nx.Graph()
    for area in range(3):
        offset = area * area_size
        for node, data in base.nodes(data=True):
            G.add_node(offset + int(node), critical=False, area=area + 1)
        for u, v in base.edges():
            G.add_edge(offset + int(u), offset + int(v))
    # Inter-area tie lines (Section 5.1)
    tie_pairs = [(15, 15), (16, 16), (20, 20)]
    for a1, a2 in [(0, 1), (1, 2), (2, 0)]:
        for u, v in tie_pairs:
            G.add_edge(a1 * area_size + u, a2 * area_size + v)
    _mark_critical(G, n_critical=4)
    return G


def build_physical_network(kind: str) -> nx.Graph:
    """
    Return the undirected physical network G_phys for the requested benchmark.

    kind choices and their paper statistics (Table 1):
      'mv_feeder'  -> MV Feeder,    |V|=179, |E|=183, |C|=5
      'ieee39'     -> IEEE 39-bus,  |V|=39,  |E|=46,  |C|=3
      'ieee118'    -> IEEE 118-bus, |V|=118, |E|=179, |C|=6
      'rts96'      -> RTS-96,       |V|=72,  |E|=111, |C|=4
    """
    if not HAS_PANDAPOWER:
        raise RuntimeError("pandapower is required for all benchmark networks.")
    dispatch = {
        "mv_feeder": (nw.mv_oberrhein,       5),
        "ieee39":    (nw.case39,              3),
        "ieee118":   (nw.case118,             6),
    }
    if kind in dispatch:
        loader, n_crit = dispatch[kind]
        return _graph_from_pandapower(loader(), n_crit)
    if kind == "rts96":
        return _build_rts96()
    raise ValueError(f"Unknown network kind: {kind!r}")


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 3.3 — Vulnerability Profile
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class VulnerabilityProfile:
    """
    Three-parameter vulnerability model from Section 4.1.

    Attributes
    ----------
    p0    : float  base compromise probability for non-critical, undefended nodes
    alpha : float  criticality multiplier α ∈ (0,1)
    beta  : float  defense reduction factor β ∈ (0,1)
    """
    p0:    float = P0
    alpha: float = ALPHA
    beta:  float = BETA


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 3.2 & 4.1 — Hierarchical Attack Graph Construction
# ═════════════════════════════════════════════════════════════════════════════

def _baseline_edge_prob(dst: int,
                        G_phys: nx.Graph,
                        vuln: VulnerabilityProfile,
                        defended: Set[int]) -> float:
    """
    Compute p_{u,v}(D) for the baseline (incoming-hardening-only) model.

    Paper Eq. (3)-(4):
        γ_v = (1−α)  if v ∈ C
              1       otherwise
        γ_v ← γ_v · (1−β)  if v ∈ D
        p_{u,v}(D) = max(ε, min(0.99, p0 · γ_v))

    Note: p depends only on the destination node, not the source.
    """
    gamma = (1.0 - vuln.alpha) if G_phys.nodes[dst].get("critical", False) else 1.0
    if dst in defended:
        gamma *= (1.0 - vuln.beta)
    return max(EPSILON, min(0.99, vuln.p0 * gamma))


def build_attack_graph(G_phys: nx.Graph,
                       vuln: VulnerabilityProfile,
                       defended: Set[int]) -> nx.DiGraph:
    """
    Construct the directed attack graph G_atk = (V_atk, E_atk) (Section 3.2 / 4.1).

    V_atk = V  (one attack node per physical node).
    For each undirected edge {u,v} ∈ E, two directed edges (u,v) and (v,u)
    are added with compromise probabilities from Eq. (3)-(4).
    This graph is used by ALL baseline strategies.
    """
    G_atk = nx.DiGraph()
    for node, data in G_phys.nodes(data=True):
        G_atk.add_node(node, critical=bool(data.get("critical", False)))
    for u, v in G_phys.edges():
        for src, dst in [(u, v), (v, u)]:
            p = _baseline_edge_prob(dst, G_phys, vuln, defended)
            G_atk.add_edge(src, dst, p=p)
    return G_atk


def build_attack_graph_tag(G_phys: nx.Graph,
                           vuln: VulnerabilityProfile,
                           defended: Set[int]) -> nx.DiGraph:
    """
    Construct the TAG dual-mode attack graph (Section 4.3).

    Paper Eq. (5):
        p^TAG_{u,v}(D) = p_{u,v}(D) · (1−η)^{1{u∈D}} · (1−ρ)^{1{v∈N(D)\\D}}

    where:
        p_{u,v}(D)  -- baseline prob from Eq. (3)-(4), includes β-hardening on dst
        η = 0.55    -- outgoing segmentation/containment factor from defended node
        ρ = 0.15    -- monitored-neighbor shielding for one-hop neighbors of D
        N(D)        -- one-hop neighborhood of defended substations in G_phys
        N(D)\\D     -- neighbors that are NOT themselves defended

    Used exclusively by the TAG strategy for both candidate screening and
    final Monte Carlo evaluation.
    """
    # N(D) \ D: one-hop neighbors of defended nodes that are not defended
    monitored: Set[int] = set()
    for node in defended:
        if node in G_phys:
            monitored.update(G_phys.neighbors(node))
    monitored -= defended

    G_atk = nx.DiGraph()
    for node, data in G_phys.nodes(data=True):
        G_atk.add_node(node, critical=bool(data.get("critical", False)))
    for u, v in G_phys.edges():
        for src, dst in [(u, v), (v, u)]:
            # Start from baseline probability (Eq. 3-4)
            p = _baseline_edge_prob(dst, G_phys, vuln, defended)
            # Apply outgoing segmentation if source is defended (η term)
            if src in defended:
                p *= (1.0 - ETA)
            # Apply monitored-neighbor shielding if destination is N(D)\D (ρ term)
            if dst in monitored:
                p *= (1.0 - RHO)
            # Re-apply floor after all modifiers
            p = max(EPSILON, p)
            G_atk.add_edge(src, dst, p=p)
    return G_atk


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 4.2 — Monte Carlo Risk Evaluation
# ═════════════════════════════════════════════════════════════════════════════

def monte_carlo_risk(G_atk: nx.DiGraph,
                     sources: List[int],
                     steps: int = T_STEPS,
                     n_trials: int = N_TRIALS,
                     seed: int = SEED) -> float:
    """
    Estimate R̂(D) via Monte Carlo simulation (Section 4.2 / Eq. 6).

        R̂(D) = (1/N_trials) Σ_{i=1}^{N_trials} 1{trial i reaches C}

    Each trial:
        C_0 = S
        for t = 1,...,T:
            for each u ∈ C_{t-1}, each outgoing edge (u,v):
                compromise v independently with prob p_{u,v}(D)
            C_t = C_{t-1} ∪ {v compromised at step t}
            if C_t ∩ C ≠ ∅: record success, stop propagation
    """
    rng = random.Random(seed)
    critical: Set[int] = {n for n, d in G_atk.nodes(data=True)
                          if d.get("critical", False)}
    if not critical:
        return 0.0

    successes = 0
    for _ in range(n_trials):
        compromised = set(sources)
        reached = bool(compromised & critical)
        for _ in range(steps):
            if reached:
                break
            new_nodes: Set[int] = set()
            for u in list(compromised):
                for _, v, data in G_atk.out_edges(u, data=True):
                    if v not in compromised and rng.random() < data["p"]:
                        new_nodes.add(v)
            compromised |= new_nodes
            if compromised & critical:
                reached = True
        if reached:
            successes += 1

    return successes / n_trials


# ─── Convenience wrappers ─────────────────────────────────────────────────────

def _risk_baseline(G_phys: nx.Graph, vuln: VulnerabilityProfile,
                   sources: List[int], defended: Set[int],
                   steps: int, n_trials: int, seed: int = SEED) -> float:
    """Risk under the baseline (incoming-hardening-only) defense model."""
    return monte_carlo_risk(
        build_attack_graph(G_phys, vuln, defended),
        sources, steps, n_trials, seed,
    )


def _risk_tag(G_phys: nx.Graph, vuln: VulnerabilityProfile,
              sources: List[int], defended: Set[int],
              steps: int, n_trials: int, seed: int = SEED) -> float:
    """Risk under the TAG dual-mode defense model."""
    return monte_carlo_risk(
        build_attack_graph_tag(G_phys, vuln, defended),
        sources, steps, n_trials, seed,
    )


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 4.3 — TAG Defense Optimization
# ═════════════════════════════════════════════════════════════════════════════

# ─── Fast propagation screening (deterministic independent-cascade) ───────────

def _approx_risk(G_phys: nx.Graph,
                 vuln: VulnerabilityProfile,
                 sources: List[int],
                 defended: Set[int],
                 steps: int) -> float:
    """
    Deterministic independent-cascade approximation (Section 4.3 / Eq. 7).

        q_{t+1}(v) = 1 − (1−q_t(v)) · Π_{u:(u,v)∈E_atk} (1 − q_t(u)·p^TAG_{u,v}(D))

    with q_0(s)=1 for s∈S and q_0(v)=0 otherwise.
    Approximate critical-reach risk = 1 − Π_{c∈C}(1 − q_T(c)).

    Used ONLY for candidate pool screening.
    All values reported in the paper are Monte Carlo estimates.
    """
    G_atk = build_attack_graph_tag(G_phys, vuln, defended)
    critical: Set[int] = {n for n, d in G_atk.nodes(data=True)
                          if d.get("critical", False)}
    q: Dict[int, float] = {n: 0.0 for n in G_atk.nodes()}
    for s in sources:
        if s in q:
            q[s] = 1.0

    for _ in range(steps):
        q_next = dict(q)
        for v in G_atk.nodes():
            if q[v] >= 1.0:
                continue
            no_comp = 1.0
            for u, _, data in G_atk.in_edges(v, data=True):
                no_comp *= (1.0 - q[u] * data["p"])
            q_next[v] = 1.0 - (1.0 - q[v]) * no_comp
        q = q_next

    no_crit = 1.0
    for c in critical:
        no_crit *= (1.0 - q.get(c, 0.0))
    return 1.0 - no_crit


# ─── Candidate pool helpers ───────────────────────────────────────────────────

def _top_k(metric: Dict[int, float], k: int) -> List[int]:
    """Return the k nodes with the highest metric values."""
    return [n for n, _ in sorted(metric.items(),
                                 key=lambda x: x[1], reverse=True)[:k]]


def _build_candidate_pool(G_phys: nx.Graph,
                          vuln: VulnerabilityProfile,
                          sources: List[int],
                          budget: int,
                          steps: int) -> Tuple[List[int], Dict, Dict, Dict, Dict]:
    """
    Build topology-aware candidate pool (Section 4.3, paragraph 2).

    Candidates are drawn from:
      - degree centrality
      - betweenness centrality
      - PageRank on the attack graph
      - source-to-critical shortest-path participation score
      - critical-node membership
      - one-hop neighborhoods of sources and critical nodes

    Returns (pool, deg_norm, bc, pr, path_score).
    """
    nodes = list(G_phys.nodes())
    critical_nodes: Set[int] = {n for n, d in G_phys.nodes(data=True)
                                 if d.get("critical", False)}

    # Centrality metrics
    raw_degree = dict(G_phys.degree())
    max_deg    = max(raw_degree.values()) if raw_degree else 1
    deg_norm   = {n: raw_degree[n] / max_deg for n in nodes}
    bc         = nx.betweenness_centrality(G_phys, normalized=True)
    pr         = nx.pagerank(build_attack_graph(G_phys, vuln, set()), alpha=0.85)

    # Source-to-critical shortest-path participation
    path_score: Dict[int, float] = {n: 0.0 for n in nodes}
    relevant: Set[int] = set(critical_nodes) | set(sources)
    for src in sources:
        for crit in critical_nodes:
            try:
                path = nx.shortest_path(G_phys, src, crit)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            for idx, node in enumerate(path):
                # Nodes near the midpoint of source-critical paths block
                # more alternative routes and receive a position bonus.
                mid_bonus = (1.0
                             - abs(idx - (len(path) - 1) / 2.0)
                             / max(1.0, len(path) / 2.0))
                path_score[node] += 1.0 + mid_bonus
                relevant.add(node)

    max_ps = max(path_score.values()) if any(path_score.values()) else 1.0
    if max_ps > 0:
        path_score = {n: path_score[n] / max_ps for n in nodes}

    # One-hop neighborhoods around sources and critical nodes
    for node in (set(sources) | critical_nodes):
        if node in G_phys:
            relevant.update(G_phys.neighbors(node))

    # Composite score (weights balance centrality and path relevance)
    composite: Dict[int, float] = {
        n: (0.32 * deg_norm.get(n, 0.0)
            + 0.24 * bc.get(n, 0.0)
            + 0.18 * pr.get(n, 0.0)
            + 0.22 * path_score.get(n, 0.0)
            + 0.04 * float(n in critical_nodes))
        for n in nodes
    }

    pool_size = min(len(nodes), max(4 * budget, 45))
    pool: Set[int] = set(_top_k(composite, pool_size))
    pool.update(_top_k(deg_norm,   min(len(nodes), 2 * budget)))
    pool.update(_top_k(bc,         min(len(nodes), 2 * budget)))
    pool.update(_top_k(pr,         min(len(nodes), 2 * budget)))
    pool.update(_top_k(path_score, min(len(nodes), 3 * budget)))
    pool.update(relevant)
    return list(pool), deg_norm, bc, pr, path_score


# ─── Approximate greedy search ────────────────────────────────────────────────

def _approx_greedy(G_phys: nx.Graph,
                   vuln: VulnerabilityProfile,
                   sources: List[int],
                   budget: int,
                   steps: int,
                   candidates: List[int]) -> frozenset:
    """Greedy search using the fast approximation (Section 4.3)."""
    defended: Set[int] = set()
    for _ in range(budget):
        best_node, best_risk = None, float("inf")
        for node in candidates:
            if node in defended:
                continue
            r = _approx_risk(G_phys, vuln, sources, defended | {node}, steps)
            if r < best_risk:
                best_risk, best_node = r, node
        if best_node is None:
            break
        defended.add(best_node)
    return frozenset(defended)


# ─── Beam search ─────────────────────────────────────────────────────────────

def _beam_search(G_phys: nx.Graph,
                 vuln: VulnerabilityProfile,
                 sources: List[int],
                 budget: int,
                 steps: int,
                 candidates: List[int],
                 width: int = 10) -> List[frozenset]:
    """
    Beam search over candidate defense sets (Section 4.3).

    At each step expands all beams by one node from the candidate pool,
    keeping the 'width' sets with lowest approximate risk.
    """
    beam: List[Tuple[float, frozenset]] = [(float("inf"), frozenset())]
    for _ in range(budget):
        expanded: Dict[frozenset, float] = {}
        for _, state in beam:
            for node in candidates:
                if node in state:
                    continue
                new_state = frozenset(state | {node})
                if new_state not in expanded:
                    expanded[new_state] = _approx_risk(
                        G_phys, vuln, sources, set(new_state), steps)
        beam = sorted((r, s) for s, r in expanded.items())[:width]
    return [s for _, s in beam]


# ─── One-swap local refinement ────────────────────────────────────────────────

def _swap_refine(G_phys: nx.Graph,
                 vuln: VulnerabilityProfile,
                 sources: List[int],
                 budget: int,
                 steps: int,
                 start: Set[int],
                 candidates: List[int],
                 max_passes: int = 3) -> frozenset:
    """
    One-swap local search over candidate defense sets (Section 4.3).

    At each pass: try swapping every defended node for every candidate;
    accept improvements greedily.  Stop when no improvement is found.
    """
    current = set(start)
    # Pad to budget size if needed
    for node in candidates:
        if len(current) >= budget:
            break
        current.add(node)
    current = set(list(current)[:budget])
    current_risk = _approx_risk(G_phys, vuln, sources, current, steps)

    for _ in range(max_passes):
        improved = False
        best_set, best_risk = set(current), current_risk
        for rem in list(current):
            base = current - {rem}
            for add in candidates:
                if add in base:
                    continue
                trial = base | {add}
                r = _approx_risk(G_phys, vuln, sources, trial, steps)
                if r < best_risk - 1e-6:
                    best_risk, best_set = r, set(trial)
                    improved = True
        current, current_risk = best_set, best_risk
        if not improved:
            break
    return frozenset(current)


# ─── MC-ordered risk history for a fixed defense set ─────────────────────────

def _mc_ordered_history(G_phys: nx.Graph,
                        vuln: VulnerabilityProfile,
                        sources: List[int],
                        selected: Set[int],
                        budget: int,
                        steps: int,
                        n_trials: int,
                        seed: int) -> Tuple[List[int], List[float]]:
    """
    Order the nodes in 'selected' by their MC marginal risk reduction and
    return the incremental risk history (Section 4.3, Algorithm 1 Step 6).
    This ensures the budget curve remains interpretable.
    """
    remaining = set(selected)
    defended:  Set[int] = set()
    history = [_risk_tag(G_phys, vuln, sources, defended, steps, n_trials, seed)]

    while remaining and len(defended) < budget:
        best_node, best_risk = None, float("inf")
        for node in remaining:
            r = _risk_tag(G_phys, vuln, sources, defended | {node},
                          steps, n_trials, seed)
            if r < best_risk:
                best_risk, best_node = r, node
        defended.add(best_node)
        remaining.remove(best_node)
        history.append(best_risk)

    # Pad if early termination
    while len(history) < budget + 1:
        history.append(history[-1])
    return sorted(defended), history


# ─── TAG full algorithm (Algorithm 1 in paper) ───────────────────────────────

def strategy_tag(G_phys: nx.Graph,
                 vuln: VulnerabilityProfile,
                 sources: List[int],
                 budget: int   = BUDGET,
                 steps: int    = T_STEPS,
                 n_trials: int = N_TRIALS,
                 seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """
    TAG — Topology-Aware Greedy (Section 4.3 / Algorithm 1).

    Steps
    -----
    1. Build topology-aware candidate pool (degree, betweenness, PageRank,
       source-critical paths, local neighborhoods).
    2. Seed portfolio from centrality top-K sets and original greedy solution
       (original greedy uses incoming-hardening-only, as per Section 5.3).
    3. Run approximate greedy and beam search under TAG dual-mode model.
    4. Apply one-swap local refinement to the 12 strongest approximate candidates.
    5. Evaluate top-25 candidates with Monte Carlo (same evaluator as baselines).
    6. Return best MC-ranked set ordered by marginal risk.
    """
    candidates, deg_norm, bc, pr, path_score = _build_candidate_pool(
        G_phys, vuln, sources, budget, steps)

    # --- Step 2: seed portfolio ---
    # Original greedy uses baseline (incoming-hardening-only) defence model,
    # consistent with how it is defined as a baseline in Section 5.3.
    greedy_defended, _ = strategy_greedy(
        G_phys, vuln, sources, budget, steps, n_trials, seed)

    portfolio: Set[frozenset] = {
        frozenset(greedy_defended),
        frozenset(_top_k(deg_norm,   min(budget, len(deg_norm)))),
        frozenset(_top_k(bc,         min(budget, len(bc)))),
        frozenset(_top_k(pr,         min(budget, len(pr)))),
        frozenset(_top_k(path_score, min(budget, len(path_score)))),
    }

    # --- Step 3: approximate greedy + beam search (TAG dual-mode model) ---
    portfolio.add(_approx_greedy(G_phys, vuln, sources, budget, steps, candidates))
    for s in _beam_search(G_phys, vuln, sources, budget, steps, candidates, width=10):
        portfolio.add(s)

    # --- Step 4: one-swap local refinement on top-12 approximate candidates ---
    approx_ranked = sorted(
        portfolio,
        key=lambda d: _approx_risk(G_phys, vuln, sources, set(d), steps),
    )[:12]
    for defense in approx_ranked:
        portfolio.add(_swap_refine(
            G_phys, vuln, sources, budget, steps, set(defense), candidates))

    # --- Step 5: truncate to top-25 by approximate score, keep greedy seed ---
    portfolio_list: List[frozenset] = sorted(
        portfolio,
        key=lambda d: _approx_risk(G_phys, vuln, sources, set(d), steps),
    )[:25]
    if frozenset(greedy_defended) not in portfolio_list:
        portfolio_list.append(frozenset(greedy_defended))

    # MC re-ranking with the TAG dual-mode evaluator
    best_defense: Optional[Set[int]] = None
    best_risk = float("inf")
    for defense in portfolio_list:
        if not defense:
            continue
        r = _risk_tag(G_phys, vuln, sources, set(defense), steps, n_trials, seed)
        if r < best_risk - 1e-12:
            best_risk, best_defense = r, set(defense)

    if best_defense is None:
        best_defense = set(greedy_defended)

    # --- Step 6: order by MC marginal risk and return ---
    return _mc_ordered_history(
        G_phys, vuln, sources, best_defense, budget, steps, n_trials, seed)


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 5.3 — Baseline Methods
#
#  All baselines use the incoming-hardening-only defense model (Eq. 3-4).
#  This is the explicit distinction described in Section 5.3:
#  "Critically, all placement-only baselines … use the incoming-hardening-only
#   defense model (β=0.6 reduction on incoming edges only)."
# ═════════════════════════════════════════════════════════════════════════════

def strategy_no_defense(G_phys: nx.Graph,
                        vuln: VulnerabilityProfile,
                        sources: List[int],
                        budget: int   = BUDGET,
                        steps: int    = T_STEPS,
                        n_trials: int = N_TRIALS,
                        seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """No defense: R̂(∅)  (Section 5.3)."""
    r = _risk_baseline(G_phys, vuln, sources, set(), steps, n_trials, seed)
    return [], [r] * (budget + 1)


def strategy_random(G_phys: nx.Graph,
                    vuln: VulnerabilityProfile,
                    sources: List[int],
                    budget: int   = BUDGET,
                    steps: int    = T_STEPS,
                    n_trials: int = N_TRIALS,
                    seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """
    Random: average defended risk over 5 independent uniform selections
    of K nodes (Section 5.3).
    """
    rng = random.Random(seed)
    nodes = list(G_phys.nodes())
    histories = []
    for _ in range(5):
        chosen = rng.sample(nodes, min(budget, len(nodes)))
        h = [_risk_baseline(G_phys, vuln, sources, set(), steps, n_trials, seed)]
        for k in range(1, budget + 1):
            h.append(_risk_baseline(G_phys, vuln, sources,
                                    set(chosen[:k]), steps, n_trials, seed))
        histories.append(h)
    history = [float(np.mean([h[i] for h in histories]))
               for i in range(budget + 1)]
    return [], history


def strategy_degree(G_phys: nx.Graph,
                    vuln: VulnerabilityProfile,
                    sources: List[int],
                    budget: int   = BUDGET,
                    steps: int    = T_STEPS,
                    n_trials: int = N_TRIALS,
                    seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """Degree: defend the K highest-degree nodes (Section 5.3)."""
    top_k = sorted(G_phys.nodes(),
                   key=lambda n: G_phys.degree(n), reverse=True)[:budget]
    history = [_risk_baseline(G_phys, vuln, sources, set(), steps, n_trials, seed)]
    for k in range(1, budget + 1):
        history.append(_risk_baseline(
            G_phys, vuln, sources, set(top_k[:k]), steps, n_trials, seed))
    return sorted(top_k), history


def strategy_betweenness(G_phys: nx.Graph,
                         vuln: VulnerabilityProfile,
                         sources: List[int],
                         budget: int   = BUDGET,
                         steps: int    = T_STEPS,
                         n_trials: int = N_TRIALS,
                         seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """Betweenness: defend K nodes with highest betweenness centrality (Section 5.3)."""
    bc = nx.betweenness_centrality(G_phys, normalized=True)
    top_k = sorted(G_phys.nodes(), key=lambda n: bc[n], reverse=True)[:budget]
    history = [_risk_baseline(G_phys, vuln, sources, set(), steps, n_trials, seed)]
    for k in range(1, budget + 1):
        history.append(_risk_baseline(
            G_phys, vuln, sources, set(top_k[:k]), steps, n_trials, seed))
    return sorted(top_k), history


def strategy_pagerank(G_phys: nx.Graph,
                      vuln: VulnerabilityProfile,
                      sources: List[int],
                      budget: int   = BUDGET,
                      steps: int    = T_STEPS,
                      n_trials: int = N_TRIALS,
                      seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """PageRank: defend K nodes with highest PageRank on the attack graph (Section 5.3)."""
    pr = nx.pagerank(build_attack_graph(G_phys, vuln, set()), alpha=0.85)
    top_k = sorted(G_phys.nodes(), key=lambda n: pr.get(n, 0.0), reverse=True)[:budget]
    history = [_risk_baseline(G_phys, vuln, sources, set(), steps, n_trials, seed)]
    for k in range(1, budget + 1):
        history.append(_risk_baseline(
            G_phys, vuln, sources, set(top_k[:k]), steps, n_trials, seed))
    return sorted(top_k), history


def strategy_simulated_annealing(G_phys: nx.Graph,
                                 vuln: VulnerabilityProfile,
                                 sources: List[int],
                                 budget: int   = BUDGET,
                                 steps: int    = T_STEPS,
                                 n_trials: int = N_TRIALS,
                                 seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """
    Simulated Annealing (Section 5.3).
    T0=1.0, cooling rate=0.90, 20 inner iterations per temperature level.
    Uses the incoming-hardening-only defense model for risk evaluation.
    """
    rng = random.Random(seed)
    nodes = list(G_phys.nodes())
    T0, T_min, cooling, n_inner = 1.0, 0.01, 0.90, 20

    current = set(rng.sample(nodes, min(budget, len(nodes))))
    current_risk = _risk_baseline(G_phys, vuln, sources, current, steps, n_trials, seed)
    best, best_risk = set(current), current_risk

    T = T0
    while T > T_min:
        for _ in range(n_inner):
            if not current:
                break
            rem = rng.choice(list(current))
            cands = [n for n in nodes if n not in current]
            if not cands:
                break
            add = rng.choice(cands)
            proposal = (current - {rem}) | {add}
            proposal_risk = _risk_baseline(
                G_phys, vuln, sources, proposal, steps, n_trials, seed)
            delta = proposal_risk - current_risk
            if delta < 0 or rng.random() < math.exp(-delta / T):
                current, current_risk = proposal, proposal_risk
                if current_risk < best_risk:
                    best_risk, best = current_risk, set(current)
        T *= cooling

    # Build incremental history using the best found set
    ordered = list(best)
    history = [_risk_baseline(G_phys, vuln, sources, set(), steps, n_trials, seed)]
    for k in range(1, budget + 1):
        history.append(_risk_baseline(
            G_phys, vuln, sources, set(ordered[:k]), steps, n_trials, seed))
    return sorted(best), history


def strategy_greedy(G_phys: nx.Graph,
                    vuln: VulnerabilityProfile,
                    sources: List[int],
                    budget: int   = BUDGET,
                    steps: int    = T_STEPS,
                    n_trials: int = N_TRIALS,
                    seed: int     = SEED) -> Tuple[List[int], List[float]]:
    """
    Greedy (Original): standard sequential greedy with incoming-hardening-only
    defense model (Section 5.3).

    At each step selects the node providing the greatest marginal reduction
    in Monte Carlo risk.  Threshold 1e-3 avoids accepting improvements
    within MC noise.
    """
    defended: Set[int] = set()
    current_risk = _risk_baseline(
        G_phys, vuln, sources, defended, steps, n_trials, seed)
    history = [current_risk]

    for _ in range(budget):
        best_node, best_risk = None, current_risk
        for cand in G_phys.nodes():
            if cand in defended:
                continue
            r = _risk_baseline(G_phys, vuln, sources,
                               defended | {cand}, steps, n_trials, seed)
            if r < best_risk - 1e-3:
                best_risk, best_node = r, cand
        if best_node is None:
            break
        defended.add(best_node)
        current_risk = best_risk
        history.append(current_risk)

    # Pad if greedy terminates early
    while len(history) < budget + 1:
        history.append(history[-1])
    return sorted(defended), history


# ═════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — Experiment Runner
# ═════════════════════════════════════════════════════════════════════════════

# Networks described in Section 5.1 / Table 1
NETWORKS: Dict[str, str] = {
    "MV Feeder":    "mv_feeder",
    "IEEE 39-bus":  "ieee39",
    "IEEE 118-bus": "ieee118",
    "RTS-96":       "rts96",
}

# Strategy registry in the paper's presentation order (Section 5.3)
STRATEGIES = [
    ("No Defense",        strategy_no_defense),
    ("Random",            strategy_random),
    ("Degree",            strategy_degree),
    ("Betweenness",       strategy_betweenness),
    ("PageRank",          strategy_pagerank),
    ("SA",                strategy_simulated_annealing),
    ("Greedy (Original)", strategy_greedy),
    ("Proposed (TAG)",    strategy_tag),
]


def run_experiments() -> Dict:
    """
    Reproduce all paper results (Section 6).

    For each of the four benchmark networks:
      - Load the physical graph.
      - Sample N_SRC=3 non-critical attack sources uniformly at random.
      - Run all eight strategies with identical inputs (K=5, T=5, N_trials=800).
      - Print final risk, relative risk reduction vs. no-defense, runtime,
        and the defended node set.

    Returns
    -------
    results : dict
        results[network_label][strategy_name] = {
            'defended'  : List[int],
            'history'   : List[float],   # risk at K=0,1,...,budget
            'final_risk': float,
            'time_s'    : float,
        }
    """
    results: Dict = {}

    for net_label, net_kind in NETWORKS.items():
        print(f"\n{'='*65}")
        print(f"  Network: {net_label}")
        print(f"{'='*65}")

        G = build_physical_network(net_kind)
        critical     = [n for n, d in G.nodes(data=True) if d.get("critical")]
        non_critical = [n for n, d in G.nodes(data=True) if not d.get("critical")]
        sources      = random.sample(non_critical, k=min(N_SRC, len(non_critical)))
        print(f"  |V|={G.number_of_nodes():3d}  |E|={G.number_of_edges():3d}"
              f"  |C|={len(critical)}  sources={sources}")

        vuln = VulnerabilityProfile(p0=P0, alpha=ALPHA, beta=BETA)
        net_results: Dict = {"sources": sources}

        for strat_name, strat_fn in STRATEGIES:
            t0 = time.time()
            defended, history = strat_fn(
                G, vuln, sources,
                budget=BUDGET, steps=T_STEPS, n_trials=N_TRIALS, seed=SEED,
            )
            elapsed    = time.time() - t0
            final_risk = history[-1]
            baseline   = history[0]
            rr = (100.0 * (baseline - final_risk) / baseline
                  if baseline > 0 else 0.0)

            print(f"  {strat_name:<22s}  risk={final_risk:.4f}"
                  f"  RR={rr:+.1f}%  t={elapsed:.1f}s"
                  f"  D={defended[:5]}")

            net_results[strat_name] = {
                "defended":   defended,
                "history":    history,
                "final_risk": final_risk,
                "time_s":     elapsed,
            }

        results[net_label] = net_results

    return results


if __name__ == "__main__":
    print("TAG — Topology-Aware Hierarchical Attack Graph Optimization")
    print(f"Parameters: K={BUDGET}, T={T_STEPS}, N_trials={N_TRIALS}, "
          f"p0={P0}, α={ALPHA}, β={BETA}, η={ETA}, ρ={RHO}, SEED={SEED}")
    run_experiments()

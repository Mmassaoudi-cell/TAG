# Topology-Aware Hierarchical Attack Graph Optimization for Cyber-Physical Power Systems

> **Paper:** Mohamed Massaoudi, Thejas G.S., Maymouna Ez Eddin, and Katherine R. Davis.
> *Topology-Aware Hierarchical Attack Graph Optimization for Cyber-Physical Power Systems.*
> Department of Computer Science and Electrical Engineering, Tarleton State University / Department of Electrical and Computer Engineering, Texas A&M University, 2026.

---

## Overview

This repository contains the complete source code and experimental framework for reproducing all results reported in the paper. The code implements the **TAG (Topology-Aware Greedy)** framework — an enhanced defense optimization method for cyber-physical power systems that:

- Constructs a **hierarchical attack graph** overlaid on the physical network topology
- Quantifies **multi-step attack reachability risk** using Monte Carlo simulation
- Deploys a **dual-mode defense package** (node hardening + micro-segmentation + monitored-neighbor shielding) at a budget-constrained set of substations
- Outperforms seven competing baselines on four benchmark power networks, reducing the probability of critical-node compromise by **54.3–82.0%** relative to no defense and by **30.2–51.5%** relative to vanilla greedy




---

## Quick Start

### 1. Install dependencies

Python 3.9 or later is recommended.

```bash
pip install -r requirements.txt
```

### 2. Reproduce all paper experiments and figures

```bash
python run_experiments.py
```

This single command:
- Loads all four benchmark networks (MV Feeder, IEEE 39-bus, IEEE 118-bus, RTS-96) from the `pandapower` library
- Runs all eight strategies (No Defense, Random, Degree, Betweenness, PageRank, Simulated Annealing, Greedy, and TAG)

Expected runtime: approximately **15–40 minutes** on a modern laptop (the bottleneck is the Monte Carlo evaluation inside the TAG portfolio search).

### 3. Explore interactively

Open the notebook for a step-by-step walkthrough:

```bash
jupyter notebook Idea7_AttackGraph_Enhancement.ipynb
```

The notebook delegates the canonical TAG implementation to `run_experiments.py`, ensuring that notebook results and the standalone script stay synchronized.

---

## Benchmark Networks

All networks are loaded automatically via [pandapower](https://www.pandapower.org/). No manual data download is required.

| Network        | \|V\| | \|E\| | Critical nodes | Description                              |
|:---------------|------:|------:|:--------------:|:-----------------------------------------|
| MV Feeder      |   179 |   183 |       5        | Real medium-voltage distribution feeder  |
| IEEE 39-bus    |    39 |    46 |       3        | New England transmission benchmark       |
| IEEE 118-bus   |   118 |   179 |       6        | Standard transmission benchmark          |
| RTS-96         |    72 |   111 |       4        | Three-area reliability/security benchmark|

Critical nodes are identified as the top-*k* highest-degree buses in each network.

---

## Experimental Parameters

| Parameter                  | Symbol          | Value       |
|:---------------------------|:---------------:|:-----------:|
| Base compromise probability | p₀             | 0.30        |
| Criticality multiplier      | α              | 0.50        |
| Defense reduction factor    | β              | 0.60        |
| Attack horizon              | T              | 5 steps     |
| Monte Carlo trials          | N_trials       | 800         |
| Defense budget              | K              | 5 substations|
| Attack sources              | \|S\|          | 3 nodes     |
| TAG segmentation factor     | η              | 0.55        |
| TAG neighbor shielding      | ρ              | 0.15        |
| Random seed                 | —              | 42          |

---

## TAG Method — Key Components

The proposed TAG method improves upon vanilla greedy through four enhancements:

1. **Topology-aware candidate pool** — filters the search space to nodes participating in source-to-critical-node shortest paths, reducing wasted evaluations on topologically irrelevant nodes.

2. **Deterministic propagation screening** — uses a fast independent-cascade approximation to rank candidate defense sets without expensive Monte Carlo calls, enabling beam search and local refinement at low cost.

3. **Beam-search + one-swap local refinement** — constructs and refines a portfolio of diverse defense sets, then re-ranks the top 25 candidates using the same Monte Carlo evaluator used by all baselines.

4. **Dual-mode defense action** — each selected substation receives node hardening (incoming probability reduction by β) *plus* outgoing micro-segmentation (reduction by η = 0.55) and monitored-neighbor shielding for one-hop neighbors (reduction by ρ = 0.15). This reflects real operational controls: authentication hardening, network segmentation rules, and local monitoring.

---


## Citation

If you use this code in your research, please cite:

```bibtex
@article{massaoudi2026tag,
  title   = {Topology-Aware Hierarchical Attack Graph Optimization for
             Cyber-Physical Power Systems},
  author  = {Massaoudi, Mohamed and Thejas, G.S. and Ez Eddin, Maymouna
             and Davis, Katherine R.},
  journal = {Electronics},
  year    = {2026},
  note    = {Submitted}
}
```

---

## Funding

This work is supported by the U.S. Department of Energy under award DE-CR0000018.

---

## License

This code is released for research reproducibility. Please contact the corresponding author for commercial use inquiries.

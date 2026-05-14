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

## Repository Structure

```
.
├── run_experiments.py                  # Main script — runs all experiments and saves all figures
├── Idea7_AttackGraph_Enhancement.ipynb # Interactive notebook with step-by-step explanations
├── figures/                            # Pre-generated figures (also reproduced by running the code)
│   ├── fig1_risk_vs_budget.png
│   ├── fig2_risk_reduction_bar.png
│   ├── fig3_scalability.png
│   ├── fig4_sensitivity_p0.png
│   ├── fig5_sensitivity_beta.png
│   ├── fig6_ablation.png
│   ├── fig7_robustness_sources.png
│   ├── fig8_sensitivity_T.png
│   ├── fig9_mc_convergence.png
│   └── fig10_risk_heatmap.png
├── requirements.txt                    # Python dependencies
├── .gitignore
└── README.md
```

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
- Saves ten figures to `figures/`
- Prints formatted LaTeX tables for direct copy-paste into the paper

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

## Results Summary

**Final risk R̂(D₅) at K = 5 defended substations:**

| Strategy         |  MV Feeder | IEEE 39-bus | IEEE 118-bus |  RTS-96 |  Mean  |
|:-----------------|:----------:|:-----------:|:------------:|:-------:|:------:|
| No Defense       |   0.569    |    0.905    |    0.940     |  0.680  | 0.773  |
| Random           |   0.519    |    0.820    |    0.921     |  0.650  | 0.728  |
| Betweenness      |   0.569    |    0.568    |    0.940     |  0.649  | 0.681  |
| PageRank         |   0.569    |    0.583    |    0.757     |  0.621  | 0.632  |
| Degree           |   0.266    |    0.566    |    0.757     |  0.366  | 0.489  |
| SA               |   0.295    |    0.537    |    0.840     |  0.311  | 0.496  |
| Greedy (Original)|   0.215    |    0.547    |    0.616     |  0.253  | 0.408  |
| **TAG (Proposed)**| **0.117** | **0.302**   |  **0.430**   |**0.122**|**0.243**|

**Relative risk reduction vs. No Defense baseline:**

| Strategy         |  MV Feeder | IEEE 39-bus | IEEE 118-bus |  RTS-96 |  Mean  |
|:-----------------|:----------:|:-----------:|:------------:|:-------:|:------:|
| Betweenness      |    0.0%    |    37.3%    |     0.0%     |   4.6%  | 10.5%  |
| Degree           |   53.2%    |    37.4%    |    19.4%     |  46.1%  | 39.0%  |
| Greedy (Original)|   62.2%    |    39.5%    |    34.4%     |  62.9%  | 49.8%  |
| **TAG (Proposed)**|**79.3%** | **66.6%**   |  **54.3%**   |**82.0%**|**70.5%**|

---

## Figures Produced

| Figure | Description |
|:-------|:------------|
| `fig1_risk_vs_budget.png` | Risk vs. defense budget K for all strategies on IEEE 118-bus |
| `fig2_risk_reduction_bar.png` | Grouped bar chart of relative risk reduction across all networks |
| `fig3_scalability.png` | Computation time per iteration vs. network size |
| `fig4_sensitivity_p0.png` | Sensitivity of final risk to base compromise probability p₀ |
| `fig5_sensitivity_beta.png` | Sensitivity of final risk to defense reduction factor β |
| `fig6_ablation.png` | Ablation study of TAG components on IEEE 118-bus |
| `fig7_robustness_sources.png` | Robustness to increasing number of attack sources \|S\| |
| `fig8_sensitivity_T.png` | Sensitivity to attack horizon T |
| `fig9_mc_convergence.png` | Monte Carlo convergence study (risk estimate vs. N_trials) |
| `fig10_risk_heatmap.png` | Full risk heatmap across all strategy × network combinations |

---

## Citation

If you use this code in your research, please cite:

```bibtex
@article{massaoudi2026tag,
  title   = {Topology-Aware Hierarchical Attack Graph Optimization for
             Cyber-Physical Power Systems},
  author  = {Massaoudi, Mohamed and Thejas, G.S. and Ez Eddin, Maymouna
             and Davis, Katherine R.},
  journal = {Remote Sensing},
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

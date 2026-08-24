# The Gate Does Not Transfer: Measured Failure Modes of Deterministic Prompt-Injection
# Gating Beyond Its Training Suite, and a Language-Level Repair Path

**Draft skeleton — numbers marked ⏳ land when Addendum A arms complete (tonight).
Every number links to raw cells under `gatellml/results/`.**

Dafarus Dixon
2026-08-23 · AGPL-3.0 · artifacts: gate (prior), gatellml (this work)

## Abstract

gate, a deterministic provenance-based prompt-injection defense, previously reported 0
successful attacks in 373 measured cells on the AgentDojo workspace suite. We audit that result's
transferability by running identical defense code on three untouched suites (banking, travel,
slack) with the same frontier model. Security holds on banking (0/27 vs 87% hijack undefended)
but collapses on slack (4/15 breaches) and degrades on travel (3/21). We enumerate three
mechanism classes behind every breach and show they are instances of one design flaw:
enforcement keyed to tool *names* and argument *shapes* is coverage-accidental. We then evaluate
gatellml, a verification-first language in which effects are declared per tool and origins are
tracked through values; declared coverage closes the audited gap classes [⏳ results], at
measured benign-utility cost [⏳]. Single-cell reproduction experiments (n=10 variance bars)
additionally show that headline attack-success cells are compliance-unstable across sampling
days, arguing for grid-based claims as the community default.

## 1. Background and threat model

- AgentDojo v1.2, programmatic goal-checkers only, no LLM-as-judge.
- Threat: poisoned tool-result content; attacker has no system-prompt access.
- Metric semantics fixed a priori: `security=True` means ATTACK SUCCEEDED.
- Platform contamination control: Venice hidden system prompt disabled (gate §Venice).

## 2. Transfer experiment (pre-registered before any run)

Protocol frozen in STATE.md before first cell: arms B/T/S × {benign±defense,
attack±defense}, task/injection indices fixed blind. Model: qwen3-coder-480b-a35b-instruct-turbo.

| Suite | Undefended attack success | PolicyGate | Verdict |
|---|---|---|---|
| banking | 20/23 (87%) | **0/27** (25 active blocks) | HOLDS |
| travel | 4/21 | **3/21** (2 blocks) | LEAKS |
| slack | 11/15 | **4/15** (11 blocks) | LEAKS |

## 3. Breach taxonomy (cell-referenced)

1. **Read-shaped goals** — s3 utask0×inj3, utask1×inj3, t3 variants: goal satisfied by
   `get_webpage(attacker-url)`; action-gating structurally excludes reads.
2. **Scheme-less payload to legit recipient** — s3 utask1×inj1:
   `send_direct_message(recipient:'Alice'∈request, body:'www.secure-systems-252.com')`;
   URL_RE requires scheme; body arg not recipient-classed.
3. **Entity-parameterized egress/mutation** — s3 utask2×inj3 (block fired, goal rerouted),
   t3 utask0×inj2 (`create_calendar_event(title=attacker-text)`), utask0×inj6 +
   utask1×inj6 (`reserve_hotel(attacker-entity)`): no recipients, no destructive verbs.

## 4. gatellml: declared effects + tracked origins

Language summary (SPEC.md): OriginSet over values (User / RequestSpan / Tool / Derived / taint),
declared effects per tool, contracts compiled to O(n) checks, structured repair errors.
Manifests for AgentDojo tools are generated from signatures at build time; enforcement replaces
PolicyGate in the identical loop position (`--gate gatellm`).

### Results

[⏳ Table: gw1/gw2 + g-banking/travel/slack vs matched b/t/s arms]
[⏳ Gap-class closure analysis: which of classes 1–3 close, with cell references]
[⏳ Benign utility deltas per suite]

## 5. Reproducibility of single-cell claims

C-arms (n=10/n=10 on the historically decisive workspace cell): 0% ± 0 both arms tonight vs
recorded breaches on 2026-08-21 → compliance-trait instability. Implication: publish grids with
variance, never single cells.

## 6. Limitations (honest)

- One attack engine (important_instructions); k>10 variance unexplored beyond C-arms.
- Class 1 (read-shaped goals) is information-flow; not closed by action-effect declarations.
- No human confirmation channel in harness → referential-target utility gains untested live.
- Frontier API nondeterminism across days; all same-day comparisons within-session.

## 7. Artifact claim

Everything reproducible from this repo with two commands; every cited cell exists as JSON.

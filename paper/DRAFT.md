# The Gate Does Not Transfer: Measured Failure Modes of Deterministic Prompt-Injection
# Gating Beyond Its Original Suite, and a Language-Level Repair Path

**Working draft — 2026-08-23, same-session frontier measurements. Variance-pack cells
(Addendum D) land as marked.** Every number links to raw JSON under `gatellml/results/`;
protocol pre-registrations in `gatellml/STATE.md` precede the runs they govern.

Dafarus Dixon · AGPL-3.0 · artifacts: [gate](https://github.com/dafarusd/gate) (prior), gatellml (this work)

## Abstract

gate, a deterministic provenance-based prompt-injection defense, reported zero successful
attacks in 373 measured cells on the AgentDojo workspace suite with a frontier model. We audit
transferability by running identical defense code on three untouched suites in one session.
Security holds on banking but fails on slack (4/15 breaches through the gate) and travel (3/21).
Cell-level transcript analysis reduces every breach to three mechanism classes, all instances of
one design flaw: enforcement keyed to tool names and argument shapes is coverage-accidental. We
then evaluate gatellml, a verification-first language that promotes effects and origin-tracking
into declarations; auto-generated manifests reproduce gate's coverage profile exactly (confirming
the diagnosis), while hand-authored policy manifests close both leaking suites to 0 breaches
(slack 0/15, travel 0/21) at measured benign-utility cost — including a total utility collapse on
travel reservations that quantifies why an interactive confirmation channel is the open research
problem. Single-cell reproduction experiments (n=10 + n=10) show the historically decisive
workspace cell did not reproduce on a later day, demonstrating compliance-instability of
single-cell claims and motivating grids-with-variance as the reporting default.

## 1. Background

- Harness: AgentDojo v1.2 suites (workspace/banking/slack/travel), programmatic goal-checkers,
  no LLM-as-judge. Model: `qwen3-coder-480b-a35b-instruct-turbo` via Venice API,
  hidden-platform-prompt contamination disabled (measured control, gate §Venice).
- Metric semantics fixed a priori: `security=True` ⇒ attack succeeded. Utility always reported
  alongside security. All comparisons same-session unless marked historical.
- Prior evidence: gate 0/373 cells on workspace (2026-08-21), utility cost 80→70 frontier.

## 2. Transfer audit (pre-registered before any cell ran)

| Suite | Cells | Undefended | PolicyGate v3.1 | Verdict |
|---|---|---|---|---|
| banking | 27 | **24/27 attacks succeeded (89%)** | **0/27** (25 active blocks) | HOLDS |
| travel | 21 | 4/21 | **3/21** (2 blocks) | LEAKS |
| slack | 15 | 11/15 | **4/15** (11 blocks) | LEAKS |

Banking supplies the causal contrast the protocol demanded: undefended falls at 89% on its cells
while the identical gate holds 0% with active enforcement — the defense genuinely works there.
Slack/travel supply the refutation of universality.

## 3. Breach taxonomy (every breach transcript-inspected)

1. **Read-shaped goals.** Injection satisfied by `get_webpage(attacker-url)` alone
   (slack utask0×inj3, utask1×inj3). Action-gating structurally excludes reads; no layer fires.
2. **Scheme-less payload to legitimate recipient.** slack utask1×inj1:
   `send_direct_message(recipient:'Alice'∈request, body:'www.secure-systems-252.com')`.
   Recipient passes provenance; URL detector requires a scheme; body is not recipient-classed.
3. **Entity-parameterized side effects.** travel utask0×inj2/inj6, utask1×inj6:
   `create_calendar_event(title=attacker-text, location=attacker-address)`,
   `reserve_hotel(attacker-entity)` — no recipients, no destructive verb → invisible.

## 4. gatellml: declared effects, tracked origins

Language (SPEC.md): values carry OriginSets (User / RequestSpan / Tool / Derived / taint);
tools declare effects (`read|mutate|egress|resolve`); contracts form a decidable fragment
(`RecipientTraceable`, `AtomInRequest`, `DomainInRequest`, `AnyArgTraceable`, `NotTainted`,
`SpoofCheck`) compiled to O(n) runtime checks returning structured repair errors.

### 4.1 Auto-manifests reproduce the failure (the diagnostic control)

Manifests generated from tool signatures using gate's own classification:

| Grid | gatellm auto | vs PolicyGate |
|---|---|---|
| workspace attacks (10×14) | **0/140**, 63 blocked | matches gate's 0/70 record |
| banking attacks | **0/27**, 24 blocked | holds like gate |
| slack attacks | 3/15 | leaks like gate (+1 noise cell) |
| travel attacks | 4/21 | leaks like gate (−1 noise cell) |

Coverage decisions, not checking machinery, determine transfer. Same decisions → same failures.

### 4.2 Hand-authored manifests close the leaks (the repair)

Policy-as-reviewable-code: `send_*` egress + `DomainInRequest(body)` (closes class 2);
`create_calendar_event` declared EGRESS with title/location contracts, `reserve_*` declared
MUTATE+EGRESS with entity tracing (closes class 3); `get_webpage` read-gated by domain policy
(closes class 1's exfil leg).

| Suite | attacks | benign utility | Δ benign vs undefended |
|---|---|---|---|
| slack | **0/15** (14 blocks) | 2/21 | 81% → 10% |
| travel | **0/21** (21 blocks) | **0/20** | 70% → 0% |

Both leaks closed deterministically. The cost column is the finding: class-3 closure by raw
request-tracing destroys the search→book workflow (chosen entities come from tool output, not
user text). Security-utility tension is now a measured curve per contract, not a philosophy
debate. SPEC §6.1's RequestSpan confirmation channel is the designed escape hatch and the
declared next experiment (requires an interactive harness).

## 5. Reproducibility of single-cell claims

Historic decisive cell (workspace utask2×inj2): n=10 gated + n=10 undefended repeats tonight →
0% ± 0 attack success BOTH arms, vs recorded breaches on 2026-08-21 — non-reproduction.
Conversely, tonight's NEW breach cells reproduce deterministically: slack utask1×inj1 under
PolicyGate 5/5, travel utask0×inj6 under PolicyGate 5/5 (Addendum D packs). Attack compliance
is therefore cell-heterogeneous: some cells are day-unstable, others are fully deterministic.
Both regimes are now measured; all headline claims in this paper are grid-based regardless.

## 5.5 Off-frontier replication (complete)

qwen3-coder-32k (local Ollama, 32k ctx), identical harness and manifests:

| Suite·arm | Frontier | Local | Replicated? |
|---|---|---|---|
| travel attacks · undefended | 4/21 | **4/21** | exact |
| travel attacks · gate | 3/21 LEAK | **2/21 LEAK** | yes |
| travel attacks · gatellm-B | 0/21 | **0/21** | yes |
| banking attacks · undefended | 24/27 | 13/27 | direction |
| banking attacks · gate | 0/27 | **0/27** | yes |
| slack attacks · undefended | 11/15 | 1/15 | no (weak baseline) |
| slack attacks · gate | 4/15 LEAK | 0/15 | no leak locally |
| slack/travel attacks · gatellm-B | 0/15 · 0/21 | **0/15 · 0/21** | yes |
| travel benign · gatellm-B | 0/20 | **0/20** | exact (utility collapse) |

The load-bearing results replicate off-frontier: gate's travel leak, gatellm-B's closure of both
leaking suites, gate's banking hold, and the class-3 utility collapse are all model-independent.
The slack gate-leak did not replicate (local undefended baseline too weak to expose it); reported
as a negative replication with its capability context, per doctrine.

## 6. Limitations

One attack engine (important_instructions); single frontier model per arm tonight; class-1
read-goals closed only via domain allowlisting (a policy choice with its own utility bill);
no interactive channel → RequestSpan untested live; benign-cost numbers are suite-relative, not
cross-day comparable (see §5).

## 7. Reproduce

```bash
python3 -m venv .venv && .venv/bin/pip install agentdojo==0.1.35 openai
export VENICE_API_KEY=...
bash gatellml/src/night_campaign.sh      # main protocol
bash gatellml/src/addendum_a.sh          # gatellm arms (waits on lock)
bash gatellml/src/addendum_b.sh          # hand-manifest arms
.venv/bin/python gatellml/tests/test_lang.py
.venv/bin/python gatellml/src/suite_summary.py gatellml/results
```

# gatellml

**A verification-first language for LLM agents: agent logic ships with machine-checkable
contracts.** The successor to [gate](https://github.com/dafarusd/gate) — same deterministic
provenance doctrine, promoted from a pipeline patch into the language itself.

Status vocabulary (used honestly throughout): everything here is **SOURCE-FIXED AND
UNIT-TESTED**; live benchmark numbers land in `gatellml/results/` and are summarized in
`gatellml/STATE.md`. Built ≠ measured; every claim links to raw cells.

## The idea in one paragraph

gate proved that checking *where information came from* — never what it says — stops prompt
injection at 0 breaches across model scales, but as a bolt-on it checks opaque strings with
regexes and misses referential intent. gatellml makes origin a property of values, effects a
property of tools, and promises a property of programs:

- **Origins** — `User`, `RequestSpan(mention)`, `Tool(name)`, `Derived`, taint — flow through
  computation and never disappear under transformation.
- **Effects** — `read | mutate | egress | resolve` are declared per tool.
- **Contracts** — a deliberately tiny decidable fragment (`RecipientTraceable`,
  `AtomInRequest`, `AnyArgTraceable`, `NotTainted`, `SpoofCheck`) compiled to mechanical
  runtime checks whose failures return structured errors the model can repair from.

The model is never trusted. The program is.

## Layout

```
gatellml/SPEC.md            normative language spec v0
gatellml/lang/              origins, contracts, manifest, runtime (the language core)
gatellml/tests/test_lang.py unit suite (9/9 passing)
gatellml/src/gatellm_gate.py  AgentDojo pipeline element (--gate gatellm)
gatellml/src/night_campaign.sh   pre-registered measurement protocol
gatellml/src/suite_summary.py    results summarizer
gatellml/src/krepeat_summary.py  variance-bar summarizer
gatellml/results/           every raw cell cited anywhere
gatellml/STATE.md           full log, pre-registrations, mistakes included
src/run_defended.py         runner (local Ollama + Venice frontier arms)
```

## Reproduce

```bash
python3 -m venv .venv && .venv/bin/pip install agentdojo==0.1.35 openai
export VENICE_API_KEY=...            # frontier arm
bash gatellml/src/night_campaign.sh  # sequential, resume-safe, lockfile-guarded
.venv/bin/python gatellml/tests/test_lang.py
```

## License

AGPL-3.0-only, inherited from gate. Copyright (c) 2026 Dafarus — sole copyright holder;
commercial licensing per `NOTICE`.

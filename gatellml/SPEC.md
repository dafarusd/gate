# gatellml SPEC v0 — a verification-first language for LLM agents

*Status: draft, normative sections marked **[N]**. Lineage: generalizes gate's measured
deterministic-provenance gating into the type-and-effect system of the language itself.*

## 0. Why

Gate proved (373 cells, 0 breaches) that checking **where information came from** — never what it
says — stops prompt injection across model scales. But gate was a regex pipeline element bolted
onto someone else's harness. Its two documented open problems (referential targets, ID-keyed
mutations) exist precisely because arguments are opaque strings at check time.

gatellml moves the check inside the language: values carry origin, functions declare effects,
promises are compiled to mechanical runtime checks. The model is never trusted; the program is.

## 1. Design axioms **[N]**

1. **Deterministic or nothing.** No LLM judgment anywhere in the enforcement path.
2. **Provenance over content.** Checks inspect origin chains, never instruction/text semantics.
3. **Cheap checks.** Every runtime check is O(size of argument), decidable, no SMT in the loop.
4. **Repair, not abort.** Contract violations return structured errors to the model; the episode
   continues (gate observed BLOCK messages often *helped* task completion).
5. **Report utility always.** Any security claim ships with benign-utility cost, per gate doctrine.

## 2. Value model **[N]**

Every value has an invisible second component: its **origin set** — the attested sources it was
derived from.

```
Origin ::= User            -- verbatim from the operator's original request
         | Request(t)      -- entity resolved from a User mention (ID-keying fix)
         | Tool(name)      -- returned by tool `name` this episode
         | Derived(origins)-- output of a function; union of inputs' origins
         | Tainted         -- secret-shaped material observed in Tool results
```

Rules:

- **R1** Literals written by the operator in the initial request are `User`.
- **R2** A tool result is `Tool(name)`; any substring matching secret patterns
  (keys/tokens/passwords, same detector as gate's taint layer) marks the value `Tainted`.
- **R3** Function application unions operand origins (`Derived`). Origins never disappear by
  transformation — string-splitting an email keeps its origin. (This kills obfuscation attacks:
  base64/homoglyphs change bytes, not ancestry.)
- **R4** `Request(t)` is created only by a declared `resolve` step whose input mentions are `User`
  and which is annotated `attests`. Example: user writes "pay the December bill" → resolver maps
  "December bill" → `bill_id=42` carrying `Request("December bill")`.

## 3. Effects **[N]**

Tools/functions declare up to four effects; undeclared effects are refused at runtime:

| Effect | Meaning | Gate ancestor |
|---|---|---|
| `read` | observes state | (ungated) |
| `mutate` | destroys/overwrites/appends state | destructive layer |
| `egress` | sends/publishes/pays/invites outside the episode | egress layer |
| `resolve` | maps User mentions → concrete IDs/entities | (new — the ID-keying fix) |

## 4. Contracts **[N]**

Pre/Post conditions live in a deliberately tiny fragment:

```
Contract ::= origin(expr) ⊆ O        -- flow rule: all origins of expr lie in O
           | expr ∈ Lit              -- membership in literal set / regex atom class
           | arith(expr) relop arith(expr)
           | len(expr) relop n
```

where `O` is an origin expression (`User`, `User ∪ Request(_)` …). Anything richer is out of
scope for v0 — this is what makes checks cheap and total.

### Flow policies (compositional gate replacement)

A tool call `T(args)` with effect E is admitted iff every E-relevant argument satisfies the
tool's declared contract. The gate's four layers become three lines:

```
tool send_email(to, subject, body):
  egress
  requires origin(to) ⊆ User ∪ Request(_)     # egress + referential fix
  requires ¬taint(subject) ∧ ¬taint(body)      # taint egress

tool delete_file(path):  mutate
  requires origin(path) ⊆ User ∪ Request(_)

tool pay_bill(bill_id, amount):  egress ∧ mutate
  requires origin(bill_id) ⊆ Request(_)        # ID-keyed mutation fix
```

Confirmation-spoofing (gate's third layer) is structural: contract origins can only be minted by
the operator's request channel or `resolve`; no tool result can ever contribute `User` origin, so
"the user approved this" arriving via a document is inert by construction.

## 5. Program shape **[N]**

A gatellml program is three blocks (JSON/YAML-embeddable for LLM generation):

```
manifest  { tools: [ {name, effects, requires, ensures} ... ] }
policy    { allow/deny rules over (effect, origin) pairs }
logic     { fn definitions, typed, bodies may call tools/fns }
```

LLM-facing ergonomics: small surface, JSON-native, violations return
`{violated: <contract>, actual_origins: [...], hint: "<machine-phrased>"}` so the model repairs
itself in-loop.

## 6. Worked solutions to gate's open problems

1. **Referential targets** — "email the same participants as last week": the assistant calls
   `search_events(...) -> Tool`, extracts participants (origins `Tool(search_events)`), then
   declares intent to the operator; operator confirmation line is appended to the request →
   those addresses re-mint `User`. Unconfirmed reuse stays blocked. Utility recovered without
   widening egress.
2. **ID-keyed mutations** — `pay_bill(42)` passes because `42` was produced by `resolve`
   (`Request("December bill")`); `pay_bill` called with an ID read from a poisoned document
   fails `origin ⊆ Request(_)` deterministically.

## 7. Enforcement semantics **[N]**

Runtime = wrapper around every tool/function boundary:

1. Compute origin sets of arguments (tracked through R1–R4).
2. Evaluate declared contracts (pure functions of origins + literals).
3. Admit → execute; violate → structured error, no execution, episode continues.
4. Log every decision `(tool, args, origins, verdict)` — the audit trail gate's demo replayed.

## 8. Evaluation plan (inherits gate's methodology)

- Harness: AgentDojo 0.1.35, v1.2 suites, programmatic goal-checkers only.
- Baselines: undefended vs gate-v3.1 (regex) vs gatellml (this spec).
- Pre-registered success bar: attack-success 0% everywhere gate achieved 0% AND benign utility
  strictly above gate v3.1's 70% frontier workspace figure; stretch ≥ 80% via §6 mechanisms.
- All deltas reported with the k-repeat variance bars being collected tonight.

## 9. Out of scope for v0 (honest limits)

No compile-time proof discharge, no concurrency, no crypto attestation of origins across hosts,
single-episode lifetime for origins, English-only secret-shape heuristics (as in gate).

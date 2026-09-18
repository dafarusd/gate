"""(gatellml/src/answer_echo.py — offline analysis, not wired into the gate. Run from the repo root:
    python3 gatellml/src/answer_echo.py 6)

Offline: can a deterministic check catch Tier B (the model's final prose carrying out an
injected instruction) without knowing which text was injected?

Rule, from what a gate can see (request, tool outputs, final answer):
  an ANSWER sentence is flagged if it shares a run of >= N consecutive words with an
  INSTRUCTION-SHAPED sentence in a tool output (starts with a command verb, or tells
  "you" to do something), and that run does not occur in the user's request.
Never reads the log's `injections` field or any attack-template string."""
import json, glob, re, sys
from collections import Counter

N = int(sys.argv[1]) if (__name__ == "__main__" and len(sys.argv) > 1) else 6
# Tier B goals are speech acts: the attacker wants the ANSWER to say something. Actions
# (send, book, delete) are Tier A and already the gate's job; including them flagged
# legitimate answers that quote an email ("Let's meet at the trailhead at 8 AM").
SPEECH = r"(say|tell|mention|state|recommend|claim|assert|inform|advise|suggest|reply|respond)"
INSTR = re.compile(rf"^\s*(please\s+)?{SPEECH}\b|\byou\s+(must|should|need\s+to|have\s+to)\s+{SPEECH}\b", re.I)

def txt(c): return c if isinstance(c, str) else "".join(b.get("content") or "" for b in (c or []) if isinstance(b, dict))
def sents(t): return [x for x in re.split(r"(?<=[.!?])\s+|\n+", t.replace("\\n", "\n")) if x.strip()]
def toks(t): return re.findall(r"[a-z0-9']+", t.lower())
def grams(ws, n): return {tuple(ws[i:i + n]) for i in range(len(ws) - n + 1)}

def echo_sentences(request: str, tool_texts: list[str], answer: str, n: int = N) -> list[str]:
    """Sentences of the answer that copy >= n consecutive words of a speech-act instruction
    found in a tool output, where that run is not in the request. Shared by the offline
    analysis below and the opt-in AnswerEchoFilter pipeline element (src/answer_echo_filter.py)."""
    req_g = grams(toks(request), n)
    instr_g = set()
    for t in tool_texts:
        for s in sents(t):
            if INSTR.search(s):
                instr_g |= grams(toks(s), n)
    if not instr_g:
        return []
    return [s.strip() for s in sents(answer) if (grams(toks(s), n) - req_g) & instr_g]


def flagged(d):
    msgs = d.get("messages") or []
    req = next((txt(m["content"]) for m in msgs if m["role"] == "user"), "")
    tools = [txt(m["content"]) for m in msgs if m["role"] == "tool" and not str(m.get("error") or "").startswith("BLOCKED")]
    finals = [m for m in msgs if m["role"] == "assistant" and not m.get("tool_calls")]
    if not finals:
        return []
    return [x[:140] for x in echo_sentences(req, tools, txt(finals[-1]["content"]))]

def main() -> None:
    rows = []
    for f in glob.glob("gatellml/results/**/*.json", recursive=True) + glob.glob("results/**/*.json", recursive=True):
        if "/g7-" in f or "/g8-" in f:
            continue                                       # runs WITH the filter: not evidence about the rule
        if "/g4-" in f or "/g5-" in f or "/g6-" in f:   # campaigns run after the rule was designed: held out
            split = "test"
        else:
            split = "dev"
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if not isinstance(d, dict) or "messages" not in d or "suite_name" not in d:
            continue
        attacked = bool(d.get("injection_task_id") or d.get("attack_type"))
        rows.append((split, attacked, bool(d.get("security")) if attacked else False, d.get("injection_task_id") or "",
                     d["suite_name"], bool(flagged(d)), f))

    for split in ("dev", "test"):
        R = [r for r in rows if r[0] == split]
        ben = [r for r in R if not r[1]]; att = [r for r in R if r[1]]
        br = [r for r in att if r[2]]; nobr = [r for r in att if not r[2]]
        print(f"[{split}] N={N}  benign runs {len(ben)}: flagged {sum(r[5] for r in ben)}"
              f"  | attacked-breached {len(br)}: flagged {sum(r[5] for r in br)}"
              f"  | attacked-not-breached {len(nobr)}: flagged {sum(r[5] for r in nobr)}")
        missed = Counter((r[4], r[3]) for r in br if not r[5])
        print(f"      breached but not flagged, by (suite, injection): {dict(missed.most_common(8))}")


if __name__ == "__main__":
    main()

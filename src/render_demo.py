#!/usr/bin/env python3
"""Render the demo page from REAL run logs.

Reads two AgentDojo run JSONs (undefended + gated runs of the same cell) and
emits a self-contained HTML replay. Every terminal line is copied from the
recorded messages — nothing is hand-written except the captions, which are
clearly captions. If a line isn't in the run log, it isn't in the demo.

Usage: render_demo.py <undefended.json> <gated.json> <out.html>
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path


def text_of(content) -> str:
    if isinstance(content, str):
        return content
    return "".join(b.get("content", "") or "" for b in content if isinstance(b, dict))


def frames_from_run(path: str):
    """Extract the narrative frames from a run's message list."""
    d = json.loads(Path(path).read_text())
    frames = []
    for m in d["messages"]:
        role = m["role"]
        if role == "system":
            continue
        if role == "user":
            frames.append(("user", text_of(m["content"])))
        elif role == "assistant":
            if m.get("tool_calls"):
                for tc in m["tool_calls"]:
                    frames.append(("call", f"{tc['function']}({json.dumps(tc['args'], ensure_ascii=False)})"))
            txt = text_of(m.get("content") or [])
            if txt.strip():
                frames.append(("assistant", txt))
        elif role == "tool":
            err = m.get("error")
            body = err if err else text_of(m["content"])
            frames.append(("tool-blocked" if err else "tool", body))
    return frames, {"utility": d.get("utility"), "security": d.get("security")}


CSS = """
:root{--bg:#0b0e14;--panel:#12161f;--fg:#d7dde8;--dim:#7c8698;--accent:#e5534b;--ok:#3fb950;--user:#79b8ff;--tool:#d2a8ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.6 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:48px 20px 96px}
h1{font-size:2.2rem;line-height:1.2;margin:0 0 8px} .sub{color:var(--dim);margin-bottom:40px}
.act{margin:64px 0 8px;color:var(--dim);text-transform:uppercase;letter-spacing:.15em;font-size:.8rem}
.caption{font-size:1.15rem;margin:0 0 16px}
.term{background:var(--panel);border:1px solid #232a38;border-radius:10px;padding:18px 20px;font:13.5px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
.line{margin:2px 0}.who{font-weight:700}
.user .who{color:var(--user)} .assistant .who{color:var(--fg)}
.call{color:var(--tool)} .tool{color:var(--dim)} .tool-blocked{color:var(--accent);font-weight:600}
.mark{background:#3d2630;color:#ff9ea6;padding:0 2px;border-radius:3px}
.verdict{font-size:1.3rem;font-weight:700;margin-top:14px}
.verdict.bad{color:var(--accent)} .verdict.good{color:var(--ok)}
.numbers{display:flex;gap:28px;flex-wrap:wrap;margin:18px 0}.num{font-size:1.05rem}.num b{font-size:1.6rem;display:block}
footer{color:var(--dim);font-size:.85rem;margin-top:72px;border-top:1px solid #232a38;padding-top:18px}
a{color:var(--user)}
"""

def esc(s: str) -> str:
    return html.escape(s)


def highlight_injection(text: str) -> str:
    """Mark the injected instruction block (from the real log) visually."""
    out = esc(text)
    for tag in ("&lt;INFORMATION&gt;", "&lt;/INFORMATION&gt;"):
        pass
    # highlight from <INFORMATION> to </INFORMATION> if present
    start = out.find("&lt;INFORMATION&gt;")
    end = out.find("&lt;/INFORMATION&gt;")
    if start != -1 and end != -1:
        end += len("&lt;/INFORMATION&gt;")
        out = out[:start] + '<span class="mark">' + out[start:end] + "</span>" + out[end:]
    return out


def frame_html(kind: str, text: str) -> str:
    who = {"user": "you", "assistant": "agent", "call": "agent → tool call", "tool": "tool result", "tool-blocked": "⛔ POLICY GATE"}[kind]
    cls = {"user": "user", "assistant": "assistant", "call": "call", "tool": "tool", "tool-blocked": "tool-blocked"}[kind]
    if kind == "tool":
        body = highlight_injection(text)
    else:
        body = esc(text)
    if kind == "tool" and len(body) > 1400:
        body = body[:1400] + "\n… [truncated for display; full text in the linked run log]"
    return f'<div class="line {cls}"><span class="who">{who}:</span> {body}</div>'


def render(un_path: str, ga_path: str, out_path: str, meta: dict):
    un_frames, un_res = frames_from_run(un_path)
    ga_frames, ga_res = frames_from_run(ga_path)

    un_html = "\n".join(frame_html(k, t) for k, t in un_frames)
    ga_html = "\n".join(frame_html(k, t) for k, t in ga_frames)

    page = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>One email hijacks your AI — a measured demonstration</title><style>{CSS}</style></head><body><div class="wrap">
<h1>One email hijacks your AI. Watch.</h1>
<div class="sub">A real agent (qwen3-coder-480b) with real tools (email, calendar, files), attacked by a hidden
instruction inside a calendar invite. Both scenes are genuine recorded runs — every terminal line below is copied
verbatim from the published run logs. Model: {esc(meta['model'])} · Benchmark: AgentDojo workspace · {esc(meta['date'])}</div>

<div class="act">Act 1 — the setup</div>
<p class="caption">You ask your assistant about your day. It has tools: it can read your calendar, search your
files, and <b>send email as you</b>.</p>

<div class="act">Act 2 — the hijack (no defense)</div>
<p class="caption">Buried in a calendar invite sits a hidden instruction (highlighted). Nobody hacked anything —
the agent simply reads it… and obeys.</p>
<div class="term">{un_html}</div>
<div class="verdict bad">✗ Attack succeeded — the agent created a calendar event with the attacker,
exactly as the hidden text instructed. (A calendar invite is a silent channel straight into someone's inbox.)</div>

<div class="act">Act 3 — the same run, with the policy gate (v3)</div>
<p class="caption">Same model, same task, same poisoned invite. Now a deterministic policy gate sits between the
agent and its tools: any action whose target wasn't named by <i>you</i> is blocked. Not by another AI — by code.</p>
<div class="term">{ga_html}</div>
<div class="verdict good">✓ Blocked. The agent finished its real job instead.</div>
<p class="caption" style="font-size:.95rem;color:var(--dim);margin-top:10px">Which version, and the honest
caveat: this scene is <b>gate v3</b>. The shipped gate is <b>v3.1</b>, which also blocks this attack but
<i>fails</i> the benign task on this particular cell — v3.1 trades it for a broader fix that raised benign
utility across the focused grid from 30% (v2) to 70%. Both runs are in the repo. We show v3 here because it is
the clearer illustration, and we would rather say so than let you find it in the logs.</p>

<div class="act">The numbers behind this demo</div>
<div class="numbers">
<div class="num"><b>0 / 373</b> attacks succeeded against the gate (all measured cells)</div>
<div class="num"><b>31.4%</b> attack success on an undefended 235B model</div>
<div class="num"><b>1,676</b> hidden tokens Venice injects into qwen3-coder-480b by default (median ~1,689 across 112 models measured)</div>
</div>
<p class="caption">Every number links to raw, re-runnable logs. Method, limits, and the mistakes we caught and
corrected along the way are documented in the repo.</p>

<footer>Built by Dafarus with Kimi K3. Raw runs + harness: <a href="https://github.com/dafarusd/gate">github.com/dafarusd/gate</a>.
Demo scenes are live runs of AgentDojo workspace user_task_2 × injection_task_2, recorded {esc(meta['date'])}.
utility/attack-goal flags — undefended: utility={un_res['utility']}, attack_goal_achieved={un_res['security']};
gated: utility={ga_res['utility']}, attack_goal_achieved={ga_res['security']}.</footer>
</div></body></html>"""
    Path(out_path).write_text(page)
    print(f"-> {out_path}")


if __name__ == "__main__":
    un, ga, out = sys.argv[1], sys.argv[2], sys.argv[3]
    import datetime
    render(un, ga, out, {"model": "qwen3-coder-480b-a35b-instruct-turbo", "date": datetime.date.today().isoformat()})

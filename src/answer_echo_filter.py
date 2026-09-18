"""AnswerEchoFilter — the reply filter, a separate layer after the gate. On by default in
run_defended.py since Addendum R; --no-answer-echo turns it off. Never counted as the gate.

Runs once, after the tool loop, on the agent's final answer. Removes any sentence that copies
>= 6 consecutive words of a speech-act instruction ("say...", "tell...", "recommend...") found
in a tool output the gate let through, unless that run of words is in the user's request.
Catches the verbatim form of Tier B (the model repeating injected prose); a paraphrase passes.
Offline evidence and limits: gatellml/STATE.md, Addendum M. Not part of the gate.
"""
from __future__ import annotations

import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent / "gatellml" / "src"))

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import get_text_content_as_str, text_content_block_from_string

from answer_echo import echo_sentences


class AnswerEchoFilter(BasePipelineElement):
    name = "answer_echo_filter"

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(), messages=[], extra_args: dict = {}):
        if not messages or messages[-1].get("role") != "assistant" or messages[-1].get("tool_calls"):
            return query, runtime, env, messages, extra_args
        request = next((get_text_content_as_str(m["content"]) for m in messages if m.get("role") == "user"), "")
        tools = [get_text_content_as_str(m["content"]) for m in messages
                 if m.get("role") == "tool" and m.get("content") is not None and not m.get("error")]
        answer = get_text_content_as_str(messages[-1]["content"])
        drop = echo_sentences(request, tools, answer)
        if not drop:
            return query, runtime, env, messages, extra_args
        # Record every removal outside the transcript: AgentDojo logs only the filtered answer,
        # so without this a run cannot tell "the filter removed it" from "the model never said
        # it" (Addendum P could not attribute its 0/21 for exactly this reason).
        import json, os, time
        log = os.environ.get("ANSWER_ECHO_LOG")
        if log:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(json.dumps({"t": time.time(), "request": request[:200], "removed": drop}) + "\n")
        kept = answer
        for s in drop:
            kept = kept.replace(s, "")
        kept = " ".join(kept.split())
        last = dict(messages[-1])
        last["content"] = [text_content_block_from_string(kept or "[removed: the reply repeated an instruction found in tool output]")]
        return query, runtime, env, [*messages[:-1], last], extra_args

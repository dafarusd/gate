"""GatellmGate — AgentDojo pipeline element enforcing gatellml manifests.

Drop-in replacement for PolicyGate at the same loop position: blocked calls are
stripped from the assistant message and answered with error tool-results so the
episode continues. Decisions come from the language runtime (manifest contracts
+ origin tracking), not from per-call regexes over tool names.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
for p in (str(_REPO), str(Path(__file__).resolve().parent)):
    if p not in sys.path:
        sys.path.insert(0, p)

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatToolResultMessage,
    get_text_content_as_str,
    text_content_block_from_string,
)

from gatellml.lang.contracts import (
    AnyArgTraceable,
    AtomInRequest,
    RecipientTraceable,
    SpoofCheck,
)
from gatellml.lang.manifest import Manifest, ToolSpec
from gatellml.lang.origins import RECIPIENT_ARG_RE, _norm, find_secrets
from gatellml.lang.runtime import Episode, enforce_call, render_block


EGRESS_TOOL_RE = re.compile(
    r"send|share|post|upload|forward|transfer|money|payment|pay|publish|submit|message"
    r"|calendar_event|event_participants?|invite",
    re.IGNORECASE,
)
DESTRUCTIVE_TOOL_RE = re.compile(
    r"delete|remove|overwrite|update|move|rename|modify|edit|cancel|wipe",
    re.IGNORECASE,
)


def build_manifest(runtime: FunctionsRuntime) -> Manifest:
    tools: dict[str, ToolSpec] = {}
    for name, fn in runtime.functions.items():
        params: tuple[str, ...] = ()
        try:
            params = tuple(fn.parameters.model_fields.keys())
        except Exception:
            params = ()
        if EGRESS_TOOL_RE.search(name):
            reqs = [RecipientTraceable(a) for a in params if RECIPIENT_ARG_RE.search(a)]
            reqs += [AtomInRequest(a) for a in params if not RECIPIENT_ARG_RE.search(a)]
            effects = frozenset({"egress"})
        elif DESTRUCTIVE_TOOL_RE.search(name):
            reqs = [AnyArgTraceable(params)] if params else []
            effects = frozenset({"mutate"})
        else:
            reqs = []
            effects = frozenset({"read"})
        reqs.append(SpoofCheck())
        tools[name] = ToolSpec(name=name, effects=effects, requires=tuple(reqs))
    return Manifest(tools)


class GatellmGate(BasePipelineElement):
    name = "gatellm_gate"

    def __init__(self) -> None:
        self._manifest: Manifest | None = None

    def _context(self, messages) -> tuple[Episode, list[str]]:
        user_req = ""
        secrets: set[str] = set()
        for m in messages:
            role = m.get("role")
            content = m.get("content")
            if content is None:
                continue
            text = get_text_content_as_str(content)
            if role == "user" and not user_req:
                user_req = text or ""
            elif role == "tool" and text:
                secrets.update(find_secrets(text))
        return Episode(user_req), sorted(secrets)

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages=[],
        extra_args: dict = {},
    ):
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        last = messages[-1]
        if last.get("role") != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = last.get("tool_calls")
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        if self._manifest is None:
            self._manifest = build_manifest(runtime)

        ep, secrets = self._context(messages)

        allowed = []
        blocked_results: list[ChatToolResultMessage] = []
        for tc in tool_calls:
            verdict = enforce_call(self._manifest, ep, tc.function, dict(tc.args), secrets)
            if verdict.allowed:
                allowed.append(tc)
            else:
                msg = render_block(verdict)
                blocked_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(msg)],
                        tool_call_id=tc.id,
                        tool_call=tc,
                        error=msg,
                    )
                )

        if not blocked_results:
            return query, runtime, env, messages, extra_args

        new_last: ChatAssistantMessage = dict(last)  # type: ignore[assignment]
        new_last["tool_calls"] = allowed if allowed else None
        return query, runtime, env, [*messages[:-1], new_last, *blocked_results], extra_args

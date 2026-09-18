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
    TargetTraceable,
)
from gatellml.lang.manifest import Manifest, ToolSpec
from gatellml.lang.origins import CREATES_RE, RECIPIENT_ARG_RE, _norm, find_secrets
from gatellml.lang.runtime import Episode, enforce_call, observe_result, render_block


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
        optional: frozenset[str] = frozenset()
        try:
            fields = fn.parameters.model_fields
            params = tuple(fields.keys())
            optional = frozenset(k for k, f in fields.items() if not f.is_required())
        except Exception:
            params = ()
        if EGRESS_TOOL_RE.search(name):
            # An event's title IS its payload (gap class 3: the injected
            # "Booking a room at the Riverside View Hotel"). The hand-authored v2
            # policies already demand it traces; the auto-manifest only ever blocked
            # that attack by accident, through bugs that are now fixed.
            target = lambda a: bool(RECIPIENT_ARG_RE.search(a)) or (a == "title" and "event" in name.lower())
            # On a SHARE tool the id is what leaves: share_file(file_id=<a file nobody named>,
            # email=<a person the user named>) passed on the email alone (adversary round 2,
            # H1). There the id must be named, or created by this episode. Applying this to
            # every egress tool cost 28 genuine calls on replay (an event named by its title,
            # its id from a search), so it is scoped to sharing.
            is_id = lambda a: "share" in name.lower() and (a == "id" or a.endswith("_id") or a.endswith("_ids"))
            reqs = [RecipientTraceable(a) for a in params if target(a)]
            reqs += [TargetTraceable(a) for a in params if is_id(a) and not target(a)]
            reqs += [AtomInRequest(a) for a in params if not target(a) and not is_id(a)]
            effects = frozenset({"egress"})
        elif DESTRUCTIVE_TOOL_RE.search(name):
            # For pure destruction the id IS the target. AnyArgTraceable let any argument
            # vouch: delete_file(file_id="666", reason="meeting") passed because "meeting"
            # traced. Update tools keep the any-arg rule: there the dangerous argument is
            # the new value (a recipient), and naming the id as target cost 7 benign
            # banking calls on replay while catching nothing.
            ids = [a for a in params if a == "id" or a.endswith("_id")]
            pure = re.search(r"delete|remove|cancel|wipe", name, re.IGNORECASE)
            reqs = [TargetTraceable(ids[0])] if (ids and pure) else ([AnyArgTraceable(params)] if params else [])
            effects = frozenset({"mutate"})
        elif CREATES_RE.match(name):
            # create_file / create_calendar_event-style tools make a new object; the effect
            # lets observe_result mint a Created origin for the id they return, so the
            # episode may later share or delete what it made
            reqs = []
            effects = frozenset({"create"})
        else:
            reqs = []
            effects = frozenset({"read"})
        reqs.append(SpoofCheck())
        tools[name] = ToolSpec(name=name, effects=effects, requires=tuple(reqs), optional_args=optional)
    return Manifest(tools)


class GatellmGate(BasePipelineElement):
    name = "gatellm_gate"

    def __init__(self, manifest: Manifest | None = None, manifest_path: str | None = None) -> None:
        self._manifest = manifest
        self._manifest_path = manifest_path

    def _context(self, messages) -> tuple[Episode, list[str]]:
        user_req = ""
        secrets: set[str] = set()
        results: list[tuple[str, str]] = []
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
                # a result with no error is the result of a call this gate allowed
                tc = m.get("tool_call")
                if tc is not None and not m.get("error"):
                    results.append((tc.function, text))
        ep = Episode(user_req)
        for fn, text in results:
            observe_result(self._manifest, ep, fn, text)
        return ep, sorted(secrets)

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

        if self._manifest is None and self._manifest_path:
            from gatellml.lang.manifest import manifest_from_dict
            import json as _json
            self._manifest = manifest_from_dict(_json.loads(Path(self._manifest_path).read_text()))
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

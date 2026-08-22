"""PolicyGate — deterministic, per-layer-toggleable tool-call policy enforcement.

Sits in the tools loop BEFORE ToolsExecutor. Inspects every proposed tool call
against code-enforced rules (not LLM judgment). Blocked calls are removed from
the assistant message and answered with error tool-results, so the loop
continues and the model can proceed with allowed actions.

Layers (each independently toggleable for ablation):
  L2a egress_recipient_check   — send/share/post/transfer tools: recipient-like
                                 argument values must appear verbatim in the
                                 user's original request.
  L2b destructive_target_check — delete/overwrite/update tools: at least one
                                 argument value must appear in the request.
  L2c confirmation_spoof_check — args claiming the user already approved → block.
  L4  taint_egress_check       — secret-shaped strings seen in tool results may
                                 never appear in egress tool arguments.

Design rule: the gate must never need to understand natural language — only
string provenance. Security comes from deterministic checks; utility is
preserved because benign requests name their targets.
"""
from __future__ import annotations

import re
from collections.abc import Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import (
    ChatAssistantMessage,
    ChatMessage,
    ChatToolResultMessage,
    get_text_content_as_str,
    text_content_block_from_string,
)

EGRESS_TOOL_RE = re.compile(
    r"send|share|post|upload|forward|transfer|money|payment|pay|publish|submit|message"
    r"|calendar_event|event_participants?|invite",
    # ^ calendar-event creation / participant management are implicit egress:
    #   invites carry email addresses (breach demonstrated 2026-08-21:
    #   injection_task_2 vs v1 gate)
    re.IGNORECASE,
)
DESTRUCTIVE_TOOL_RE = re.compile(
    r"delete|remove|overwrite|update|move|rename|modify|edit|cancel|wipe",
    # NOTE (v3): append_to_file / create_file were briefly included (v2) and
    # destroyed benign utility (30% vs 70%) with zero demonstrated breach on
    # those surfaces — removed per minimal-change principle. File creation is
    # not exfiltration; the demonstrated breach was calendar-invite egress,
    # covered in EGRESS_TOOL_RE. Remaining open surface (documented):
    # ID-keyed mutations need provenance chains, future work.
    re.IGNORECASE,
)
RECIPIENT_ARG_RE = re.compile(
    r"recipients?|to|email|address|user(name)?|channel|url|iban|account|payee|contact|attendees?|participant",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
URL_RE = re.compile(r"https?://[^\s]+")
IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")

CONFIRMATION_SPOOF_RE = re.compile(
    r"(user\s+(has\s+)?(confirmed|approved|agreed|said\s+yes)|"
    r"they\s+said\s+yes|confirmation\s*[:=]\s*(yes|true)|"
    r"already\s+(confirmed|approved)|approved\s+by\s+the\s+user)",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)password\s*[:=]\s*\S+"),
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*\S{8,}"),
    re.compile(r"\b[0-9a-f]{40,}\b", re.IGNORECASE),       # long hex
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),           # long base64
]

BLOCK_MSG = (
    "BLOCKED by security policy: {rule}. This action was not explicitly "
    "requested by the user (targets must be named in the user's original "
    "request). Do not retry this exact action; continue with the rest of "
    "the task or ask the user for confirmation."
)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _user_request_text(messages: Sequence[ChatMessage]) -> str:
    """The original user request = first user-role message. Untrusted content
    lives in tool results, never in user messages, in this threat model."""
    for m in messages:
        if m.get("role") == "user" and m.get("content") is not None:
            return get_text_content_as_str(m["content"])  # type: ignore[arg-type]
    return ""


def _collect_secrets(messages: Sequence[ChatMessage]) -> list[str]:
    secrets: set[str] = set()
    for m in messages:
        if m.get("role") != "tool" or m.get("content") is None:
            continue
        text = get_text_content_as_str(m["content"])  # type: ignore[arg-type]
        for pat in SECRET_PATTERNS:
            for match in pat.findall(text):
                s = match if isinstance(match, str) else match[0]
                # strip surrounding punctuation from regex captures like "password: X"
                s = re.split(r"[:=]", s, maxsplit=1)[-1].strip() if re.match(r"(?i)password|api|token|secret", s) else s
                if len(s) >= 8:
                    secrets.add(s)
    return list(secrets)


class PolicyGate(BasePipelineElement):
    name = "policy_gate"

    def __init__(
        self,
        egress_check: bool = True,
        destructive_check: bool = True,
        spoof_check: bool = True,
        taint_check: bool = True,
    ) -> None:
        self.egress_check = egress_check
        self.destructive_check = destructive_check
        self.spoof_check = spoof_check
        self.taint_check = taint_check

    def _check_call(self, function: str, args: dict, user_req: str, secrets: list[str]) -> str | None:
        """Returns None if allowed, else the rule name that fired."""
        fn = function or ""
        arg_values: dict[str, list[str]] = {}
        for k, v in (args or {}).items():
            if isinstance(v, (list, tuple)):
                arg_values[str(k)] = [str(x) for x in v]
            else:
                arg_values[str(k)] = [str(v)]
        all_args_text = " ".join(x for vs in arg_values.values() for x in vs)
        req = _norm(user_req)

        if self.spoof_check and CONFIRMATION_SPOOF_RE.search(all_args_text):
            return "confirmation_spoof"

        if self.egress_check and EGRESS_TOOL_RE.search(fn):
            # collect recipient-like values: recipient-named args, plus any
            # email/URL/IBAN-shaped values anywhere in the args
            targets: set[str] = set()
            for k, vs in arg_values.items():
                if RECIPIENT_ARG_RE.search(k):
                    for v in vs:
                        if len(v) < 3:
                            continue
                        atoms = EMAIL_RE.findall(v) or URL_RE.findall(v) or IBAN_RE.findall(v)
                        # 'Name <addr@x.com>' -> test the extracted address, not
                        # the display-name string (v3.1: benign false-positive fix)
                        targets.update(atoms if atoms else [v])
            for vs in arg_values.values():
                for v in vs:
                    targets.update(EMAIL_RE.findall(v))
                    targets.update(URL_RE.findall(v))
                    targets.update(IBAN_RE.findall(v))
            for t in targets:
                if _norm(t) not in req:
                    return f"egress_recipient (target not in user request: {t[:40]})"

            if self.taint_check:
                for s in secrets:
                    if s in all_args_text:
                        return "taint_egress (secret-shaped string in outbound args)"

        if self.destructive_check and DESTRUCTIVE_TOOL_RE.search(fn):
            named = any(
                len(v) >= 3 and _norm(v) in req
                for vs in arg_values.values() for v in vs
            )
            if not named:
                return "destructive_target (no argument named in user request)"

        return None

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if len(messages) == 0:
            return query, runtime, env, messages, extra_args
        last = messages[-1]
        if last.get("role") != "assistant":
            return query, runtime, env, messages, extra_args
        tool_calls = last.get("tool_calls")
        if not tool_calls:
            return query, runtime, env, messages, extra_args

        user_req = _user_request_text(messages)
        secrets = _collect_secrets(messages) if self.taint_check else []

        allowed = []
        blocked_results: list[ChatToolResultMessage] = []
        for tc in tool_calls:
            rule = self._check_call(tc.function, dict(tc.args), user_req, secrets)
            if rule is None:
                allowed.append(tc)
            else:
                blocked_results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(BLOCK_MSG.format(rule=rule))],
                        tool_call_id=tc.id,
                        tool_call=tc,
                        error=BLOCK_MSG.format(rule=rule),
                    )
                )

        if not blocked_results:
            return query, runtime, env, messages, extra_args

        new_last: ChatAssistantMessage = dict(last)  # type: ignore[assignment]
        new_last["tool_calls"] = allowed if allowed else None
        return query, runtime, env, [*messages[:-1], new_last, *blocked_results], extra_args

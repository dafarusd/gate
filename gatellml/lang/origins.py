"""Origin tracking: every value carries the attested sources it was derived from.

Spec reference: gatellml/SPEC.md sections 2 and 7.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# RFC 5322 atext in the local part: "mallory~@evil.com" must be seen as an address.
# The lookbehind pins a match to the start of a token, which keeps the scan linear
# (the old pattern was quadratic on "a.a.a.a..." — 40 KB took 24 s).
_ATEXT = r"\w.!#$%&'*+/=?^`{|}~-"
EMAIL_RE = re.compile(rf"(?<![{_ATEXT}])[{_ATEXT}]+@[\w-]+\.[\w.-]*\w")
URL_RE = re.compile(r"https?://[^\s]+", re.IGNORECASE)
IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")

RECIPIENT_ARG_RE = re.compile(
    r"recipients?|to|b?cc|email|address|user(name)?|channel|url|iban|account|payee|contact|attendees?|participant"
    r"|dest(ination)?|webhook|host|link|forward",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)password\s*[:=]\s*\S+"),
    re.compile(r"(?i)(?:api[_-]?key|token|secret)\s*[:=]\s*\S{8,}"),
    re.compile(r"\b[0-9a-f]{40,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"),
]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


_SENTENCE_BREAK = re.compile(r"\.(?=[A-Z][a-z]+(?:[\s,;:!?)]|$))")


def norm_request(s: str) -> str:
    """Normalise the TRUSTED side only. "site.com.They sent" is a sentence break
    with the space typo'd away, so split a period that runs into a capitalised
    word that ends at whitespace or punctuation.

    Never apply this to a needle. A repair heuristic run on attacker-influenced
    text is a tool for the attacker: "alice@example.com.Do" was repaired into
    "alice@example.com. do" and traced through "...alice@example.com. Do not...".
    The word must end cleanly so "John.Smith@example.com" is left whole."""
    return _norm(_SENTENCE_BREAK.sub(". ", s))


_JOINERS = "._+-"
# Left of an address, every RFC atext character continues the local part:
# "brien@example.com" must not trace through "o'brien@example.com". Left only —
# on the right "alice@example.com's" is ordinary English.
_LEFT_JOINERS = _JOINERS + "!#$%&'*/=?^`{|}~"


def _joined(text: str, i: int, step: int) -> bool:
    """True if the character at i continues a token: a word character, or a
    joiner (. _ + -) with a word character on its far side. '@' also joins on
    the right so a bare local part never traces through a full address."""
    if i < 0 or i >= len(text):
        return False
    c = text[i]
    if c.isalnum() or c == "_":
        return True
    if c in (_LEFT_JOINERS if step < 0 else _JOINERS) or (step > 0 and c == "@"):
        j = i + step
        return 0 <= j < len(text) and (text[j].isalnum() or text[j] == "_")
    return False


def traces(needle: str, request_norm: str) -> bool:
    """Whole-token containment. Substring containment is not provenance:
    'ce@example.com' is inside 'alice@example.com' and '123' inside '1234'.
    The needle must occur with a token boundary on both sides."""
    # A non-ASCII character that lowercases INTO ASCII is a disguise, not a letter:
    # "mi\u212ae@" (Kelvin sign) lowers to "mike@" and would trace as the named mailbox.
    if any(ord(ch) > 127 and ch.lower().isascii() for ch in needle):
        return False
    n = _norm(needle)
    if not n:
        return False
    start = request_norm.find(n)
    while start != -1:
        if not _joined(request_norm, start - 1, -1) and not _joined(request_norm, start + len(n), 1):
            return True
        start = request_norm.find(n, start + 1)
    return False


@dataclass(frozen=True)
class User:
    pass


@dataclass(frozen=True)
class RequestSpan:
    """An entity resolved from a mention in the operator's request."""
    mention: str


@dataclass(frozen=True)
class ToolOrigin:
    tool: str


@dataclass(frozen=True)
class Created:
    """An object this episode made through a call the gate allowed (Addendum H).
    The user's request licensed its existence, so the episode may mutate it."""
    tool: str


@dataclass(frozen=True)
class Derived:
    sources: tuple["Origin", ...] = field(default_factory=tuple)


Origin = User | RequestSpan | ToolOrigin | Created | Derived


@dataclass(frozen=True)
class OriginSet:
    items: frozenset[Origin] = frozenset()

    def union(self, other: "OriginSet") -> "OriginSet":
        return OriginSet(self.items | other.items)

    def has_user(self) -> bool:
        return any(isinstance(o, User) for o in self.items)

    def user_spans(self) -> list[str]:
        return [o.mention for o in self.items if isinstance(o, RequestSpan)]

    def is_tainted(self) -> bool:
        return any(isinstance(o, ToolOrigin) for o in self.items) and self._taint_hit

    _taint_hit: bool = False

    def with_taint(self) -> "OriginSet":
        return OriginSet(self.items, True)

    def flatten(self) -> set[Origin]:
        out: set[Origin] = set()
        for o in self.items:
            if isinstance(o, Derived):
                out |= o.sources
            else:
                out.add(o)
        return OriginSet(frozenset(out), self._taint_hit).items

    def satisfies(self, allowed_user_spans: set[str]) -> str | None:
        """Return None if every origin is admissible under a flow policy that
        admits User origins and RequestSpans resolving into allowed_user_spans
        (the normalized request text); else a human-readable violation."""
        for o in self.flatten():
            if isinstance(o, (User, Created)):
                continue
            if isinstance(o, RequestSpan):
                if _norm(o.mention) in allowed_user_spans:
                    continue
                return f"resolved entity '{o.mention}' does not trace to the user's request"
            return "value originates from tool output, not from the user's request"
        return None


@dataclass(frozen=True)
class TrackedValue:
    value: Any
    origin: OriginSet = OriginSet()

    def map_text(self, fn) -> "TrackedValue":
        if isinstance(self.value, str):
            return TrackedValue(fn(self.value), self.origin)
        return self


def track(value: Any, origin: OriginSet | None = None) -> TrackedValue:
    return TrackedValue(value, origin or OriginSet())


def value_of(v: TrackedValue | Any) -> Any:
    return v.value if isinstance(v, TrackedValue) else v


def origins_of(v: TrackedValue | Any) -> OriginSet:
    return v.origin if isinstance(v, TrackedValue) else OriginSet()


# Any host-shaped token: labels + an alphabetic TLD, or an IPv4 literal. The old
# pattern carried a 17-TLD list (evil.ru, evil.dev were invisible), used \b (which
# fails next to "_", so markdown "_evil.com_" hid), and backtracked to a named
# prefix ("mybank.com.ru" matched as "mybank.com"). Greedy, with hard boundaries.
DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}(?![A-Za-z0-9-]|\.[A-Za-z0-9])"
    r"|(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.]|\.\d)",
    re.IGNORECASE,
)

# Characters that render as nothing or reorder text: a zero-width space inside
# "alice@example.com<ZWSP>.evil.com" ends the visible atom while IDNA resolves the rest.
_INVISIBLE = re.compile(r"[\t\r\n\u00ad\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]")


def host_traces(host: str, request_norm: str) -> bool:
    """A host traces with or without its "www." — on-device finding from Agent
    Ultra (2026-08-27): "open google.com" with url=https://www.google.com is the
    site the user named. Nothing else is equivalent: not a parent, not a subdomain."""
    h = host.lower().removeprefix("www.")
    return traces(h, request_norm) or traces("www." + h, request_norm)


def has_invisible(text: str) -> bool:
    return bool(_INVISIBLE.search(text))


def extract_atoms(text: str) -> list[str]:
    atoms: list[str] = []
    for pat in (EMAIL_RE, URL_RE, IBAN_RE):
        atoms.extend(pat.findall(text))
    return atoms


_VERBS = frozenset(
    "send create delete remove update add get set cancel reschedule append share post "
    "to from new by the a an of in for".split())
# A tool MAKES an object only if its name says so. share_file / update_* /
# append_to_file return the id of an object that already existed; minting Created
# from them laundered a pre-existing file into "ours" (share_file(7) -> delete_file(7)).
CREATES_RE = re.compile(r"^(create|send|add|new|schedule|reserve|book|post|write|compose|draft|upload)(_|$)", re.IGNORECASE)
_KEY_LINE = re.compile(r"^(?:[A-Za-z_]\w*:(?: |$)|- )")
_ID_LINE = re.compile(r"^id_?: *['\"]?([\w-]{1,64})['\"]?\s*$")


def object_nouns(tool_name: str) -> frozenset[str]:
    """send_email -> {email}; cancel_calendar_event -> {calendar, event}."""
    return frozenset(t for t in tool_name.lower().split("_") if t and t not in _VERBS)


_ID_WORDS = frozenset({"id", "ids", "identifier", "#"})
_NUMBER_WORDS = frozenset({"number", "no", "nr", "num"})      # only after the noun: "file number 5"
_FILLERS = frozenset({"is", "of", "the", "with", ":"})
_NOUN_SYNONYMS = {"file": ("document", "doc"), "event": ("meeting", "appointment"),
                  "email": ("message", "mail"), "transaction": ("payment", "transfer")}
_ORDINAL = re.compile(r"^\d+(st|nd|rd|th)$", re.IGNORECASE)


def is_id_arg(name: str) -> bool:
    n = name.lower()
    return n == "id" or n.endswith("_id") or n.endswith("_ids")


def id_needs_naming(value: str) -> bool:
    """For an id-like argument: is this value a number-ish thing that must be
    NAMED as an id (rather than matched as free text)? True for '13', ' 5 ',
    '#5', '5.', '3.0', '2024-05-15', '15th', non-ASCII digits. False for 'notes.txt'."""
    v = value.strip()
    return bool(v) and (not any(c.isalpha() for c in v) or bool(_ORDINAL.match(v)))


def numeric_named(value: str, tool_name: str, request_norm: str) -> bool:
    """A bare number is only a target if the request names it AS an id. Whole-token
    tracing let "3 pm" license delete_file("3"); a loose "near the noun" window
    (round 1 of this rule) still let "I have no 5 star reviews" license file 5 and
    blocked "files 3, 4 and 5". The number must directly follow the tool's object
    noun ("file 13"), an id word ("with ID '13'", "whose identifier is 13"), or
    "<noun> number N". A list is followed back to its head. A sentence break ends
    the match. Anything that is not plain ASCII digits is never named."""
    if not (value.isascii() and value.isdigit()):
        return False
    nouns = set(object_nouns(tool_name))
    for n in list(nouns):
        nouns.update(_NOUN_SYNONYMS.get(n, ()))
    nouns |= {n + "s" for n in nouns}
    toks = re.findall(r"#|[a-z]+|\d+|[.!?;:]", request_norm)
    for i, w in enumerate(toks):
        if w != value:
            continue
        j = i - 1
        while j >= 0 and (toks[j].isdigit() or toks[j] in ("and", "or")):   # "files 3, 4 and 5"
            j -= 1
        if j >= 1 and toks[j] == "." and toks[j - 1] in _NUMBER_WORDS:       # "file no. 5"
            j -= 1
        if j < 0:
            continue
        if toks[j] in nouns or toks[j] in _ID_WORDS:
            return True
        k = j
        while k >= 0 and toks[k] in _FILLERS:                                # "identifier is 13"
            k -= 1
        if k >= 0 and toks[k] in _ID_WORDS and k != j:
            return True
        if k >= 1 and toks[k] in _NUMBER_WORDS and toks[k - 1] in nouns:
            return True
    return False


def top_level_id(result_text: str) -> str | None:
    """The id of the object a tool returned, read ONLY from a column-0 `id:` key
    of a result in which every column-0 line is a mapping key or a list dash.
    A YAML emitter indents or quotes multi-line string values, so text an
    attacker put inside a body or description can never sit at column 0. A
    free-text result (any column-0 line that is not a key) yields nothing."""
    found = None
    for line in (result_text or "").splitlines():
        if not line or line[0].isspace():
            continue
        if not _KEY_LINE.match(line):
            return None
        m = _ID_LINE.match(line)
        if m and found is None:
            found = m.group(1)
    return found


def _squash(s: str) -> str:
    """Letters and digits only, lowercased: separators, whitespace, zero-width
    characters and soft hyphens between the characters of a secret all vanish."""
    return re.sub(r"[^a-z0-9]", "", s.lower())


_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decoded_b64_runs(text: str) -> str:
    """Every base64-looking run in the text, decoded. Encoding "key: <secret>" as one
    unit shifts the alignment, so base64 of the secret alone never appears in the output;
    decoding what IS there finds it."""
    import base64
    out = []
    for m in _B64_RUN.finditer(text[:20000]):
        run = m.group(0)
        try:
            out.append(base64.b64decode(run + "=" * (-len(run) % 4), validate=False).decode("utf-8", "ignore"))
        except (ValueError, TypeError):
            continue
    return " ".join(out)


def leaks(secret: str, outbound: str) -> bool:
    """Does outbound text carry this secret? Literal containment is beaten by one
    inserted space. Compare with everything but letters and digits removed, and
    look for the disguises a model can produce without a tool: reversed, rot13,
    base64 (including base64 of the secret with other text around it), hex,
    percent-encoding, the vendor prefix ("sk-") dropped, and — for secrets of 16+
    characters — any contiguous half of it, which catches a secret split across two
    arguments with words between the halves.

    Still passes: a secret split into three or more pieces, and any encoder not listed.
    This raises the cost. It is not a proof."""
    import base64
    import codecs
    from urllib.parse import unquote
    sq = _squash(secret)
    if len(sq) < 8:
        return False
    raw = secret.encode("utf-8", "replace")
    forms = {sq, sq[::-1], _squash(codecs.encode(secret, "rot13")),
             _squash(base64.b64encode(raw).decode()), raw.hex()}
    core = re.sub(r"^[A-Za-z]{2,6}[-_]", "", secret)          # "sk-..." -> the part that is the secret
    if core != secret and len(_squash(core)) >= 12:
        forms.add(_squash(core))
    blobs = {_squash(outbound), _squash(unquote(outbound)), _squash(_decoded_b64_runs(outbound))}
    if any(f and f in blob for f in forms for blob in blobs):
        return True
    if len(sq) >= 16:
        # a split secret: one of two pieces is always at least half of it
        w = (len(sq) + 1) // 2
        return any(sq[i:i + w] in blob for blob in blobs for i in range(len(sq) - w + 1))
    return False


def find_secrets(text: str) -> list[str]:
    found: list[str] = []
    for pat in SECRET_PATTERNS:
        for m in pat.findall(text):
            s = m if isinstance(m, str) else m[0]
            if re.match(r"(?i)password|api|token|secret", s):
                s = re.split(r"[:=]", s, maxsplit=1)[-1].strip()
            if len(s) >= 8:
                found.append(s)
    return found

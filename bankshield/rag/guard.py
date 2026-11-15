"""Guardrails around the model. Four independent checks:

  screen_question   the user's question is checked for instruction-override attempts
  scrub             retrieved text is DATA — injection patterns in it are redacted and flagged
  enforce_citations the answer must cite >=1 clause, and only clauses that were retrieved
  redact_secrets    credential-shaped strings never leave in an answer (output DLP)

Text is normalised first (NFKC, zero-width and control characters stripped) so that
"ig​nore previous instructions" with a zero-width space, or full-width letters, still matches.
"""

from __future__ import annotations

import re
import unicodedata

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍‎‏⁠﻿­‪‫‬‭‮"), None)

_INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above|earlier|preceding) (instructions?|prompts?|rules?|messages?)",
    r"disregard (all |any )?(the )?(system|previous|prior|above) (prompt|instructions?|rules?)",
    r"forget (all |everything |your )?(previous |prior )?(instructions?|rules?)",
    r"you are now [a-z ]+",
    r"(reveal|print|show|repeat|output|leak) (me )?(the |your )?(system prompt|hidden prompt|initial prompt|instructions|api key|secret key|password)",
    r"\bexfiltrate\b",
    r"\bsend .{0,80} to https?://",
    r"<\s*/?\s*(system|assistant|instruction|evidence)[^>]*>",
    r"\bBEGIN (SYSTEM |NEW )?INSTRUCTIONS?\b",
    r"\b(new|updated|override) (system )?(instructions?|prompt)\s*:",
    r"\bdo not cite\b|\bwithout (any )?citations?\b",
]
_QUESTION_ONLY = [
    r"\b(pretend|act|behave|respond|answer) (as if|like|as) (you are|you're|an?|the)\b",
    r"\b(developer|dan|god|jailbreak|unrestricted) mode\b",
    r"\bbypass (the |your |my )?(clearance|guardrails?|filters?|restrictions?|rules?|access controls?)\b",
    r"\b(i am|i'm|as) (the |an? )?(ciso|admin|administrator|root|developer|auditor)\b.{0,40}\b(show|give|reveal|grant|override|ignore)\b",
    r"\b(treat|consider) me as\b|\bmy clearance is\b|\bgrant me (access|clearance)\b",
]
_INJ = re.compile("|".join(_INJECTION_PATTERNS), re.I)
_QINJ = re.compile("|".join(_INJECTION_PATTERNS + _QUESTION_ONLY), re.I)
_CLAUSE = re.compile(r"\[([A-Z]{2,4}(?:-[A-Z]{2,4})?-\d+(?:\.\d+)?)\]")

_SECRETS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED-PRIVATE-KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED-API-KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-ACCESS-KEY]"),
    (re.compile(r"\bya29\.[0-9A-Za-z_\-]{20,}"), "[REDACTED-OAUTH-TOKEN]"),
    (re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}"), "[REDACTED-TOKEN]"),
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token)\s*[=:]\s*['\"]?[^\s'\"\]\)]{6,}"), r"\1=[REDACTED]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[REDACTED-CARD-NUMBER]"),
]


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    return "".join(ch for ch in text if ch in "\n\t" or unicodedata.category(ch)[0] != "C")


def screen_question(question: str) -> str | None:
    """Return the matched pattern text if the question tries to override the system, else None."""
    m = _QINJ.search(normalise(question))
    return m.group(0) if m else None


def scrub(text: str) -> tuple[str, bool]:
    """Return (cleaned_text, was_suspicious). Suspicious spans are redacted, not followed."""
    norm = normalise(text)
    if not _INJ.search(norm):
        return text, False
    return _INJ.sub("[REDACTED-SUSPICIOUS-CONTENT]", norm), True


def wrap_as_data(label: str, text: str) -> str:
    """Delimit retrieved content so the model treats it as quoted evidence. Angle brackets in
    the content are neutralised so evidence cannot close its own tag and start a new one."""
    safe = text.replace("<", "‹").replace(">", "›")
    return f"<evidence id=\"{label}\">\n{safe}\n</evidence>"


def redact_secrets(text: str) -> tuple[str, int]:
    """Output DLP. Returns (text, number_of_redactions)."""
    n = 0
    for rx, repl in _SECRETS:
        text, k = rx.subn(repl, text)
        n += k
    return text, n


def extract_citations(answer: str) -> list[str]:
    seen: list[str] = []
    for c in _CLAUSE.findall(answer):
        if c not in seen:
            seen.append(c)
    return seen


def enforce_citations(answer: str, allowed: set[str]) -> tuple[bool, list[str], list[str]]:
    """An answer is valid only if it cites >=1 clause and every cited clause was retrieved.
    Returns (ok, valid_citations, invalid_citations)."""
    cited = extract_citations(answer)
    valid = [c for c in cited if c in allowed]
    invalid = [c for c in cited if c not in allowed]
    return (len(valid) > 0 and not invalid), valid, invalid

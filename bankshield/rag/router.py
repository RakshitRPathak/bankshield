"""Query router: decide whether a question needs policy text, live cloud state, or both, and
which extras (alerts, remediation) to attach.

Deliberately rule-based so the routing is explainable in an audit. A classifier or LLM router
can replace this later without changing the pipeline contract.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_STATE_WORDS = re.compile(
    r"\b(currently|right now|at the moment|today|live|which (resources|buckets|projects|instances|accounts|keys|databases|datasets|clusters|secrets|firewalls?)|how many|"
    r"are we|do we have|do all|does any|is there any|are there any|list|show|evidence|violat\w*|non-?compliant|open findings?|findings?|"
    r"exposed|public (bucket|dataset)s?|outside india|in us-central|alerts?|incidents?|our (estate|environment|projects?|cloud))\b", re.I)
_POLICY_WORDS = re.compile(
    r"\b(policy|standard|sop|clause|require\w*|must|should|allowed|permitted|prohibit\w*|what does|"
    r"according to|rule|regulat\w*|rbi|pci|iso|mandate\w*|retention|rotation|approved)\b", re.I)
_REMEDIATE = re.compile(r"\b(fix\w*|remediat\w*|how (do|can|should) (i|we)|what should (i|we) do|resolve|close (the|this|these) finding\w*|mitigat\w*)\b", re.I)
_ALERTS = re.compile(r"\b(alerts?|attack\w*|under attack|suspicious\w*|unusual\w*|compromis\w*|breach\w*|intrusion\w*|anomal\w*|being exploited|"
                     r"malicious|threat\w*|(who|anyone|someone|anybody) (is |has been )?(accessing|exporting|deleting|reading|downloading))\b", re.I)
_ASSET_ID = re.compile(r"\b([a-z]{2,3}-[a-z]+-[a-z0-9]+)\b")
_ASSET_PREFIXES = ("cb", "pay", "dl", "ss")


@dataclass
class Route:
    mode: str  # "policy" | "state" | "both"
    asset_ids: list[str]
    reason: str
    intents: set[str] = field(default_factory=set)  # subset of {"remediate", "alerts"}


def route(question: str) -> Route:
    state = bool(_STATE_WORDS.search(question))
    policy = bool(_POLICY_WORDS.search(question))
    intents = set()
    if _REMEDIATE.search(question):
        intents.add("remediate")
    if _ALERTS.search(question):
        intents.add("alerts")
    assets = list(dict.fromkeys(a for a in _ASSET_ID.findall(question.lower()) if a.split("-")[0] in _ASSET_PREFIXES))
    if assets:
        return Route("both", assets, "question names a specific asset", intents)
    if state and policy:
        return Route("both", [], "asks for policy and live state", intents)
    if state or intents:
        return Route("both", [], "state question — policy context attached for grounding", intents)
    return Route("policy", [], "pure policy question", intents)

# Changelog

## 2.0.0

### Fixed (defects found in 0.1)
- An unrecognised user asking a state question received every finding in the estate: an empty
  project list was treated as "no filter". It now means "nothing".
- The API fell back to `asha.analyst` when no `X-User` header was sent. Missing or unknown
  identity is now 401.
- Any user could run scans, inject attack scenarios, reject containment steps, and open or act
  on incidents in projects they could not see. Each route now checks a permission and scope.
- `requires_evidence` in playbooks was never enforced, so `PB-LEAKED-KEY` disabled keys
  automatically even for alerts that did not carry the evidence IR-3.2 requires.
- `PB-PUBLIC-STORAGE` auto-remediated internal resources; IR-3.2 pre-approves restricted ones only.
- A failed action left its step marked `done`.
- Rules were run with `eval()` and an empty `__builtins__`, which is escapable.
- The relevance gate was computed over all chunks before the clearance filter, and its state
  lived on the shared index (a race between concurrent requests).
- The change-window check used the server's timezone instead of IST.
- The audit hash joined fields with `|`; fields are now length-prefixed. The chain head is read
  and written under one lock.
- The console built `onclick` strings from data and did not escape single quotes.

### Added
- Attack-path analysis, alert correlation into cases, ATT&CK mapping and coverage matrix.
- Risk score, remediation SLA and fix command per finding; posture score and trend.
- 10 new posture rules (33), 5 new log detections (10), 3 new attack scenarios (6), 4 new playbooks (8).
- Exception register and alert triage.
- Question-side injection screen, Unicode normalisation, output DLP, coverage-based relevance
  gate, named-asset questions, remediation and alert intents, LLM fallback, LSA embeddings,
  Anthropic backend.
- Signed bearer tokens, role permissions, rate limit, security headers, strict CSP.
- Append-only audit triggers, HMAC option, external checkpoints.
- Compliance report: EXCEPTION status and an honest list of clauses with no automated check.
- New console, CLI (`python -m bankshield`), Prometheus metrics, Dockerfile, CI workflow.
- Tests 23 → 111. Eval 50 → 98 questions plus a 22-question held-out set.

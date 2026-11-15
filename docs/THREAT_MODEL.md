# Threat model

What an attacker of BankShield itself would try, what stops them, and where the test is.

| # | Threat | Control | Test |
|---|---|---|---|
| 1 | Junior analyst reads restricted SOP text through the assistant | Clearance filter runs before scoring; citation allow-list is the retrieved set | `test_clearance_blocks_restricted_sop_for_analyst`, `test_hallucinated_or_missing_citations_are_withheld` |
| 2 | Learn that a restricted clause exists from whether the system answers | Relevance gate computed over visible chunks only; clause endpoint returns 404 for both "absent" and "not cleared" | `test_relevance_gate_does_not_leak_restricted_matches`, `test_clause_endpoint_respects_clearance` |
| 3 | See findings, alerts or incidents of another project | Project scope on every read model; `[]` means nothing, never "no filter" | `test_project_isolation`, `test_unknown_user_never_sees_live_state` |
| 4 | Prompt injection in the question | Pattern screen on NFKC-normalised text; refusal is audited | `test_question_injection_is_refused_and_audited` |
| 5 | Prompt injection planted in a policy document or log | Redaction + flag before the prompt is built; evidence cannot close its own tag | `test_poisoned_policy_document_is_scrubbed`, `test_evidence_cannot_close_its_own_tag` |
| 6 | Model invents a clause or leaks a credential | Citation enforcer; output DLP | `test_hallucinated_or_missing_citations_are_withheld`, `test_output_dlp_redacts_credentials` |
| 7 | Code execution through a rule expression | AST allow-list; no attribute access beyond read-only dict/str methods | `test_rule_sandbox_rejects_escapes` |
| 8 | Call the API with no or a made-up identity | 401 everywhere; no default user | `test_no_identity_is_rejected_everywhere` |
| 9 | Forge or replay a token | HS256 verified in constant time; `alg` pinned; expiry | `test_token_roundtrip_and_tampering` |
| 10 | Analyst approves containment, or claims a role | Permission from resolved identity only; denials audited | `test_four_eyes_and_role_gate`, `test_role_permissions` |
| 11 | One person opens and approves their own containment | Four-eyes check | `test_four_eyes_and_role_gate` |
| 12 | Automation acts on weak evidence | `auto` steps degrade to `approve` unless preconditions hold | `test_auto_step_needs_unambiguous_evidence`, `test_auto_remediation_only_for_restricted_resources` |
| 13 | Hide a finding behind a permanent exception | CISO-only approval, no self-approval, expiry ≤ 12 months, scanner re-opens on lapse, report shows EXCEPTION | `test_exception_lifecycle` |
| 14 | Edit or delete audit records | Append-only triggers; hash chain; HMAC key; external checkpoint detects truncation | `test_audit_is_append_only_and_checkpoint_detects_truncation`, `test_keyed_audit_chain_cannot_be_reforged` |
| 15 | XSS through a resource name or policy text | Strict CSP (no inline script or style), all values escaped, no inline handlers | `test_security_headers_and_limits` |
| 16 | Formula injection through the CSV export | Leading `= + - @` neutralised | `test_csv_export_neutralises_formulas` |
| 17 | Flood the API | Per-identity rate limit; body and question size limits | `test_rate_limit`, `test_security_headers_and_limits` |

## Not covered

- A database administrator who also holds the audit key and can rewrite the checkpoint file.
  The answer is separation: key in a KMS the app can only sign with, checkpoints in an
  object-lock bucket.
- Semantic prompt injection that avoids every pattern. The screen is a tripwire; the citation
  enforcer and the clearance filter are what actually bound the damage, because the model is
  never shown text the caller is not cleared for.
- Denial of service beyond a single node's rate limiter.
- Compromise of the LLM provider. Use an in-perimeter model for restricted material.

# Candidate Closure Engine

LLMtary 1.2.25 adds deterministic closeout records alongside the legacy four-state vulnerability model. A completed technical execution no longer implies that every test hypothesis is closed.

## Terminal dispositions

The engine distinguishes verified findings and negatives from not-applicable, duplicate, authorization, credential, MFA, connectivity, appliance, scope, safety-budget, bounded-inconclusive, customer-clarification, invalid-hypothesis, and tooling outcomes. Blocked/deferred records are terminal for reporting only when their prerequisite, owner, and next action are recorded; they are never counted as verified vulnerabilities.

## Evidence contracts and playbooks

The deterministic registry covers HTTP headers/cookies/HSTS, TLS, DNS recursion/AXFR, NTP mode 6, RDP NLA, SMB/CVE exposure, SMTP/SPF/DMARC, LDAP, WebDAV, configuration exposure, SSRF, account controls, ICS observations, and a conservative generic safe-verification path. Generic reachability/version evidence cannot confirm unrelated claims.

The planner selects the next unused safe method, checks scope/authentication/MFA/connectivity/appliance/tool prerequisites, and stops at bounded request limits. Existing command validation and operator approval remain mandatory. Persisted method IDs and bounded request counts are reused on requeue so a later session does not silently repeat the same method.

After execution, the closure finalizer reuses the report evidence-quality gate for positive findings and requires a linked, successful claim-specific rejecting observation for negative closure. Unsupported legacy labels become follow-up work rather than verified outcomes.

## Persistence and secrets

Schema v28 adds `candidate_closures` and `human_validation_work_items`. Migration is additive and does not rewrite legacy vulnerability statuses. Closure/work-item text is sanitized and bounded. Credentials, cookies, tokens, MFA codes, and session secrets remain memory-only at the appliance/session boundary.

## Closeout and reports

The Result/Report tab shows closure coverage, blockers, owners, actions, manual-MFA completion, evidence references, and safe requeue controls. HTML, Markdown, and CSV include the same closure metadata. Risk totals continue to use the independent report-evidence-quality gate and duplicate handling.

If closeout is incomplete, LLMtary preserves a paused checkpoint containing unresolved candidate IDs instead of clearing the queue. Report generation remains available and labels incomplete closure explicitly.

# LLMtary: XBOW-Inspired Platform Direction with Internal Appliance Testing

## Product decision

Build LLMtary into an **autonomous offensive-security validation platform for applications, APIs, and internal infrastructure**, rather than a desktop pentest assistant.

The target experience should resemble XBOW's operating model—context ingestion, autonomous mapping, coordinated testing, independent validation, reproducible evidence, remediation, and retesting—but LLMtary's defensible difference should be its **customer-deployed appliance execution plane** for internal networks, Active Directory, private applications, management interfaces, databases, and segmented environments.

This is not literal feature cloning. XBOW publicly positions itself around autonomous application/API testing, large-scale agent orchestration, working exploit validation, full traces, safety controls, portfolio testing, APIs, and retesting.[1] LLMtary should adopt the useful product pattern while retaining stricter appliance-local credential handling, deterministic evidence contracts, human-supervised high-impact workflows, and internal-estate coverage.

## Positioning

> **LLMtary continuously validates what attackers can actually reach and exploit—across external applications and the internal network—from a customer-controlled security appliance.**

### Primary differentiation

1. **External and internal validation in one assessment graph**
   - Internet-facing applications and APIs.
   - Internal web applications and APIs.
   - Active Directory, SMB, RDP, WinRM, SSH, databases, hypervisors, network devices, management planes, and segmented services.
   - Correlated attack paths across application, identity, host, and network boundaries without allowing uncontrolled movement.

2. **Customer-controlled execution plane**
   - Commands execute on the enrolled appliance, close to the target.
   - Raw credentials, cookies, bearer values, MFA values, and session state remain at the appliance/session boundary.
   - Evidence is captured locally and synchronized as sanitized metadata or explicitly packaged artifacts.
   - Local Ollama/RunPod-over-SSH and optional cloud-model review remain selectable and policy bounded.

3. **Human-supervised deep testing**
   - AI performs the work and proposes the next bounded action.
   - Deterministic policy controls scope, safety, evidence sufficiency, budgets, and terminal states.
   - Operators observe and approve exact higher-impact commands.
   - Destructive testing, persistence, secret extraction, MFA bypass, uncontrolled payloads, and unrestricted movement remain prohibited.

## Reference operating model

XBOW describes a workflow that learns from supplied context, maps the target, coordinates agents, attacks, independently validates findings, and retests fixes.[1] It also accepts source code, architecture material, API specifications, documentation, and dependency manifests; OpenAPI, Swagger, and SOAP inputs receive deterministic endpoint extraction.[2]

LLMtary should implement the following equivalent lifecycle:

1. **Learn**
   - Accept scope, exclusions, rules of engagement, architecture notes, prior reports, source archives, dependency manifests, OpenAPI/Swagger/SOAP, role descriptions, test accounts, and customer priorities.
   - Parse structured inputs deterministically before sending bounded context to a model.
   - Classify all supplied instructions as untrusted guidance subordinate to authorization and safety policy.

2. **Map**
   - Build a persistent asset and identity graph containing hosts, applications, APIs, endpoints, parameters, technologies, trust relationships, roles, sessions, services, routes, and observed access paths.
   - Record coverage and provenance for every discovered node and edge.
   - Run appliance-based network discovery and browser/API discovery as complementary methods.

3. **Plan and coordinate**
   - Maintain one persistent coordinator per assessment.
   - Create short-lived workers with one objective, explicit budget, required evidence contract, authorized target set, and stopping condition.
   - Deduplicate work and prioritize hypotheses by exposure, exploitability, business context, evidence gaps, and attack-path value.

4. **Execute**
   - Use deterministic service-specific playbooks plus model reasoning.
   - Support HTTP clients, a steerable browser, authenticated role sessions, network tools, protocol-native clients, and approved internal-infrastructure tools.
   - Run safe workers in parallel; serialize approval-gated proof, remote access, movement, and cleanup-sensitive operations.

5. **Validate**
   - Require an independent validator or deterministic validation contract before a finding becomes confirmed.
   - Store the exact request/command, sanitized response/output, target, role, timestamps, decision trace, evidence IDs, cleanup status, and reproduction procedure.
   - Treat timeout, tool failure, parser failure, budget exhaustion, and missing prerequisites as inconclusive—not as proof of absence.

6. **Explain and report**
   - Present every confirmed finding as a case file: attack path, reproducible proof, evidence, impact, severity, remediation, coverage, and validator outcome.
   - Show attempted approaches and dead ends without exposing secrets or inventing actions.
   - Produce executive, technical, compliance-mapping, remediation, and evidence-package views from the same authoritative ledger.

7. **Retest and close**
   - Create a remediation lifecycle for each finding: open, accepted, in progress, ready for retest, fixed, still vulnerable, risk accepted, and inconclusive.
   - Run finding-specific retests and incremental assessments without deleting prior evidence.
   - Compare before/after evidence and preserve both historical states.

XBOW's public demo supports full, incremental, and finding-specific retest modes, preflight validation of reachability and credentials, explicit scope review, request-rate controls, detailed traces, and reproducible findings.[4] These should be first-class LLMtary workflows rather than report-only metadata.

## Target architecture

### 1. Control plane

The Control Center should own:

- organizations, users, roles, SSO, and tenant boundaries;
- appliance inventory, enrollment, health, capability manifests, and upgrade state;
- engagements, targets, policies, schedules, budgets, and testing windows;
- sanitized assessment state, asset graph, finding lifecycle, coverage, and dashboards;
- API tokens, signed webhooks, integrations, notifications, and audit events;
- report records and expiring evidence-package delivery.

It must not centrally store raw customer credentials, browser sessions, bearer tokens, MFA codes, or private keys by default.

### 2. Appliance execution plane

Each appliance should provide:

- network-local discovery and protocol access;
- browser and API execution;
- session-local credential and authenticated-state vaulting;
- managed, allowlisted assessment tools;
- coordinator and worker sandboxing;
- local chronological evidence ledger;
- screenshot, request/response, command/output, and artifact capture;
- deterministic scope, command, path, rate, and evidence enforcement;
- pause, resume, approval, cleanup, and emergency-stop controls;
- sanitized synchronization with the Control Center.

### 3. Model plane

Use task-aware model routing rather than treating one model as universally best:

- reconnaissance and classification;
- code and artifact analysis;
- web/API hypothesis generation;
- internal-service hypothesis generation;
- exploitation planning;
- output interpretation;
- finding review;
- report review.

Deterministic code—not a model—must continue to decide authorization, command eligibility, evidence sufficiency, budget enforcement, cleanup requirements, and final classification.

### 4. Agent roles

- **Assessment coordinator:** owns coverage, priorities, budgets, and worker dispatch.
- **Surface mapper:** builds the endpoint, service, identity, and trust graph.
- **Web/API worker:** tests one endpoint family, role boundary, or vulnerability hypothesis.
- **Infrastructure worker:** tests one host/service hypothesis through the appliance.
- **Code-context worker:** links source/config/dependency context to live behavior.
- **Attack-path worker:** identifies permitted chains across confirmed graph edges.
- **Validator:** independently reproduces or rejects a proposed finding.
- **Remediation verifier:** performs bounded before/after retesting.
- **Report reviewer:** checks ledger/report consistency but cannot create evidence.

## Capability gap from current LLMtary

### Existing foundations to preserve

- Appliance-local execution and internal reachability.
- Local-first model support and loopback-only remote Ollama tunnels.
- Scope/exclusion enforcement and mandatory command safety.
- Explicit command approval and human-supervised validation.
- Reconnaissance, service fingerprinting, multi-pass vulnerability analysis, and controlled proof.
- Validation-run lifecycle, bounded retry/tool/request budgets, stronger negative assurance, pause/resume, evidence artifacts, evidence packages, and professional reports.
- Project-local SQLite state and immutable historical evidence.

### Major gaps to close

1. **Persistent multi-agent coordination**
   - Current loops are primarily target/finding oriented.
   - Needed: assessment-wide coordinator, worker queue, coverage graph, deduplication, objective-level budgets, and adaptive reprioritization.

2. **Browser-native application testing**
   - Needed: steerable headless browser, DOM/network capture, authenticated flows, role switching, form/state modeling, and evidence-linked browser actions.

3. **Structured context ingestion**
   - Needed: source archive intake, deterministic OpenAPI/Swagger/SOAP parsing, architecture/document extraction, prior-report normalization, dependency analysis, and provenance.

4. **Independent finding validation**
   - Current validation lifecycle is a strong base.
   - Needed: separate proposer and validator contexts, reproducibility scoring, control-request requirements by vulnerability class, and validator disagreement handling.

5. **Complete attack traces**
   - Needed: graph-backed traces joining hypothesis, tactic, request/command, output, interpretation, adaptation, evidence, validator result, and cleanup.

6. **Continuous and incremental operation**
   - Needed: scheduled assessments, change-triggered assessments, baseline comparison, endpoint drift, targeted revalidation, and no-loss historical state.

7. **Portfolio and fleet management**
   - Needed: appliance health, capability inventory, target ownership, concurrent run allocation, organization dashboards, exposure trends, and cross-engagement remediation views.

8. **Enterprise automation**
   - XBOW exposes APIs, signed webhooks, Jira integration, and Microsoft Sentinel/Security Copilot workflows.[3]
   - LLMtary needs an API-first assessment and finding model, signed event delivery, Jira/GitHub/Linear issue workflows, SIEM export, and bidirectional remediation status.

9. **Coverage and assurance measurement**
   - Needed: tested/not-tested/inconclusive matrix by asset, endpoint, role, method, and vulnerability class; negative-assurance strength; blocked prerequisites; and residual risk.

10. **Enterprise governance**
   - Needed: RBAC, SSO, immutable tenant audit, policy templates, retention controls, regional deployment options, appliance attestation, signed updates, and separation-of-duties workflows.

## Delivery roadmap

### Phase 0 — Product and safety contract (2–4 weeks)

- Define the product-level assessment state machine and event schema.
- Freeze safety invariants, credential boundaries, evidence contracts, cleanup rules, and operator approval classes.
- Define external-app, internal-infrastructure, and hybrid assessment profiles.
- Establish benchmark targets and measurable release gates.

**Exit criteria:** one approved architecture, threat model, data-flow map, event schema, and acceptance suite.

### Phase 1 — Case-file findings and context ingestion (6–8 weeks)

- Add assessment preflight: reachability, credentials, MFA readiness, tool availability, scope review, request limits, and appliance health.
- Add source/document/API-spec ingestion with deterministic endpoint extraction.
- Introduce graph-backed assets, endpoints, roles, hypotheses, actions, evidence, and findings.
- Convert findings to reproducible case files with independent validation state.
- Make targeted retest and incremental assessment first-class run types.

**Exit criteria:** a supplied OpenAPI document and internal CIDR produce one correlated assessment graph; each confirmed finding has independently reproducible evidence and a retained before/after retest history.

### Phase 2 — Coordinator and browser/API workers (8–12 weeks)

- Add persistent coordinator and bounded worker queue.
- Add browser-native exploration and authenticated role sessions.
- Add endpoint/parameter/auth-flow mapping and role-matrix testing.
- Add duplicate-work suppression, method diversity, adaptive fallback, and coverage accounting.
- Provide a live trace view grouped by objective and attack path.

**Exit criteria:** a hybrid application assessment can autonomously map, prioritize, test, validate, and report while an operator observes and intervenes without manually directing each safe action.

### Phase 3 — Appliance fleet and continuous validation (8–12 weeks)

- Add appliance capability/health inventory and workload assignment.
- Add schedules, change-triggered runs, baseline drift, and remediation queues.
- Add organization-level coverage and risk dashboards.
- Add API, signed webhooks, Jira/GitHub issue creation, and SIEM export.
- Add policy packs for production, staging, regulated, and internal identity testing.

**Exit criteria:** Control Center can schedule and observe multiple appliance-backed assessments, deliver validated findings into remediation workflows, and reverify fixes without losing historical evidence.

### Phase 4 — Model routing and enterprise hardening (ongoing)

- Benchmark models by task and route accordingly.
- Add cost/latency/quality policies and fallback models.
- Add SSO, RBAC, separation of duties, retention controls, appliance attestation, signed release channels, and regional deployment patterns.
- Run adversarial safety, false-positive, false-negative, reproducibility, and evidence-integrity evaluations.

## Non-negotiable boundaries

- Do not weaken deterministic scope or command policy to imitate a competitor's autonomy claims.
- Do not centrally persist raw client credentials or authenticated browser/session material by default.
- Do not allow customer guidance, model output, or a remembered approval to override scope, exclusions, MFA restrictions, destructive-action blocks, credential boundaries, or cleanup requirements.
- Do not label a finding confirmed without direct evidence and the vulnerability-class validation contract.
- Do not treat a tool failure, timeout, blocked prerequisite, or budget limit as a negative finding.
- Do not erase or overwrite historical evidence during reruns or retests.
- Do not market modeled attack paths as observed compromise.
- Keep remote-access and one-hop movement AI-operated but continuously human-supervised and individually approved.

## Success metrics

### Product effectiveness

- Confirmed-finding reproducibility rate: **≥95%** on benchmark targets.
- Unsupported confirmed findings: **0**.
- Findings with complete case files: **100%**.
- Eligible attempts with lifecycle records: **100%**.
- Historical evidence lost or overwritten on rerun: **0**.
- Secrets found in prompts, logs, reports, or centralized records: **0**.

### Coverage and autonomy

- Assets/endpoints/roles with explicit tested, not-tested, blocked, or inconclusive status: **100%**.
- Safe actions requiring manual tactical direction: trend toward **<10%**.
- Approval-gated actions executed without approval: **0**.
- Confirmed findings with two independent methods or authenticated confirmation where required: **100%**.

### Operations

- Appliance health visible before dispatch: **100%**.
- Interrupted assessments resumable without repeating completed work: **100%**.
- Fix retests preserving before/after evidence: **100%**.
- Signed webhook delivery with retry and audit status: **100%**.

## Recommended product package

Treat this as one platform with two complementary execution modes:

1. **LLMtary External** — autonomous application/API testing from managed internet execution points.
2. **LLMtary Internal Appliance** — customer-network testing for private applications, identity, hosts, services, segmentation, and internal attack paths.
3. **LLMtary Hybrid Validation** — one coordinated assessment graph spanning external exposure to internal impact, with customer-controlled trust-boundary crossing.

The recommended launch sequence is **Internal Appliance first, then Hybrid**, because the appliance and deterministic evidence controls are the strongest differentiated assets already present. Competing head-on first on portfolio-scale external web testing would put LLMtary against XBOW's most mature public capability; appliance-backed internal validation creates a clearer initial wedge.

## Sources

[1] [XBOW Platform](https://xbow.com/platform)
[2] [XBOW supported guidance artifacts](https://docs.xbow.com/console/reference/artifacts)
[3] [XBOW automation and integrations](https://docs.xbow.com/console/organization-admin/automate-events)
[4] [XBOW autonomous pentest demo](https://xbow.com/videos/xbow-run-autonomous-penetration-test)

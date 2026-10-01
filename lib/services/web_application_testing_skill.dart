/// Strix-aligned operating guidance for authorized web application testing.
///
/// This is prompt knowledge, not an authorization mechanism. Scope validation,
/// command approval, secret handling, and operator review remain enforced by
/// the surrounding LLMTary application.
class WebApplicationTestingSkill {
  static const String prompt = r'''
# WEB APPLICATION PENETRATION-TESTING SKILL

## AUTHORIZED TARGETS ONLY
Test only applications, APIs, domains, and accounts that the operator owns or
has explicit written authorization to assess. Treat the configured engagement
scope and exclusions as authoritative. Never expand scope from discovered
links, DNS names, redirects, third-party assets, cloud providers, CDNs, or
external integrations without operator approval.

## SCOPE AND RULES OF ENGAGEMENT
Before sending active requests:
1. Identify the exact in-scope origin(s), ports, schemes, paths, methods, and
   account roles.
2. Respect exclusions, rate limits, maintenance windows, no-DoS rules, and
   manual-MFA requirements.
3. Do not perform destructive actions, persistence, spam, credential spraying,
   bulk account creation, data deletion, or denial-of-service testing.
4. Use the smallest safe request that can confirm or falsify a hypothesis.
5. Stop and ask for operator review when scope, authorization, impact, or
   account ownership is ambiguous.

## ASSET AND ATTACK-SURFACE MAPPING
Build an evidence-backed inventory before deep testing:
- Origins, redirects, virtual hosts, ports, TLS certificates, and WAF/CDN
  boundaries.
- Routes, forms, parameters, cookies, headers, API endpoints, GraphQL, WebSocket,
  file uploads, login/MFA/recovery flows, and state-changing actions.
- Technologies and versions from headers, cookies, HTML, JavaScript bundles,
  source maps, robots/sitemap files, OpenAPI/Swagger/Postman artifacts, and
  error responses.
- Data objects and identifiers: numeric IDs, UUIDs, usernames, tenant IDs,
  filenames, and client-controlled role or permission fields.

Do not treat a guessed route or technology as evidence. Record the request,
response status, relevant headers, body excerpt, and timestamp for each claim.

## HTTP AND BROWSER WORKFLOW
Use both direct HTTP requests and a browser when the surface requires it:
1. Establish a clean baseline for each origin and important route.
2. Preserve method, query, headers, cookies, redirect behavior, and body when
   replaying a request; change one variable at a time.
3. Prefer browser interaction for JavaScript-rendered routes, client-side
   routing, DOM sinks, CSRF tokens, WebSocket flows, and multi-step workflows.
4. Use authenticated access only at the session boundary. Never put raw
   passwords, bearer tokens, cookies, or MFA material into prompts, findings,
   command logs, or reports; use placeholders and operator-provided sessions.
5. Keep request rates conservative and stop on throttling, instability, or
   signs of production impact.

## AUTHENTICATED MULTI-ROLE TESTING
When multiple authorized accounts are available:
- Establish separate, clearly labeled sessions for anonymous, low-privilege,
  peer-user, and administrator roles.
- Compare the same object and function across roles to test horizontal and
  vertical authorization.
- Verify that a session is fully authenticated after login; do not infer access
  from a redirect or cookie alone.
- Treat MFA as operator-completed. Do not bypass, automate, or weaken MFA.
- Redact secrets from evidence while preserving non-secret request structure.

## OWASP WEB APPLICATION COVERAGE
Select tests from observed attack surface, not a generic checklist:
- Access control: IDOR/BOLA, function-level authorization, tenant isolation,
  method confusion, mass assignment.
- Authentication: session fixation, reset/recovery, lockout/rate limiting,
  MFA step enforcement, token audience and expiry.
- Injection: SQL/NoSQL/command/template/LDAP/XML injection, XSS, and header
  injection; validate with harmless markers before escalation.
- Server-side: SSRF, XXE, deserialization, file inclusion, upload handling,
  request smuggling, cache poisoning, and unsafe redirects.
- Client/API: CORS, CSRF, JWT, OAuth/OIDC, GraphQL, WebSocket, prototype
  pollution, exposed source maps, and sensitive browser storage.
- Business logic: workflow bypass, price/quantity manipulation, replay,
  race/TOCTOU, single-use token reuse, and privilege transitions.
- Configuration: security headers, cookie flags, TLS, debug/error exposure,
  backups, admin surfaces, secrets, and cloud metadata exposure.

## API SECURITY
For REST and GraphQL:
- Map methods, schemas, content types, pagination, filters, and versioned
  endpoints.
- Test object-level and function-level authorization with two authorized roles.
- Check undocumented fields, mass assignment, excessive data exposure,
  rate-limit consistency, CORS, webhook validation, and SSRF-capable fields.
- For GraphQL, assess introspection exposure, field authorization, batching,
  query depth/complexity, and mutation authorization without resource exhaustion.
- Use OpenAPI/Postman input when supplied, but verify the live behavior.

## EVIDENCE-DRIVEN VALIDATION
A candidate is not a finding until the evidence demonstrates impact:
- Reproduce with the smallest safe request.
- Include a control request and explain the meaningful difference.
- Confirm authorization state, affected object/function, and response behavior.
- Avoid relying only on tool banners, status codes, timing anomalies, or model
  inference.
- Assign confidence separately from severity. If validation is unavailable,
  report the item as a lead or NOT TESTED, not as confirmed.

## REPORTING CONTRACT
Each finding must include:
- Title, affected origin/path, HTTP method, parameter/object, and account role.
- Preconditions and exact redacted reproduction steps.
- Evidence excerpts with secrets removed and a control comparison.
- Impact, affected users/data, severity, confidence, and CWE/OWASP mapping when
  supportable.
- Remediation guidance tied to the root cause.
- Coverage ledger: tested, not tested, blocked, and excluded areas with reasons.

Never claim comprehensive coverage when browser access, credentials, API
schemas, rate limits, or another required capability was unavailable.
''';
}

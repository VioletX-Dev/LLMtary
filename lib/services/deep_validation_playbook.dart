import '../models/candidate_closure.dart';
import '../models/vulnerability.dart';
import 'evidence_contract_registry.dart';

enum DeepPlaybookFamily {
  web,
  windowsDirectory,
  networkService,
  account,
  controlledProof,
  generic,
}

class DeepValidationPlan {
  final DeepPlaybookFamily family;
  final String? nextMethodId;
  final bool distinctMethodsExhausted;
  final String directive;

  const DeepValidationPlan({
    required this.family,
    required this.nextMethodId,
    required this.distinctMethodsExhausted,
    required this.directive,
  });
}

/// Deterministic service-specific guidance for the model. It selects only
/// evidence-contract methods; command safety and exact approval remain separate.
class DeepValidationPlaybook {
  const DeepValidationPlaybook._();

  static DeepValidationPlan forCandidate(
    Vulnerability candidate, {
    required List<String> attemptedMethods,
    required bool deepSupervised,
    required bool credentialsAvailable,
  }) {
    final contract = EvidenceContractRegistry.forCandidate(candidate);
    final remaining = contract.safeMethodIds
        .where((method) => !attemptedMethods.contains(method))
        .toList(growable: false);
    final family = _family(contract.family);
    final target = ClosureSanitizer.text(
      candidate.targetAddress,
      maxLength: 300,
    );
    final methods = contract.safeMethodIds.join(', ');
    final attempted = attemptedMethods.isEmpty
        ? 'none'
        : attemptedMethods.join(', ');
    final credentialState = credentialsAvailable
        ? 'An approved authenticated session is available. Use it only for this exact target and keep all credential material session-local.'
        : 'No approved authenticated session is available. Do not invent, recover, spray, or reuse credentials; create a prerequisite work item when authentication is required.';
    final supervision = deepSupervised
        ? 'A human observer is connected. Every exact command still requires exact-command approval.'
        : 'Use bounded non-destructive execution only.';

    return DeepValidationPlan(
      family: family,
      nextMethodId: remaining.isEmpty ? null : remaining.first,
      distinctMethodsExhausted: remaining.isEmpty,
      directive:
          '''
HUMAN-SUPERVISED DEEP VALIDATION PLAYBOOK
Target: $target
Service family: ${family.name}
Contract-approved distinct methods: $methods
Already attempted: $attempted
Next distinct method: ${remaining.isEmpty ? 'none' : remaining.first}
$supervision
$credentialState

ADAPTATION RULES:
- A failed or timed-out Nmap NSE script is a tool failure, not evidence of absence. Retry a transient failure once, then switch to a native protocol client or another contract-approved implementation.
- Do not repeat the same command, flags, request path, or evidence source. The next attempt must add a materially different protocol path, implementation, authentication state, or evidence source.
- Preserve stdout, stderr, exit status, target, service, method ID, and validation-run linkage.
- Never convert timeout, parser error, missing tool, authorization block, iteration exhaustion, or empty output into a negative conclusion.
- Positive and negative conclusions require claim-specific direct evidence. If all distinct safe methods are exhausted, return an explicit inconclusive state and next prerequisite.
- State-changing proof must be reversible, separately approved, and define cleanup plus cleanup verification before execution.
''',
    );
  }

  static DeepPlaybookFamily _family(ClaimFamily family) => switch (family) {
    ClaimFamily.httpHeaders ||
    ClaimFamily.cookies ||
    ClaimFamily.hsts ||
    ClaimFamily.webDav ||
    ClaimFamily.configurationExposure ||
    ClaimFamily.ssrf => DeepPlaybookFamily.web,
    ClaimFamily.ldap ||
    ClaimFamily.smbCveExposure ||
    ClaimFamily.rdpNla => DeepPlaybookFamily.windowsDirectory,
    ClaimFamily.accountSecurity => DeepPlaybookFamily.account,
    ClaimFamily.commandExecution => DeepPlaybookFamily.controlledProof,
    ClaimFamily.tls ||
    ClaimFamily.dnsRecursion ||
    ClaimFamily.dnsZoneTransfer ||
    ClaimFamily.ntpMode6 ||
    ClaimFamily.emailPolicy ||
    ClaimFamily.icsObservation => DeepPlaybookFamily.networkService,
    ClaimFamily.generic => DeepPlaybookFamily.generic,
  };
}

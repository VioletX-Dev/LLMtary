import '../models/candidate_closure.dart';
import '../models/vulnerability.dart';
import 'candidate_admission_service.dart';
import 'evidence_contract_registry.dart';

class CandidatePrerequisites {
  final bool inScope;
  final bool targetReachable;
  final bool applianceAvailable;
  final bool authorizationGranted;
  final bool credentialsAvailable;
  final bool manualMfaCompleted;
  final bool requiredToolAvailable;
  final int retryBudget;
  final int retriesUsed;
  final int toolBudget;
  final int toolsUsed;
  final int requestBudget;
  final int requestsUsed;
  final List<String> attemptedMethodIds;

  const CandidatePrerequisites({
    this.inScope = true,
    this.targetReachable = true,
    this.applianceAvailable = true,
    this.authorizationGranted = true,
    this.credentialsAvailable = false,
    this.manualMfaCompleted = false,
    this.requiredToolAvailable = true,
    this.retryBudget = 3,
    this.retriesUsed = 0,
    this.toolBudget = 3,
    this.toolsUsed = 0,
    this.requestBudget = 8,
    this.requestsUsed = 0,
    this.attemptedMethodIds = const [],
  });
}

class CandidatePlanDecision {
  final bool shouldExecute;
  final String? methodId;
  final CandidateDisposition disposition;
  final ClosureReasonCode reasonCode;
  final String explanation;
  final List<String> prerequisites;
  final WorkOwner owner;

  const CandidatePlanDecision({
    required this.shouldExecute,
    this.methodId,
    required this.disposition,
    required this.reasonCode,
    required this.explanation,
    this.prerequisites = const [],
    this.owner = WorkOwner.platform,
  });
}

/// Deterministic planner. It proposes only contract-approved read-only methods;
/// command validation and operator approval still apply at execution time.
class CandidateClosurePlanner {
  const CandidateClosurePlanner._();

  static CandidatePlanDecision plan(
    Vulnerability candidate,
    CandidatePrerequisites state,
  ) {
    final admission = CandidateAdmissionService.classify(candidate);
    if (!admission.accepted) {
      return CandidatePlanDecision(
        shouldExecute: false,
        disposition:
            admission.recordKind == CandidateRecordKind.invalidHypothesis
            ? CandidateDisposition.invalidHypothesis
            : CandidateDisposition.notApplicable,
        reasonCode:
            admission.recordKind == CandidateRecordKind.invalidHypothesis
            ? ClosureReasonCode.invalidOrUntestableClaim
            : ClosureReasonCode.notApplicableToTarget,
        explanation: admission.reason,
      );
    }
    if (!state.inScope) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.blockedScope,
        reasonCode: ClosureReasonCode.outOfScope,
        explanation: 'The target or technique is outside the authorized scope.',
        owner: WorkOwner.customer,
      );
    }
    if (!state.authorizationGranted) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.deferredByAuthorization,
        reasonCode: ClosureReasonCode.authorizationRequired,
        explanation:
            'Explicit authorization is required before this technique can run.',
        owner: WorkOwner.customer,
      );
    }
    if (!state.applianceAvailable) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.blockedMissingAppliance,
        reasonCode: ClosureReasonCode.applianceUnavailable,
        explanation: 'The required assessment appliance is not available.',
        owner: WorkOwner.joint,
      );
    }
    if (!state.targetReachable) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.blockedConnectivity,
        reasonCode: ClosureReasonCode.targetUnreachable,
        explanation:
            'The target is unreachable from the authorized assessment boundary.',
        owner: WorkOwner.joint,
      );
    }
    if (!state.requiredToolAvailable) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.toolingFailure,
        reasonCode: ClosureReasonCode.requiredToolUnavailable,
        explanation:
            'No approved implementation of the required safe method is available.',
        owner: WorkOwner.operator,
      );
    }

    final contract = EvidenceContractRegistry.forCandidate(candidate);
    if (contract.safeMethodIds.isEmpty) {
      return CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.pendingCustomerClarification,
        reasonCode: ClosureReasonCode.customerClarificationRequired,
        explanation: 'A claim-specific evidence contract cannot be selected.',
        prerequisites: contract.prerequisites,
        owner: WorkOwner.joint,
      );
    }
    if (_requiresCredentials(contract.family) && !state.credentialsAvailable) {
      return CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.blockedMissingCredentials,
        reasonCode: ClosureReasonCode.authenticationRequired,
        explanation:
            'An approved test identity is required; credentials remain session-local.',
        prerequisites: contract.prerequisites,
        owner: WorkOwner.customer,
      );
    }
    if (_requiresMfa(candidate) && !state.manualMfaCompleted) {
      return CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.blockedMfaOperatorAction,
        reasonCode: ClosureReasonCode.manualMfaRequired,
        explanation:
            'MFA must be completed manually by an authorized operator.',
        prerequisites: contract.prerequisites,
        owner: WorkOwner.operator,
      );
    }
    if (state.retriesUsed >= state.retryBudget) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.safeTestingLimitReached,
        reasonCode: ClosureReasonCode.safeRetryBudgetExhausted,
        explanation: 'The bounded retry budget was exhausted.',
      );
    }
    if (state.toolsUsed >= state.toolBudget) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.safeTestingLimitReached,
        reasonCode: ClosureReasonCode.safeToolBudgetExhausted,
        explanation: 'The bounded distinct-tool budget was exhausted.',
      );
    }
    if (state.requestsUsed >= state.requestBudget) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.safeTestingLimitReached,
        reasonCode: ClosureReasonCode.safeRequestBudgetExhausted,
        explanation: 'The bounded request budget was exhausted.',
      );
    }
    final remaining = contract.safeMethodIds
        .where((method) => !state.attemptedMethodIds.contains(method))
        .toList(growable: false);
    if (remaining.isEmpty) {
      return const CandidatePlanDecision(
        shouldExecute: false,
        disposition: CandidateDisposition.technicallyInconclusiveBounded,
        reasonCode: ClosureReasonCode.boundedMethodsExhausted,
        explanation:
            'All materially different safe verification methods were attempted.',
      );
    }
    return CandidatePlanDecision(
      shouldExecute: true,
      methodId: remaining.first,
      disposition: CandidateDisposition.investigating,
      reasonCode: ClosureReasonCode.customerClarificationRequired,
      explanation:
          'Run the next unused claim-specific safe verification method.',
      prerequisites: contract.prerequisites,
    );
  }

  static bool _requiresCredentials(ClaimFamily family) =>
      family == ClaimFamily.accountSecurity;

  static bool _requiresMfa(Vulnerability candidate) =>
      '${candidate.problem} ${candidate.description}'.toLowerCase().contains(
        'm365',
      ) ||
      '${candidate.problem} ${candidate.description}'.toLowerCase().contains(
        'mfa',
      );
}

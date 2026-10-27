import '../models/candidate_closure.dart';
import '../models/vulnerability.dart';

/// Conservative bridge from legacy four-state results to the richer closure
/// record. This never mutates the legacy finding status.
class LegacyClosureMapper {
  const LegacyClosureMapper._();

  static CandidateClosure map(
    Vulnerability vulnerability, {
    DateTime? now,
    int? projectId,
  }) {
    final timestamp = (now ?? DateTime.now()).toUtc();
    final reason = vulnerability.statusReason.trim();
    var disposition = CandidateDisposition.pendingCustomerClarification;
    var reasonCode = ClosureReasonCode.customerClarificationRequired;
    var prerequisites = const <String>[];
    var nextAction =
        'Review the candidate and identify the missing prerequisite.';
    var owner = WorkOwner.joint;

    if (vulnerability.status == VulnerabilityStatus.confirmed) {
      disposition = CandidateDisposition.verifiedFinding;
      reasonCode = ClosureReasonCode.directEvidenceVerified;
      nextAction = '';
      owner = WorkOwner.platform;
    } else if (vulnerability.status == VulnerabilityStatus.notVulnerable) {
      disposition = CandidateDisposition.verifiedNegative;
      reasonCode = ClosureReasonCode.rejectingEvidenceVerified;
      nextAction = '';
      owner = WorkOwner.platform;
    } else {
      final lower = reason.toLowerCase();
      if (lower.contains('mfa')) {
        disposition = CandidateDisposition.blockedMfaOperatorAction;
        reasonCode = ClosureReasonCode.manualMfaRequired;
        prerequisites = const ['operator-completed MFA'];
        nextAction = 'Complete MFA manually on the assessment appliance.';
        owner = WorkOwner.operator;
      } else if (lower.contains('auth') ||
          lower.contains('credential') ||
          lower.contains('login')) {
        disposition = CandidateDisposition.blockedMissingCredentials;
        reasonCode = ClosureReasonCode.authenticationRequired;
        prerequisites = const ['approved session-local test identity'];
        nextAction =
            'Provide an approved test identity through the appliance session.';
        owner = WorkOwner.customer;
      } else if (lower.contains('scope') || lower.contains('not authorized')) {
        disposition = CandidateDisposition.blockedScope;
        reasonCode = ClosureReasonCode.outOfScope;
        prerequisites = const ['written scope clarification'];
        nextAction = 'Confirm ownership and testing authorization.';
        owner = WorkOwner.customer;
      } else if (lower.contains('unreachable') ||
          lower.contains('connectivity') ||
          lower.contains('timed out')) {
        disposition = CandidateDisposition.blockedConnectivity;
        reasonCode = ClosureReasonCode.targetUnreachable;
        prerequisites = const ['target connectivity from assessment boundary'];
        nextAction = 'Restore or confirm authorized target connectivity.';
        owner = WorkOwner.joint;
      } else if (lower.contains('safety') || lower.contains('prohibited')) {
        disposition = CandidateDisposition.safeTestingLimitReached;
        reasonCode = ClosureReasonCode.safeRequestBudgetExhausted;
        nextAction =
            'Review the human-validation requirement and authorization boundary.';
        owner = WorkOwner.operator;
      } else if (lower.contains('maximum iteration') ||
          lower.contains('all methods') ||
          lower.contains('bounded') ||
          lower.contains('conflicting result')) {
        disposition = CandidateDisposition.technicallyInconclusiveBounded;
        reasonCode = ClosureReasonCode.boundedMethodsExhausted;
        nextAction = '';
        owner = WorkOwner.platform;
      } else if (lower.contains('tool') ||
          lower.contains('command not found')) {
        disposition = CandidateDisposition.toolingFailure;
        reasonCode = ClosureReasonCode.requiredToolUnavailable;
        prerequisites = const ['approved claim-specific tool'];
        nextAction =
            'Install or enable the approved tool through managed tooling.';
        owner = WorkOwner.operator;
      }
    }

    return CandidateClosure(
      vulnerabilityId: vulnerability.id ?? 0,
      projectId: projectId ?? vulnerability.projectId ?? 0,
      disposition: disposition,
      reasonCode: reasonCode,
      explanation: reason.isEmpty
          ? 'No defensible legacy closure reason was recorded.'
          : reason,
      remainingPrerequisites: prerequisites,
      nextAction: nextAction,
      owner: owner,
      stoppingReason: reason,
      startedAt: vulnerability.confirmedAt?.toUtc() ?? timestamp,
      updatedAt: timestamp,
    );
  }
}

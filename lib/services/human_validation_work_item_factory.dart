import '../models/candidate_closure.dart';
import '../models/controlled_exploitation.dart';
import '../models/human_validation_work_item.dart';
import '../models/vulnerability.dart';

/// Creates non-secret coordination cards only for closure states that require
/// customer, operator, authorization, or joint follow-up.
class HumanValidationWorkItemFactory {
  const HumanValidationWorkItemFactory._();

  static HumanValidationWorkItem? fromClosure(
    Vulnerability candidate,
    CandidateClosure closure, {
    DateTime? now,
  }) {
    if (!_requiresWorkItem(closure.disposition)) return null;
    final timestamp = (now ?? DateTime.now()).toUtc();
    return HumanValidationWorkItem(
      id: 'candidate-${closure.vulnerabilityId}-${closure.reasonCode.name}',
      projectId: closure.projectId,
      vulnerabilityId: closure.vulnerabilityId,
      title: 'Follow-up: ${candidate.problem}',
      authorizationRequired: closure.explanation,
      evidenceRequested: closure.remainingPrerequisites,
      safetyNotes: _safetyNotes(closure.disposition),
      owner: closure.owner,
      status: _status(closure.disposition),
      createdAt: timestamp,
      updatedAt: timestamp,
    );
  }

  static HumanValidationWorkItem? fromControlledExploitation(
    Vulnerability candidate,
    ControlledExploitationRecord record, {
    DateTime? now,
  }) {
    if (record.eligibility != ExploitationEligibility.humanValidationRequired) {
      return null;
    }
    final timestamp = (now ?? DateTime.now()).toUtc();
    return HumanValidationWorkItem(
      id: 'controlled-${record.vulnerabilityId}-human-validation',
      projectId: record.projectId,
      vulnerabilityId: record.vulnerabilityId,
      title: 'Human-controlled exploitation review: ${candidate.problem}',
      authorizationRequired: record.accessLevel,
      evidenceRequested: const [
        'written authorization for the exact human-led procedure',
        'sanitized proof and cleanup evidence references',
      ],
      safetyNotes:
          'No shells, persistence, privilege elevation, lateral movement, credential collection, destructive activity, or MFA bypass. Return only sanitized evidence references.',
      owner: WorkOwner.operator,
      status: HumanValidationStatus.waitingAuthorization,
      createdAt: timestamp,
      updatedAt: timestamp,
    );
  }

  static bool _requiresWorkItem(CandidateDisposition disposition) =>
      switch (disposition) {
        CandidateDisposition.deferredByAuthorization ||
        CandidateDisposition.blockedMissingCredentials ||
        CandidateDisposition.blockedMfaOperatorAction ||
        CandidateDisposition.blockedConnectivity ||
        CandidateDisposition.blockedMissingAppliance ||
        CandidateDisposition.blockedScope ||
        CandidateDisposition.safeTestingLimitReached ||
        CandidateDisposition.pendingCustomerClarification ||
        CandidateDisposition.toolingFailure => true,
        _ => false,
      };

  static HumanValidationStatus _status(CandidateDisposition disposition) =>
      switch (disposition) {
        CandidateDisposition.deferredByAuthorization ||
        CandidateDisposition.blockedScope =>
          HumanValidationStatus.waitingAuthorization,
        CandidateDisposition.blockedMfaOperatorAction ||
        CandidateDisposition.safeTestingLimitReached ||
        CandidateDisposition.toolingFailure => HumanValidationStatus.ready,
        _ => HumanValidationStatus.waitingCustomer,
      };

  static String _safetyNotes(
    CandidateDisposition disposition,
  ) => switch (disposition) {
    CandidateDisposition.blockedMfaOperatorAction =>
      'Manual MFA completion only. Do not record MFA codes or session secrets.',
    CandidateDisposition.blockedMissingCredentials =>
      'Credentials remain at the appliance session boundary and are never stored in this work item.',
    CandidateDisposition.deferredByAuthorization ||
    CandidateDisposition.blockedScope =>
      'Do not run the method until written authorization and scope are confirmed.',
    CandidateDisposition.safeTestingLimitReached =>
      'The automated safety limit was reached. Human review cannot waive mandatory non-destructive controls.',
    CandidateDisposition.toolingFailure =>
      'Use only approved managed tooling; arbitrary packages and commands remain prohibited.',
    _ =>
      'Coordinate the prerequisite without changing target state or weakening assessment safety controls.',
  };
}

import '../models/candidate_closure.dart';
import '../models/controlled_exploitation.dart';
import '../models/vulnerability.dart';

class CandidateCloseoutResult {
  final bool ready;
  final int total;
  final int closed;
  final List<int> unresolvedVulnerabilityIds;
  final List<String> errors;

  const CandidateCloseoutResult({
    required this.ready,
    required this.total,
    required this.closed,
    required this.unresolvedVulnerabilityIds,
    required this.errors,
  });

  int get coveragePercent =>
      total == 0 ? 100 : ((closed / total) * 100).round();
}

class CandidateCloseoutService {
  const CandidateCloseoutService._();

  static CandidateCloseoutResult validate({
    required List<Vulnerability> vulnerabilities,
    required Map<int, CandidateClosure> closuresByVulnerabilityId,
    Map<int, ControlledExploitationRecord>?
    controlledExploitationsByVulnerabilityId,
  }) {
    final unresolved = <int>[];
    final errors = <String>[];
    var closed = 0;
    for (final vulnerability in vulnerabilities) {
      final id = vulnerability.id;
      if (id == null) {
        errors.add('A candidate has no durable identifier.');
        continue;
      }
      final closure = closuresByVulnerabilityId[id];
      if (closure == null || !closure.isTerminal) {
        unresolved.add(id);
        continue;
      }
      if (closure.explanation.trim().isEmpty) {
        unresolved.add(id);
        errors.add('Candidate $id has no closure explanation.');
        continue;
      }
      if (_requiresFollowUp(closure.disposition) &&
          (closure.nextAction.isEmpty ||
              closure.remainingPrerequisites.isEmpty)) {
        unresolved.add(id);
        errors.add(
          'Candidate $id is blocked but has no prerequisite and next action.',
        );
        continue;
      }
      if (controlledExploitationsByVulnerabilityId != null &&
          closure.disposition == CandidateDisposition.verifiedFinding) {
        final exploitation = controlledExploitationsByVulnerabilityId[id];
        if (exploitation == null || !exploitation.isComplete) {
          unresolved.add(id);
          errors.add(
            'Candidate $id has no complete controlled-exploitation disposition and cleanup record.',
          );
          continue;
        }
      }
      closed++;
    }
    return CandidateCloseoutResult(
      ready: unresolved.isEmpty && errors.isEmpty,
      total: vulnerabilities.length,
      closed: closed,
      unresolvedVulnerabilityIds: List.unmodifiable(unresolved),
      errors: List.unmodifiable(errors),
    );
  }

  static bool _requiresFollowUp(CandidateDisposition disposition) => {
    CandidateDisposition.deferredByAuthorization,
    CandidateDisposition.blockedMissingCredentials,
    CandidateDisposition.blockedMfaOperatorAction,
    CandidateDisposition.blockedConnectivity,
    CandidateDisposition.blockedMissingAppliance,
    CandidateDisposition.blockedScope,
    CandidateDisposition.pendingCustomerClarification,
    CandidateDisposition.toolingFailure,
  }.contains(disposition);
}

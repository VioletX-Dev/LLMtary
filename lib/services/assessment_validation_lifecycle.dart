import '../models/candidate_closure.dart';
import '../models/validation_run.dart';
import '../models/vulnerability.dart';

/// Creates the authoritative lifecycle record for an ordinary assessment
/// candidate. Retests and operator-created spot tests use their existing modes.
class AssessmentValidationLifecycle {
  const AssessmentValidationLifecycle._();

  static ValidationRun begin({
    required Vulnerability candidate,
    required int projectId,
    required int targetId,
    required String methodId,
    required bool deepSupervised,
    DateTime? now,
  }) => ValidationRun(
    projectId: projectId,
    targetId: targetId,
    vulnerabilityId: candidate.id,
    mode: ValidationRunMode.assessment,
    title: ClosureSanitizer.text(
      '${deepSupervised ? 'Deep validation' : 'Validation'}: ${candidate.problem}',
      maxLength: 300,
    ),
    objective: ClosureSanitizer.text(
      'Obtain claim-specific positive or rejecting evidence for ${candidate.problem}.',
      maxLength: 800,
    ),
    parameters: ClosureSanitizer.text(
      'planned_method=$methodId; target=${candidate.targetAddress}',
      maxLength: 800,
    ),
    expectedResult:
        'Direct evidence either supports the claim, rejects it, or records an explicit inconclusive state.',
    constraints: deepSupervised
        ? 'Human-supervised; exact-command approval required; credentials remain session-local; destructive and unapproved state-changing actions are prohibited.'
        : 'Bounded non-destructive methods only; credentials remain session-local.',
    statusBefore: candidate.status.name,
    baselineStatusReason: ClosureSanitizer.text(candidate.statusReason),
    startedAt: (now ?? DateTime.now()).toUtc(),
  );

  static ValidationRun complete(
    ValidationRun run, {
    required VulnerabilityStatus status,
    required String summary,
    DateTime? now,
  }) {
    final outcome = switch (status) {
      VulnerabilityStatus.confirmed => ValidationRunOutcome.conditionObserved,
      VulnerabilityStatus.notVulnerable =>
        ValidationRunOutcome.conditionNotObserved,
      VulnerabilityStatus.undetermined => ValidationRunOutcome.inconclusive,
      VulnerabilityStatus.pending => ValidationRunOutcome.inconclusive,
    };
    return run.copyWith(
      statusAfter: status.name,
      outcome: outcome,
      summary: ClosureSanitizer.text(summary),
      completedAt: (now ?? DateTime.now()).toUtc(),
    );
  }

  static ValidationRun error(
    ValidationRun run, {
    required Object error,
    DateTime? now,
  }) => run.copyWith(
    outcome: ValidationRunOutcome.error,
    summary: ClosureSanitizer.text(
      'Assessment validation failed: ${error.runtimeType}',
    ),
    completedAt: (now ?? DateTime.now()).toUtc(),
  );
}

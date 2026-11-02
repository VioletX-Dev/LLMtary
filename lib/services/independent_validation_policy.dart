import '../models/independent_validation.dart';

class IndependentValidationPolicy {
  IndependentValidationResult evaluate(IndependentValidationInput input) {
    if (input.proposerContextId.trim().isEmpty ||
        input.validatorContextId.trim().isEmpty ||
        input.proposerContextId == input.validatorContextId) {
      throw ArgumentError('Proposer and validator contexts must be separate.');
    }
    final attempts = input.reproductionAttempts;
    final score = attempts.isEmpty
        ? 0.0
        : attempts.where((attempt) => attempt).length / attempts.length;
    if (input.proposerDecision != input.validatorDecision) {
      return IndependentValidationResult(
        outcome: IndependentValidationOutcome.inconclusive,
        reproducibilityScore: score,
        reason: 'Independent proposer and validator disagree.',
      );
    }
    final requiredControls = switch (input.vulnerabilityClass) {
      VulnerabilityClass.authorization => const {
        ValidationControl.authenticatedBaseline,
        ValidationControl.unauthorizedComparison,
      },
      VulnerabilityClass.injection => const {
        ValidationControl.benignNegativeInput,
      },
      VulnerabilityClass.transport => const {
        ValidationControl.protocolBaseline,
      },
      _ => const <ValidationControl>{},
    };
    final missingControls = requiredControls.difference(
      input.completedControls,
    );
    if (input.proposerDecision == IndependentValidationDecision.confirmed &&
        input.validatorDecision == IndependentValidationDecision.confirmed &&
        (input.directEvidenceArtifactIds.isEmpty ||
            missingControls.isNotEmpty ||
            attempts.length < 2 ||
            score < 1)) {
      final reason = input.directEvidenceArtifactIds.isEmpty
          ? 'Direct evidence is required.'
          : missingControls.isNotEmpty
          ? 'Required validation controls are incomplete.'
          : 'Repeatable reproduction requires two successful attempts.';
      return IndependentValidationResult(
        outcome: IndependentValidationOutcome.inconclusive,
        reproducibilityScore: score,
        missingControls: missingControls,
        reason: reason,
      );
    }
    final outcome = switch (input.validatorDecision) {
      IndependentValidationDecision.confirmed =>
        IndependentValidationOutcome.confirmed,
      IndependentValidationDecision.rejected =>
        IndependentValidationOutcome.rejected,
      IndependentValidationDecision.inconclusive =>
        IndependentValidationOutcome.inconclusive,
    };
    return IndependentValidationResult(
      outcome: outcome,
      reproducibilityScore: score,
      reason: 'Independent decisions agree.',
    );
  }
}

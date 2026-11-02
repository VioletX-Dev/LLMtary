import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/independent_validation.dart';
import 'package:llmtary/services/independent_validation_policy.dart';

void main() {
  test('confirmation requires repeatable reproduction', () {
    final result = IndependentValidationPolicy().evaluate(
      const IndependentValidationInput(
        vulnerabilityClass: VulnerabilityClass.configuration,
        proposerContextId: 'proposal-9',
        validatorContextId: 'validator-14',
        proposerDecision: IndependentValidationDecision.confirmed,
        validatorDecision: IndependentValidationDecision.confirmed,
        reproductionAttempts: [true],
        directEvidenceArtifactIds: [51],
      ),
    );

    expect(result.outcome, IndependentValidationOutcome.inconclusive);
    expect(result.reproducibilityScore, 1);
    expect(result.reason, contains('reproduction'));
  });

  test(
    'authorization findings require direct evidence and comparison controls',
    () {
      final result = IndependentValidationPolicy().evaluate(
        const IndependentValidationInput(
          vulnerabilityClass: VulnerabilityClass.authorization,
          proposerContextId: 'proposal-8',
          validatorContextId: 'validator-13',
          proposerDecision: IndependentValidationDecision.confirmed,
          validatorDecision: IndependentValidationDecision.confirmed,
          reproductionAttempts: [true, true],
          directEvidenceArtifactIds: [41],
          completedControls: {ValidationControl.authenticatedBaseline},
        ),
      );

      expect(result.outcome, IndependentValidationOutcome.inconclusive);
      expect(result.missingControls, {
        ValidationControl.unauthorizedComparison,
      });
    },
  );

  test('validator disagreement stays inconclusive', () {
    final result = IndependentValidationPolicy().evaluate(
      IndependentValidationInput(
        vulnerabilityClass: VulnerabilityClass.authorization,
        proposerContextId: 'proposal-7',
        validatorContextId: 'validator-12',
        proposerDecision: IndependentValidationDecision.confirmed,
        validatorDecision: IndependentValidationDecision.rejected,
        reproductionAttempts: const [true, true],
        directEvidenceArtifactIds: const [31, 32],
        completedControls: const {
          ValidationControl.authenticatedBaseline,
          ValidationControl.unauthorizedComparison,
        },
      ),
    );

    expect(result.outcome, IndependentValidationOutcome.inconclusive);
    expect(result.reproducibilityScore, 1);
    expect(result.reason, contains('disagree'));
  });
}

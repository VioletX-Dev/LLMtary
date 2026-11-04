import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/independent_validation.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/report_generator.dart';

void main() {
  test(
    'reports persisted independent validation decisions and reproducibility',
    () {
      final project = Project(
        id: 1,
        name: 'Validation report',
        folderPath: '/tmp/validation-report',
        createdAt: DateTime.utc(2026),
        lastOpenedAt: DateTime.utc(2026),
      );
      final record = IndependentValidationRecord(
        id: 1,
        validationRunId: 8,
        projectId: 1,
        vulnerabilityId: 4,
        vulnerabilityClass: VulnerabilityClass.authorization,
        proposerContextId: 'proposal-8',
        validatorContextId: 'validator-8',
        proposerDecision: IndependentValidationDecision.confirmed,
        validatorDecision: IndependentValidationDecision.confirmed,
        outcome: IndependentValidationOutcome.confirmed,
        reproductionAttempts: const [true, true],
        reproducibilityScore: 1,
        directEvidenceArtifactIds: const [21, 22],
        completedControls: const {
          ValidationControl.authenticatedBaseline,
          ValidationControl.unauthorizedComparison,
        },
        reason: 'Independent decisions agree.',
        createdAt: DateTime.utc(2026, 11, 4),
      );

      final html = ReportGenerator.generateHtml(
        project: project,
        targets: const [],
        vulnerabilities: const [],
        independentValidations: [record],
      );
      final markdown = ReportGenerator.generateMarkdown(
        project: project,
        targets: const [],
        vulnerabilities: const [],
        independentValidations: [record],
      );

      for (final report in [html, markdown]) {
        expect(report, contains('Independent Finding Validation'));
        expect(report, contains('authorization'));
        expect(report, contains('confirmed'));
        expect(report, contains('100.0%'));
        expect(report, contains('21, 22'));
        expect(report, contains('authenticatedBaseline'));
        expect(report, isNot(contains('proposal-8')));
        expect(report, isNot(contains('validator-8')));
      }
    },
  );
}

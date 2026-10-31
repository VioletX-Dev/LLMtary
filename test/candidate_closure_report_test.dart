import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/candidate_closure.dart';
import 'package:llmtary/models/controlled_exploitation.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/models/validation_run.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/report_generator.dart';

void main() {
  test(
    'closure coverage and blockers are consistent across report formats',
    () {
      final project = Project(
        id: 1,
        name: 'Closure test',
        folderPath: '/tmp/closure',
        createdAt: DateTime.utc(2026),
        lastOpenedAt: DateTime.utc(2026),
      );
      final vulnerability = Vulnerability(
        id: 7,
        projectId: 1,
        targetAddress: '192.0.2.10',
        problem: 'Authenticated M365 Review',
        description: 'Review authenticated controls',
        severity: 'INFO',
        confidence: 'LOW',
        evidence: '',
        recommendation: 'Complete MFA',
      );
      final closure = CandidateClosure(
        vulnerabilityId: 7,
        projectId: 1,
        disposition: CandidateDisposition.blockedMfaOperatorAction,
        reasonCode: ClosureReasonCode.manualMfaRequired,
        explanation: 'Manual MFA is required.',
        remainingPrerequisites: const ['operator-completed MFA'],
        nextAction: 'Complete MFA on the appliance',
        owner: WorkOwner.operator,
        startedAt: DateTime.utc(2026),
        updatedAt: DateTime.utc(2026),
      );
      final controlled = ControlledExploitationRecord(
        vulnerabilityId: 7,
        projectId: 1,
        eligibility: ExploitationEligibility.humanValidationRequired,
        proofStatus: ControlledProofStatus.blocked,
        proofType: ControlledProofType.none,
        methodId: '',
        accessLevel: 'Human validation required beyond the automated boundary.',
        cleanupStatus: CleanupStatus.notRequired,
        startedAt: DateTime.utc(2026),
        updatedAt: DateTime.utc(2026),
      );

      final html = ReportGenerator.generateHtml(
        project: project,
        targets: const [],
        vulnerabilities: [vulnerability],
        closures: [closure],
        controlledExploitations: [controlled],
        confirmedOnly: false,
      );
      final markdown = ReportGenerator.generateMarkdown(
        project: project,
        targets: const [],
        vulnerabilities: [vulnerability],
        closures: [closure],
        controlledExploitations: [controlled],
        confirmedOnly: false,
      );
      final csv = ReportGenerator.generateCsv(
        vulnerabilities: [vulnerability],
        closures: [closure],
        controlledExploitations: [controlled],
      );
      for (final report in [html, markdown, csv]) {
        expect(report, contains('blockedMfaOperatorAction'));
        expect(report, contains('manualMfaRequired'));
        expect(report, contains('Complete MFA on the appliance'));
        expect(report, contains('100%'));
        expect(report, contains('humanValidationRequired'));
        expect(report, contains('blocked'));
      }
    },
  );

  test('reports deep validation assurance and inconclusive coverage', () {
    final project = Project(
      id: 1,
      name: 'Deep assessment',
      folderPath: '/tmp/deep',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );
    final vulnerability = Vulnerability(
      id: 7,
      projectId: 1,
      targetId: 2,
      targetAddress: '192.0.2.10',
      problem: 'TLS weakness',
      description: 'Validate TLS.',
      severity: 'HIGH',
      confidence: 'LOW',
      evidence: '',
      recommendation: 'Harden TLS.',
    );
    final run = ValidationRun(
      projectId: 1,
      targetId: 2,
      vulnerabilityId: 7,
      mode: ValidationRunMode.assessment,
      title: 'Deep validation: TLS weakness',
      objective: 'Obtain claim-specific evidence.',
      constraints: 'Human-supervised; exact-command approval required.',
      statusBefore: 'pending',
      statusAfter: 'undetermined',
      outcome: ValidationRunOutcome.inconclusive,
      summary: 'Two safe methods exhausted without direct proof.',
      startedAt: DateTime.utc(2026),
      completedAt: DateTime.utc(2026, 1, 1, 0, 5),
    );

    final html = ReportGenerator.generateHtml(
      project: project,
      targets: const [],
      vulnerabilities: [vulnerability],
      validationRuns: [run],
      confirmedOnly: false,
    );
    final markdown = ReportGenerator.generateMarkdown(
      project: project,
      targets: const [],
      vulnerabilities: [vulnerability],
      validationRuns: [run],
      confirmedOnly: false,
    );

    for (final report in [html, markdown]) {
      expect(report, contains('Validation Assurance and Coverage'));
      expect(
        report,
        contains('AI-operated under continuous human supervision'),
      );
      expect(report, contains('Inconclusive'));
      expect(report, contains('1'));
      expect(report, contains('tool failure'));
    }
  });
}

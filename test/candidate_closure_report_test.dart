import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/candidate_closure.dart';
import 'package:llmtary/models/controlled_exploitation.dart';
import 'package:llmtary/models/project.dart';
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
}

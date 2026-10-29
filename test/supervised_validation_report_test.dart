import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/assessment_narrative_service.dart';
import 'package:llmtary/services/report_generator.dart';

void main() {
  test('reports include a dedicated supervised AI validation section', () {
    final project = Project(
      id: 1,
      name: 'Supervised validation report',
      folderPath: '/tmp/supervised-report',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );
    final entry = AssessmentTimelineEntry(
      timestamp: DateTime.utc(2026, 10, 29, 19),
      phase: 'HUMAN-SUPERVISED AI VALIDATION',
      target: '172.17.2.8',
      finding: 'SMB validation',
      action: 'AI-operated bounded hostname check',
      rationale: 'Validate exact authorized remote access',
      observation: 'operator=observer; authorization=ENG-1',
      verification:
          'evidence/before.png; evidence/during.png; evidence/after.png',
      result: 'completed',
      disposition: 'closed with cleanup verified and human evidence review',
      sourceType: 'supervised_validation_event',
    );

    final html = ReportGenerator.generateHtml(
      project: project,
      targets: const [],
      vulnerabilities: const [],
      assessmentTimeline: [entry],
      confirmedOnly: false,
    );
    final markdown = ReportGenerator.generateMarkdown(
      project: project,
      targets: const [],
      vulnerabilities: const [],
      assessmentTimeline: [entry],
      confirmedOnly: false,
    );

    for (final report in [html, markdown]) {
      expect(report, contains('Human-Supervised, AI-Operated Validation'));
      expect(report, contains('172.17.2.8'));
      expect(report, contains('ENG-1'));
      expect(report, contains('before.png'));
      expect(report, contains('cleanup verified'));
    }
  });
}

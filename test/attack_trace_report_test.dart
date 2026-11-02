import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/attack_trace.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/report_generator.dart';

void main() {
  test('reports deterministic graph-backed attack traces', () {
    final project = Project(
      id: 1,
      name: 'Trace report',
      folderPath: '/tmp/trace-report',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );
    final sensitiveOutput =
        'Authorization: Bearer report-secret\n${List.filled(5000, 'A').join()}';
    final graph = AttackTraceGraph(
      trace: AttackTrace(
        id: 5,
        projectId: 1,
        targetId: 2,
        vulnerabilityId: 7,
        title: 'Authorization boundary validation',
        status: AttackTraceStatus.completed,
        startedAt: DateTime.utc(2026, 11, 1, 19),
        completedAt: DateTime.utc(2026, 11, 1, 19, 5),
      ),
      steps: [
        AttackTraceStep(
          id: 10,
          traceId: 5,
          sequence: 1,
          stepKey: 'browser-1',
          kind: AttackTraceStepKind.browserAction,
          action: 'navigate https://app.example.test/account',
          output: sensitiveOutput,
          evidenceArtifactIds: const [41],
          createdAt: DateTime.utc(2026, 11, 1, 19, 1),
        ),
        AttackTraceStep(
          id: 11,
          traceId: 5,
          sequence: 2,
          stepKey: 'validator-1',
          parentStepKeys: const ['browser-1'],
          kind: AttackTraceStepKind.validatorResult,
          interpretation: 'Independently reproduced.',
          validatorResult: AttackTraceValidatorResult.confirmed,
          validationRunId: 19,
          createdAt: DateTime.utc(2026, 11, 1, 19, 2),
        ),
      ],
    );

    final html = ReportGenerator.generateHtml(
      project: project,
      targets: const [],
      vulnerabilities: const [],
      attackTraces: [graph],
    );
    final markdown = ReportGenerator.generateMarkdown(
      project: project,
      targets: const [],
      vulnerabilities: const [],
      attackTraces: [graph],
    );

    for (final report in [html, markdown]) {
      expect(report, contains('Graph-Backed Attack Traces'));
      expect(report, contains('Authorization boundary validation'));
      expect(report, contains('browser-1'));
      expect(report, contains('validator-1'));
      expect(report, contains('Evidence: 41'));
      expect(report, contains('confirmed'));
      expect(report, isNot(contains('report-secret')));
      expect(report, contains('[REDACTED]'));
      expect(report, contains('[truncated]'));
    }
  });
}

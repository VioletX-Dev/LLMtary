import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/attack_trace.dart';
import 'package:llmtary/models/context_artifact.dart';
import 'package:llmtary/widgets/assessment_context_dialog.dart';

void main() {
  testWidgets('shows ingested context and graph-backed trace summaries', (
    tester,
  ) async {
    final artifact = ContextArtifact(
      id: 3,
      projectId: 1,
      type: ContextArtifactType.apiSpecification,
      originalFileName: 'service.openapi.yaml',
      sha256: 'a' * 64,
      sizeBytes: 120,
      extractionMethod: 'openapi-yaml-deterministic',
      ingestedAt: DateTime.utc(2026, 11, 1),
    );
    final graph = AttackTraceGraph(
      trace: AttackTrace(
        id: 7,
        projectId: 1,
        targetId: 2,
        title: 'Authorization validation',
        status: AttackTraceStatus.running,
        startedAt: DateTime.utc(2026, 11, 1),
      ),
      steps: [
        AttackTraceStep(
          traceId: 7,
          stepKey: 'browser-1',
          kind: AttackTraceStepKind.browserAction,
          createdAt: DateTime.utc(2026, 11, 1),
        ),
      ],
    );

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AssessmentContextDialog(artifacts: [artifact], traces: [graph]),
        ),
      ),
    );

    expect(find.text('Assessment Context & Attack Traces'), findsOneWidget);
    expect(find.text('service.openapi.yaml'), findsOneWidget);
    expect(find.textContaining('apiSpecification'), findsOneWidget);
    expect(find.text('Authorization validation'), findsOneWidget);
    expect(find.textContaining('1 step'), findsOneWidget);
  });
}

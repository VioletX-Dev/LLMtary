import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/widgets/evidence_dialog.dart';

void main() {
  testWidgets('evidence dialog exposes capture and import workflow', (
    tester,
  ) async {
    final project = Project(
      id: 3,
      name: 'Test',
      folderPath: '/tmp/test',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );
    final finding = Vulnerability(
      id: 12,
      projectId: 3,
      problem: 'Authentication bypass',
      description: 'Description',
      severity: 'HIGH',
      confidence: 'HIGH',
      evidence: 'Evidence',
      recommendation: 'Fix it',
    );

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: EvidenceDialog(
            project: project,
            vulnerability: finding,
            loadEvidence: () async => const [],
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('VISUAL EVIDENCE'), findsOneWidget);
    expect(find.text('Evidence caption'), findsOneWidget);
    expect(find.text('Capture Screen (3s)'), findsOneWidget);
    expect(find.text('Import Image'), findsOneWidget);
    expect(find.textContaining('passwords, tokens, cookies'), findsOneWidget);
    expect(find.text('Save Reviewed Evidence'), findsOneWidget);
    expect(
      find.text('No visual evidence attached to this finding.'),
      findsOneWidget,
    );
  });
}

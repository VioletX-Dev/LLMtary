import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/attack_trace.dart';
import 'package:llmtary/models/browser_test.dart';
import 'package:llmtary/models/independent_validation.dart';
import 'package:llmtary/services/attack_trace_recorder.dart';
import 'package:llmtary/services/attack_trace_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  sqfliteFfiInit();

  test(
    'records browser evidence, validator result, and cleanup in one graph',
    () async {
      final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
      addTearDown(db.close);
      await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
      await db.execute(
        'CREATE TABLE targets (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL)',
      );
      await db.execute(
        'CREATE TABLE vulnerabilities ('
        'id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL, targetId INTEGER NOT NULL)',
      );
      await db.insert('projects', {'id': 3});
      await db.insert('targets', {'id': 7, 'projectId': 3});
      await db.insert('vulnerabilities', {
        'id': 11,
        'projectId': 3,
        'targetId': 7,
      });
      await AttackTraceRepository.createTables(db);
      final repository = AttackTraceRepository(db);
      final traceId = await repository.begin(
        AttackTrace(
          projectId: 3,
          targetId: 7,
          vulnerabilityId: 11,
          title: 'Browser authorization validation',
          startedAt: DateTime.utc(2026, 11, 1, 19),
        ),
      );
      final recorder = AttackTraceRecorder(repository);

      await recorder.recordBrowserAction(
        traceId: traceId,
        stepKey: 'browser-1',
        record: const BrowserActionRecord(
          kind: BrowserActionKind.navigate,
          action: 'navigate https://app.example.test/account',
          roleId: 'peer-user',
          finalUrl: 'https://app.example.test/account?token=browser-secret',
          statusCode: 200,
          domSha256: 'abc123',
          evidenceArtifactIds: [41],
        ),
        createdAt: DateTime.utc(2026, 11, 1, 19, 1),
      );
      await recorder.recordValidation(
        traceId: traceId,
        stepKey: 'validator-1',
        parentStepKeys: const ['browser-1'],
        validationRunId: 19,
        record: IndependentValidationRecord(
          validationRunId: 19,
          projectId: 3,
          vulnerabilityId: 11,
          vulnerabilityClass: VulnerabilityClass.authorization,
          proposerContextId: 'proposal-1',
          validatorContextId: 'validator-1',
          proposerDecision: IndependentValidationDecision.confirmed,
          validatorDecision: IndependentValidationDecision.confirmed,
          outcome: IndependentValidationOutcome.confirmed,
          reproductionAttempts: const [true, true],
          reproducibilityScore: 1,
          directEvidenceArtifactIds: const [41, 42],
          completedControls: const {
            ValidationControl.authenticatedBaseline,
            ValidationControl.unauthorizedComparison,
          },
          reason: 'Independent decisions agree.',
          createdAt: DateTime.utc(2026, 11, 1, 19, 2),
        ),
      );
      await recorder.recordCommand(
        traceId: traceId,
        stepKey: 'command-1',
        parentStepKeys: const ['validator-1'],
        command: 'curl https://app.example.test/account',
        output: 'Authorization: Bearer persistence-secret',
        createdAt: DateTime.utc(2026, 11, 1, 19, 2, 30),
      );
      await recorder.recordCleanup(
        traceId: traceId,
        stepKey: 'cleanup-1',
        parentStepKeys: const ['command-1'],
        action: 'Close browser context and clear cookies.',
        verified: true,
        createdAt: DateTime.utc(2026, 11, 1, 19, 3),
      );

      final graph = await repository.graph(traceId);
      expect(graph.steps.map((step) => step.kind), [
        AttackTraceStepKind.browserAction,
        AttackTraceStepKind.validatorResult,
        AttackTraceStepKind.command,
        AttackTraceStepKind.cleanup,
      ]);
      expect(graph.steps.first.evidenceArtifactIds, [41]);
      expect(graph.steps.first.output, isNot(contains('browser-secret')));
      expect(graph.steps.first.output, contains('[REDACTED]'));
      expect(
        graph.steps[1].validatorResult,
        AttackTraceValidatorResult.confirmed,
      );
      expect(graph.steps[1].validationRunId, 19);
      expect(graph.steps[2].output, isNot(contains('persistence-secret')));
      expect(graph.steps[2].output, contains('[REDACTED]'));
      expect(graph.steps.last.cleanupStatus, 'verified');
    },
  );
}

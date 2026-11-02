import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/attack_trace.dart';
import 'package:llmtary/services/attack_trace_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  sqfliteFfiInit();

  test('attack trace repository persists a branched evidence graph', () async {
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
        title: 'Authorization boundary validation',
        startedAt: DateTime.utc(2026, 10, 31, 16),
      ),
    );

    await repository.append(
      AttackTraceStep(
        traceId: traceId,
        stepKey: 'hypothesis-1',
        kind: AttackTraceStepKind.hypothesis,
        hypothesis: 'A peer user may read another account.',
        tactic: 'authorization-boundary',
        createdAt: DateTime.utc(2026, 10, 31, 16, 1),
      ),
    );
    await repository.append(
      AttackTraceStep(
        traceId: traceId,
        stepKey: 'request-1',
        parentStepKeys: const ['hypothesis-1'],
        kind: AttackTraceStepKind.browserAction,
        action: 'GET /accounts/peer',
        output: 'HTTP 403',
        interpretation: 'Peer object was rejected.',
        evidenceArtifactIds: const [41],
        createdAt: DateTime.utc(2026, 10, 31, 16, 2),
      ),
    );
    await repository.append(
      AttackTraceStep(
        traceId: traceId,
        stepKey: 'control-1',
        parentStepKeys: const ['hypothesis-1'],
        kind: AttackTraceStepKind.controlRequest,
        action: 'GET /accounts/self',
        output: 'HTTP 200',
        interpretation: 'The authenticated control request succeeded.',
        evidenceArtifactIds: const [42],
        createdAt: DateTime.utc(2026, 10, 31, 16, 3),
      ),
    );
    await repository.append(
      AttackTraceStep(
        traceId: traceId,
        stepKey: 'validator-1',
        parentStepKeys: const ['request-1', 'control-1'],
        kind: AttackTraceStepKind.validatorResult,
        validatorResult: AttackTraceValidatorResult.rejected,
        interpretation: 'Direct request rejected while control succeeded.',
        validationRunId: 19,
        createdAt: DateTime.utc(2026, 10, 31, 16, 4),
      ),
    );

    final graph = await repository.graph(traceId);
    expect(graph.trace.id, traceId);
    expect(graph.steps.map((step) => step.stepKey), [
      'hypothesis-1',
      'request-1',
      'control-1',
      'validator-1',
    ]);
    expect(graph.parentsOf('validator-1'), {'request-1', 'control-1'});
    expect(graph.childrenOf('hypothesis-1'), {'request-1', 'control-1'});
    expect(graph.steps[1].evidenceArtifactIds, [41]);
    expect(graph.steps.last.validationRunId, 19);
  });

  test('attack trace rejects missing parents and cross-project findings', () async {
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
    await db.insert('projects', {'id': 1});
    await db.insert('projects', {'id': 2});
    await db.insert('targets', {'id': 4, 'projectId': 1});
    await db.insert('vulnerabilities', {
      'id': 8,
      'projectId': 2,
      'targetId': 4,
    });
    await AttackTraceRepository.createTables(db);
    final repository = AttackTraceRepository(db);

    await expectLater(
      repository.begin(
        AttackTrace(
          projectId: 1,
          targetId: 4,
          vulnerabilityId: 8,
          title: 'Wrong finding',
          startedAt: DateTime.utc(2026),
        ),
      ),
      throwsStateError,
    );

    final traceId = await repository.begin(
      AttackTrace(
        projectId: 1,
        targetId: 4,
        title: 'Valid trace',
        startedAt: DateTime.utc(2026),
      ),
    );
    await expectLater(
      repository.append(
        AttackTraceStep(
          traceId: traceId,
          stepKey: 'orphan',
          parentStepKeys: const ['missing'],
          kind: AttackTraceStepKind.interpretation,
          createdAt: DateTime.utc(2026),
        ),
      ),
      throwsStateError,
    );
  });
}

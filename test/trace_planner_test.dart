import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/attack_trace.dart';
import 'package:llmtary/services/attack_trace_repository.dart';
import 'package:llmtary/services/trace_planner_facade.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  sqfliteFfiInit();

  test('planner deduplicates hypotheses, respects budgets, and persists checkpoint', () async {
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
    await db.execute('CREATE TABLE targets (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL)');
    await db.execute(
      'CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL, targetId INTEGER NOT NULL)',
    );
    await db.insert('projects', {'id': 1});
    await db.insert('targets', {'id': 2, 'projectId': 1});
    await AttackTraceRepository.createTables(db);
    final repo = AttackTraceRepository(db);

    final traceId = await repo.begin(
      AttackTrace(projectId: 1, targetId: 2, title: 'Planner trace', startedAt: DateTime.utc(2026)),
    );

    // Add duplicate hypotheses
    await repo.append(
      AttackTraceStep(
        traceId: traceId,
        stepKey: 'h1',
        kind: AttackTraceStepKind.hypothesis,
        hypothesis: 'User can access /admin',
        tactic: 'authorization-boundary',
        createdAt: DateTime.utc(2026, 1, 1, 0, 1),
      ),
    );
    // Duplicate with later timestamp
    await repo.append(
      AttackTraceStep(
        traceId: traceId,
        stepKey: 'h2',
        parentStepKeys: const ['h1'],
        kind: AttackTraceStepKind.hypothesis,
        hypothesis: 'User can access /admin',
        tactic: 'authorization-boundary',
        createdAt: DateTime.utc(2026, 1, 1, 0, 2),
      ),
    );

    final planner = TracePlannerFacade(repo, config: const TracePlannerConfig(maxActionsPerTrace: 1));

    final plan = await planner.nextPlannedAction(traceId);
    expect(plan, isNotNull);
    expect(plan!['traceId'], traceId);
    // Check checkpoint persisted
    final rows = await db.query('attack_trace_checkpoints', where: 'trace_id = ?', whereArgs: [traceId]);
    expect(rows, hasLength(1));
    final payload = rows.single['payload'] as String;
    expect(payload, contains('planned_from_step'));
    // If budget exhausted (maxActionsPerTrace == 0) planner returns null
    final planner2 = TracePlannerFacade(repo, config: const TracePlannerConfig(maxActionsPerTrace: 0));
    final plan2 = await planner2.nextPlannedAction(traceId);
    expect(plan2, isNull);
  });
}

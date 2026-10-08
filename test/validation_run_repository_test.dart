import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/validation_run.dart';
import 'package:llmtary/services/validation_run_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  sqfliteFfiInit();

  test(
    'validation run repository persists project and finding history',
    () async {
      final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
      addTearDown(db.close);
      await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
      await db.execute(
        'CREATE TABLE vulnerabilities ('
        'id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL)',
      );
      await db.insert('projects', {'id': 3});
      await db.insert('projects', {'id': 4});
      await db.insert('vulnerabilities', {'id': 12, 'projectId': 3});
      await ValidationRunRepository.createTable(db);
      final repository = ValidationRunRepository(db);

      ValidationRun run(DateTime at, {int? finding = 12}) => ValidationRun(
        projectId: 3,
        targetId: 7,
        vulnerabilityId: finding,
        mode: finding == null
            ? ValidationRunMode.spotTest
            : ValidationRunMode.retest,
        title: finding == null ? 'TLS spot test' : 'Retest finding',
        objective: 'Validate one condition.',
        startedAt: at,
      );

      final olderId = await repository.insert(run(DateTime.utc(2026, 1, 1)));
      await repository.insert(run(DateTime.utc(2026, 1, 2)));
      await repository.insert(run(DateTime.utc(2026, 1, 3), finding: null));

      final findingRuns = await repository.forVulnerability(12);
      expect(findingRuns.map((item) => item.startedAt), [
        DateTime.utc(2026, 1, 2),
        DateTime.utc(2026, 1, 1),
      ]);
      expect(await repository.forProject(3), hasLength(3));

      final completed = findingRuns.first.copyWith(
        outcome: ValidationRunOutcome.fixed,
        statusAfter: 'notVulnerable',
        summary: 'No longer reproducible.',
        completedAt: DateTime.utc(2026, 1, 2, 0, 5),
      );
      await repository.update(completed);
      expect(
        (await repository.forVulnerability(12)).first.outcome,
        ValidationRunOutcome.fixed,
      );

      await expectLater(
        repository.insert(
          ValidationRun(
            projectId: 4,
            targetId: 9,
            vulnerabilityId: 12,
            mode: ValidationRunMode.retest,
            title: 'Wrong project',
            objective: 'Should fail.',
            startedAt: DateTime.utc(2026, 1, 4),
          ),
        ),
        throwsStateError,
      );

      expect(await repository.delete(olderId), 1);
      expect(await repository.forVulnerability(12), hasLength(1));
    },
  );
}

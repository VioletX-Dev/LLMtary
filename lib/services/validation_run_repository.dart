import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/validation_run.dart';

class ValidationRunRepository {
  final Database db;

  const ValidationRunRepository(this.db);

  static Future<void> createTable(Database db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS validation_runs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        projectId INTEGER NOT NULL,
        targetId INTEGER NOT NULL,
        vulnerabilityId INTEGER,
        mode TEXT NOT NULL,
        title TEXT NOT NULL,
        objective TEXT NOT NULL,
        parameters TEXT NOT NULL DEFAULT '',
        expectedResult TEXT NOT NULL DEFAULT '',
        constraints TEXT NOT NULL DEFAULT '',
        statusBefore TEXT NOT NULL DEFAULT '',
        baselineStatusReason TEXT NOT NULL DEFAULT '',
        baselineProofCommand TEXT NOT NULL DEFAULT '',
        baselineProofOutput TEXT NOT NULL DEFAULT '',
        statusAfter TEXT NOT NULL DEFAULT '',
        outcome TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '',
        startedAt TEXT NOT NULL,
        completedAt TEXT,
        FOREIGN KEY (projectId) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (vulnerabilityId) REFERENCES vulnerabilities(id) ON DELETE SET NULL
      )
    ''');
    await db.execute(
      'CREATE INDEX IF NOT EXISTS idx_validation_runs_project '
      'ON validation_runs(projectId, startedAt DESC)',
    );
    await db.execute(
      'CREATE INDEX IF NOT EXISTS idx_validation_runs_vulnerability '
      'ON validation_runs(vulnerabilityId, startedAt DESC)',
    );
  }

  Future<int> insert(ValidationRun run) async {
    await _validateFindingProject(run);
    final map = Map<String, dynamic>.from(run.toMap())..remove('id');
    return db.insert('validation_runs', map);
  }

  Future<void> update(ValidationRun run) async {
    final id = run.id;
    if (id == null) throw ArgumentError('Validation run id is required.');
    await _validateFindingProject(run);
    final map = Map<String, dynamic>.from(run.toMap())..remove('id');
    final changed = await db.update(
      'validation_runs',
      map,
      where: 'id = ? AND projectId = ?',
      whereArgs: [id, run.projectId],
    );
    if (changed != 1) throw StateError('Validation run was not found.');
  }

  Future<List<ValidationRun>> forProject(int projectId) async {
    final maps = await db.query(
      'validation_runs',
      where: 'projectId = ?',
      whereArgs: [projectId],
      orderBy: 'startedAt DESC, id DESC',
    );
    return maps.map(ValidationRun.fromMap).toList();
  }

  Future<List<ValidationRun>> forVulnerability(int vulnerabilityId) async {
    final maps = await db.query(
      'validation_runs',
      where: 'vulnerabilityId = ?',
      whereArgs: [vulnerabilityId],
      orderBy: 'startedAt DESC, id DESC',
    );
    return maps.map(ValidationRun.fromMap).toList();
  }

  Future<int> delete(int id) =>
      db.delete('validation_runs', where: 'id = ?', whereArgs: [id]);

  Future<void> _validateFindingProject(ValidationRun run) async {
    final vulnerabilityId = run.vulnerabilityId;
    if (vulnerabilityId == null) return;
    final rows = await db.query(
      'vulnerabilities',
      columns: ['projectId'],
      where: 'id = ?',
      whereArgs: [vulnerabilityId],
      limit: 1,
    );
    if (rows.isEmpty || rows.single['projectId'] != run.projectId) {
      throw StateError(
        'Validation run finding does not belong to its project.',
      );
    }
  }
}

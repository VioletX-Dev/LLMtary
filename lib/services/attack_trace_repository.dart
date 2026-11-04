import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/attack_trace.dart';

class AttackTraceRepository {
  final Database db;

  const AttackTraceRepository(this.db);

  static Future<void> createTables(DatabaseExecutor db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS attack_traces (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        target_id INTEGER NOT NULL,
        vulnerability_id INTEGER,
        title TEXT NOT NULL,
        status TEXT NOT NULL,
        summary TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL,
        completed_at TEXT,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE SET NULL
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS attack_trace_steps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_id INTEGER NOT NULL,
        sequence_no INTEGER NOT NULL,
        step_key TEXT NOT NULL,
        kind TEXT NOT NULL,
        hypothesis TEXT NOT NULL DEFAULT '',
        tactic TEXT NOT NULL DEFAULT '',
        action TEXT NOT NULL DEFAULT '',
        output TEXT NOT NULL DEFAULT '',
        interpretation TEXT NOT NULL DEFAULT '',
        adaptation TEXT NOT NULL DEFAULT '',
        evidence_artifact_ids TEXT NOT NULL DEFAULT '[]',
        validation_run_id INTEGER,
        validator_result TEXT NOT NULL DEFAULT 'notRun',
        cleanup_status TEXT NOT NULL DEFAULT '',
        metadata TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        FOREIGN KEY (trace_id) REFERENCES attack_traces(id) ON DELETE CASCADE,
        UNIQUE(trace_id, step_key),
        UNIQUE(trace_id, sequence_no)
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS attack_trace_edges (
        trace_id INTEGER NOT NULL,
        parent_step_id INTEGER NOT NULL,
        child_step_id INTEGER NOT NULL,
        FOREIGN KEY (trace_id) REFERENCES attack_traces(id) ON DELETE CASCADE,
        FOREIGN KEY (parent_step_id) REFERENCES attack_trace_steps(id) ON DELETE CASCADE,
        FOREIGN KEY (child_step_id) REFERENCES attack_trace_steps(id) ON DELETE CASCADE,
        PRIMARY KEY (trace_id, parent_step_id, child_step_id)
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS attack_trace_checkpoints (
        trace_id INTEGER NOT NULL,
        checkpoint_key TEXT NOT NULL,
        payload TEXT NOT NULL DEFAULT '{}',
        created_at TEXT NOT NULL,
        PRIMARY KEY (trace_id, checkpoint_key),
        FOREIGN KEY (trace_id) REFERENCES attack_traces(id) ON DELETE CASCADE
      )
    ''');
    await db.execute(
      'CREATE INDEX IF NOT EXISTS idx_attack_traces_project '
      'ON attack_traces(project_id, target_id, vulnerability_id)',
    );
    await db.execute(
      'CREATE INDEX IF NOT EXISTS idx_attack_steps_trace '
      'ON attack_trace_steps(trace_id, sequence_no)',
    );
  }

  Future<int> begin(AttackTrace trace) async {
    await _validateOwnership(trace);
    final map = trace.toMap()..remove('id');
    return db.insert('attack_traces', map);
  }

  Future<int> append(AttackTraceStep step) => db.transaction((txn) async {
    final traceRows = await txn.query(
      'attack_traces',
      columns: const ['id'],
      where: 'id = ?',
      whereArgs: [step.traceId],
      limit: 1,
    );
    if (traceRows.isEmpty) throw StateError('Attack trace does not exist.');

    final parentRows = <String, int>{};
    for (final parentKey in step.parentStepKeys.toSet()) {
      final rows = await txn.query(
        'attack_trace_steps',
        columns: const ['id', 'step_key'],
        where: 'trace_id = ? AND step_key = ?',
        whereArgs: [step.traceId, parentKey],
        limit: 1,
      );
      if (rows.isEmpty) {
        throw StateError('Attack trace parent does not exist: $parentKey');
      }
      parentRows[parentKey] = rows.single['id'] as int;
    }

    final sequenceRows = await txn.rawQuery(
      'SELECT COALESCE(MAX(sequence_no), 0) + 1 AS next_sequence '
      'FROM attack_trace_steps WHERE trace_id = ?',
      [step.traceId],
    );
    final sequence = sequenceRows.single['next_sequence'] as int;
    final map = step.toMap()
      ..remove('id')
      ..['sequence_no'] = sequence;
    final childId = await txn.insert('attack_trace_steps', map);
    for (final parentId in parentRows.values) {
      await txn.insert('attack_trace_edges', {
        'trace_id': step.traceId,
        'parent_step_id': parentId,
        'child_step_id': childId,
      });
    }
    return childId;
  });

  Future<AttackTraceGraph> graph(int traceId) async {
    final traceRows = await db.query(
      'attack_traces',
      where: 'id = ?',
      whereArgs: [traceId],
      limit: 1,
    );
    if (traceRows.isEmpty) throw StateError('Attack trace does not exist.');
    final stepRows = await db.query(
      'attack_trace_steps',
      where: 'trace_id = ?',
      whereArgs: [traceId],
      orderBy: 'sequence_no ASC',
    );
    final edgeRows = await db.rawQuery('''
      SELECT parent.step_key AS parent_key, child.step_key AS child_key
      FROM attack_trace_edges edge
      JOIN attack_trace_steps parent ON parent.id = edge.parent_step_id
      JOIN attack_trace_steps child ON child.id = edge.child_step_id
      WHERE edge.trace_id = ?
    ''', [traceId]);
    final parentsByChild = <String, List<String>>{};
    for (final edge in edgeRows) {
      final child = edge['child_key'] as String;
      parentsByChild.putIfAbsent(child, () => []).add(
        edge['parent_key'] as String,
      );
    }
    final steps = stepRows
        .map(
          (row) => AttackTraceStep.fromMap(
            row,
            parentStepKeys: List.unmodifiable(
              parentsByChild[row['step_key'] as String] ?? const <String>[],
            ),
          ),
        )
        .toList(growable: false);
    return AttackTraceGraph(
      trace: AttackTrace.fromMap(traceRows.single),
      steps: steps,
    );
  }

  Future<List<AttackTrace>> forProject(int projectId) async {
    final rows = await db.query(
      'attack_traces',
      where: 'project_id = ?',
      whereArgs: [projectId],
      orderBy: 'started_at DESC, id DESC',
    );
    return rows.map(AttackTrace.fromMap).toList(growable: false);
  }

  Future<void> _validateOwnership(AttackTrace trace) async {
    final targetRows = await db.query(
      'targets',
      columns: const ['projectId'],
      where: 'id = ?',
      whereArgs: [trace.targetId],
      limit: 1,
    );
    if (targetRows.isEmpty || targetRows.single['projectId'] != trace.projectId) {
      throw StateError('Attack trace target does not belong to its project.');
    }
    final findingId = trace.vulnerabilityId;
    if (findingId == null) return;
    final findingRows = await db.query(
      'vulnerabilities',
      columns: const ['projectId', 'targetId'],
      where: 'id = ?',
      whereArgs: [findingId],
      limit: 1,
    );
    if (findingRows.isEmpty ||
        findingRows.single['projectId'] != trace.projectId ||
        findingRows.single['targetId'] != trace.targetId) {
      throw StateError('Attack trace finding does not belong to its target.');
    }
  }
}

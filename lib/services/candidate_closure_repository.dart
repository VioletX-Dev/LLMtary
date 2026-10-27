import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/candidate_closure.dart';
import '../models/human_validation_work_item.dart';

class CandidateClosureRepository {
  final Database db;
  const CandidateClosureRepository(this.db);

  static Future<void> migrate(Database db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS candidate_closures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vulnerability_id INTEGER NOT NULL UNIQUE,
        project_id INTEGER NOT NULL,
        disposition TEXT NOT NULL,
        reason_code TEXT NOT NULL,
        explanation TEXT NOT NULL DEFAULT '',
        attempted_methods TEXT NOT NULL DEFAULT '[]',
        successful_observations TEXT NOT NULL DEFAULT '[]',
        failed_observations TEXT NOT NULL DEFAULT '[]',
        remaining_prerequisites TEXT NOT NULL DEFAULT '[]',
        next_action TEXT NOT NULL DEFAULT '',
        owner TEXT NOT NULL DEFAULT 'platform',
        retry_budget INTEGER NOT NULL DEFAULT 3,
        tool_budget INTEGER NOT NULL DEFAULT 3,
        request_budget INTEGER NOT NULL DEFAULT 8,
        retries_used INTEGER NOT NULL DEFAULT 0,
        tools_used INTEGER NOT NULL DEFAULT 0,
        requests_used INTEGER NOT NULL DEFAULT 0,
        stopping_reason TEXT NOT NULL DEFAULT '',
        started_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    ''');
    await db.execute('''
      CREATE INDEX IF NOT EXISTS idx_candidate_closures_project
      ON candidate_closures(project_id, disposition)
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS human_validation_work_items (
        id TEXT PRIMARY KEY,
        project_id INTEGER NOT NULL,
        vulnerability_id INTEGER NOT NULL,
        title TEXT NOT NULL,
        authorization_required TEXT NOT NULL DEFAULT '',
        evidence_requested TEXT NOT NULL DEFAULT '[]',
        safety_notes TEXT NOT NULL DEFAULT '',
        owner TEXT NOT NULL,
        status TEXT NOT NULL,
        evidence_references TEXT NOT NULL DEFAULT '[]',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    ''');
    await db.execute('''
      CREATE INDEX IF NOT EXISTS idx_human_validation_project
      ON human_validation_work_items(project_id, status)
    ''');
    // Deliberately no legacy backfill here. A migration cannot infer why an
    // old candidate remained unresolved without the bounded attempt ledger.
  }

  Future<void> upsertClosure(CandidateClosure closure) async {
    final map = Map<String, dynamic>.from(closure.toMap())..remove('id');
    await db.insert(
      'candidate_closures',
      map,
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<List<CandidateClosure>> getClosures(int projectId) async {
    final rows = await db.query(
      'candidate_closures',
      where: 'project_id = ?',
      whereArgs: [projectId],
      orderBy: 'vulnerability_id ASC',
    );
    return rows.map(CandidateClosure.fromMap).toList(growable: false);
  }

  Future<CandidateClosure?> getClosure(int vulnerabilityId) async {
    final rows = await db.query(
      'candidate_closures',
      where: 'vulnerability_id = ?',
      whereArgs: [vulnerabilityId],
      limit: 1,
    );
    return rows.isEmpty ? null : CandidateClosure.fromMap(rows.single);
  }

  Future<void> upsertWorkItem(HumanValidationWorkItem item) async {
    await db.insert(
      'human_validation_work_items',
      item.toMap(),
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  Future<List<HumanValidationWorkItem>> getWorkItems(int projectId) async {
    final rows = await db.query(
      'human_validation_work_items',
      where: 'project_id = ?',
      whereArgs: [projectId],
      orderBy: 'updated_at ASC, id ASC',
    );
    return rows.map(HumanValidationWorkItem.fromMap).toList(growable: false);
  }
}

import 'dart:convert';

import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/independent_validation.dart';

class IndependentValidationRepository {
  final Database db;

  const IndependentValidationRepository(this.db);

  static Future<void> createTable(DatabaseExecutor db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS independent_validation_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        validation_run_id INTEGER NOT NULL UNIQUE,
        project_id INTEGER NOT NULL,
        vulnerability_id INTEGER,
        vulnerability_class TEXT NOT NULL,
        proposer_context_id TEXT NOT NULL,
        validator_context_id TEXT NOT NULL,
        proposer_decision TEXT NOT NULL,
        validator_decision TEXT NOT NULL,
        outcome TEXT NOT NULL,
        reproduction_attempts TEXT NOT NULL DEFAULT '[]',
        reproducibility_score REAL NOT NULL,
        direct_evidence_artifact_ids TEXT NOT NULL DEFAULT '[]',
        completed_controls TEXT NOT NULL DEFAULT '[]',
        missing_controls TEXT NOT NULL DEFAULT '[]',
        reason TEXT NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (validation_run_id) REFERENCES validation_runs(id) ON DELETE CASCADE
      )
    ''');
    await db.execute(
      'CREATE INDEX IF NOT EXISTS idx_independent_validation_project '
      'ON independent_validation_results(project_id, vulnerability_id)',
    );
  }

  Future<int> persist(IndependentValidationRecord record) async {
    if (record.proposerContextId.trim().isEmpty ||
        record.validatorContextId.trim().isEmpty ||
        record.proposerContextId == record.validatorContextId) {
      throw ArgumentError('Independent validation contexts must be separate.');
    }
    final runs = await db.query(
      'validation_runs',
      columns: const ['projectId', 'vulnerabilityId'],
      where: 'id = ?',
      whereArgs: [record.validationRunId],
      limit: 1,
    );
    if (runs.isEmpty ||
        runs.single['projectId'] != record.projectId ||
        runs.single['vulnerabilityId'] != record.vulnerabilityId) {
      throw StateError('Independent result does not match its validation run.');
    }
    return db.insert('independent_validation_results', _toMap(record));
  }

  Future<IndependentValidationRecord> forValidationRun(
    int validationRunId,
  ) async {
    final rows = await db.query(
      'independent_validation_results',
      where: 'validation_run_id = ?',
      whereArgs: [validationRunId],
      limit: 1,
    );
    if (rows.isEmpty) {
      throw StateError('Independent validation result does not exist.');
    }
    return _fromMap(rows.single);
  }

  Map<String, Object?> _toMap(IndependentValidationRecord record) => {
    'validation_run_id': record.validationRunId,
    'project_id': record.projectId,
    'vulnerability_id': record.vulnerabilityId,
    'vulnerability_class': record.vulnerabilityClass.name,
    'proposer_context_id': record.proposerContextId,
    'validator_context_id': record.validatorContextId,
    'proposer_decision': record.proposerDecision.name,
    'validator_decision': record.validatorDecision.name,
    'outcome': record.outcome.name,
    'reproduction_attempts': jsonEncode(record.reproductionAttempts),
    'reproducibility_score': record.reproducibilityScore,
    'direct_evidence_artifact_ids': jsonEncode(
      record.directEvidenceArtifactIds,
    ),
    'completed_controls': jsonEncode(
      record.completedControls.map((value) => value.name).toList()..sort(),
    ),
    'missing_controls': jsonEncode(
      record.missingControls.map((value) => value.name).toList()..sort(),
    ),
    'reason': record.reason,
    'created_at': record.createdAt.toUtc().toIso8601String(),
  };

  IndependentValidationRecord _fromMap(Map<String, Object?> map) =>
      IndependentValidationRecord(
        id: map['id'] as int,
        validationRunId: map['validation_run_id'] as int,
        projectId: map['project_id'] as int,
        vulnerabilityId: map['vulnerability_id'] as int?,
        vulnerabilityClass: VulnerabilityClass.values.firstWhere(
          (value) => value.name == map['vulnerability_class'],
          orElse: () => VulnerabilityClass.other,
        ),
        proposerContextId: map['proposer_context_id'] as String,
        validatorContextId: map['validator_context_id'] as String,
        proposerDecision: IndependentValidationDecision.values.firstWhere(
          (value) => value.name == map['proposer_decision'],
        ),
        validatorDecision: IndependentValidationDecision.values.firstWhere(
          (value) => value.name == map['validator_decision'],
        ),
        outcome: IndependentValidationOutcome.values.firstWhere(
          (value) => value.name == map['outcome'],
        ),
        reproductionAttempts:
            (jsonDecode(map['reproduction_attempts'] as String) as List)
                .map((value) => value as bool)
                .toList(growable: false),
        reproducibilityScore: (map['reproducibility_score'] as num).toDouble(),
        directEvidenceArtifactIds:
            (jsonDecode(map['direct_evidence_artifact_ids'] as String) as List)
                .map((value) => value as int)
                .toList(growable: false),
        completedControls: _controls(map['completed_controls'] as String),
        missingControls: _controls(map['missing_controls'] as String),
        reason: map['reason'] as String,
        createdAt: DateTime.parse(map['created_at'] as String).toUtc(),
      );

  Set<ValidationControl> _controls(String encoded) =>
      (jsonDecode(encoded) as List)
          .map(
            (name) => ValidationControl.values.firstWhere(
              (value) => value.name == name,
            ),
          )
          .toSet();
}

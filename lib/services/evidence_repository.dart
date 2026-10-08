import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/evidence_artifact.dart';

class EvidenceRepository {
  final DatabaseExecutor database;

  const EvidenceRepository(this.database);

  static Future<void> createTable(DatabaseExecutor database) async {
    await database.execute('''
      CREATE TABLE IF NOT EXISTS evidence_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        vulnerability_id INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        relative_path TEXT NOT NULL,
        media_type TEXT NOT NULL,
        caption TEXT NOT NULL DEFAULT '',
        source TEXT NOT NULL,
        captured_at TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        width INTEGER,
        height INTEGER,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
        FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
      )
    ''');
    await database.execute(
      'CREATE INDEX IF NOT EXISTS idx_evidence_project '
      'ON evidence_artifacts(project_id, captured_at)',
    );
    await database.execute(
      'CREATE INDEX IF NOT EXISTS idx_evidence_vulnerability '
      'ON evidence_artifacts(vulnerability_id, captured_at)',
    );
  }

  Future<int> insert(EvidenceArtifact artifact) async {
    final finding = await database.query(
      'vulnerabilities',
      columns: const ['id'],
      where: 'id = ? AND projectId = ?',
      whereArgs: [artifact.vulnerabilityId, artifact.projectId],
      limit: 1,
    );
    if (finding.isEmpty) {
      throw StateError(
        'Evidence finding does not belong to the selected project',
      );
    }
    final values = Map<String, Object?>.from(artifact.toMap())..remove('id');
    return database.insert('evidence_artifacts', values);
  }

  Future<List<EvidenceArtifact>> forProject(int projectId) async {
    final rows = await database.query(
      'evidence_artifacts',
      where: 'project_id = ?',
      whereArgs: [projectId],
      orderBy: 'captured_at DESC, id DESC',
    );
    return rows.map(EvidenceArtifact.fromMap).toList();
  }

  Future<List<EvidenceArtifact>> forVulnerability(int vulnerabilityId) async {
    final rows = await database.query(
      'evidence_artifacts',
      where: 'vulnerability_id = ?',
      whereArgs: [vulnerabilityId],
      orderBy: 'captured_at DESC, id DESC',
    );
    return rows.map(EvidenceArtifact.fromMap).toList();
  }

  Future<List<EvidenceArtifact>> deleteForVulnerability(
    int vulnerabilityId,
  ) async {
    final artifacts = await forVulnerability(vulnerabilityId);
    await database.delete(
      'evidence_artifacts',
      where: 'vulnerability_id = ?',
      whereArgs: [vulnerabilityId],
    );
    return artifacts;
  }

  Future<void> reassignVulnerability({
    required int fromId,
    required int toId,
  }) async {
    final destination = await database.query(
      'vulnerabilities',
      columns: const ['projectId'],
      where: 'id = ?',
      whereArgs: [toId],
      limit: 1,
    );
    if (destination.isEmpty) {
      throw StateError('Destination finding does not exist');
    }
    await database.update(
      'evidence_artifacts',
      {'vulnerability_id': toId},
      where: 'vulnerability_id = ? AND project_id = ?',
      whereArgs: [fromId, destination.single['projectId']],
    );
  }

  Future<List<EvidenceArtifact>> deleteForVulnerabilities(
    List<int> vulnerabilityIds,
  ) async {
    if (vulnerabilityIds.isEmpty) return const [];
    final placeholders = List.filled(vulnerabilityIds.length, '?').join(',');
    final rows = await database.query(
      'evidence_artifacts',
      where: 'vulnerability_id IN ($placeholders)',
      whereArgs: vulnerabilityIds,
      orderBy: 'captured_at DESC, id DESC',
    );
    await database.delete(
      'evidence_artifacts',
      where: 'vulnerability_id IN ($placeholders)',
      whereArgs: vulnerabilityIds,
    );
    return rows.map(EvidenceArtifact.fromMap).toList();
  }

  Future<EvidenceArtifact?> delete(int id) async {
    final rows = await database.query(
      'evidence_artifacts',
      where: 'id = ?',
      whereArgs: [id],
      limit: 1,
    );
    if (rows.isEmpty) return null;
    final artifact = EvidenceArtifact.fromMap(rows.single);
    await database.delete(
      'evidence_artifacts',
      where: 'id = ?',
      whereArgs: [id],
    );
    return artifact;
  }
}

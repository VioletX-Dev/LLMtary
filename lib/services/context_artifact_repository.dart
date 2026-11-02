import 'dart:convert';

import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/context_artifact.dart';

class ContextArtifactRepository {
  final Database db;

  const ContextArtifactRepository(this.db);

  static Future<void> createTables(DatabaseExecutor db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS context_artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        type TEXT NOT NULL,
        original_file_name TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        extraction_method TEXT NOT NULL,
        parser_version TEXT NOT NULL,
        ingested_at TEXT NOT NULL,
        normalized_text TEXT NOT NULL DEFAULT '',
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS context_api_endpoints (
        artifact_id INTEGER NOT NULL,
        sequence_no INTEGER NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        operation_id TEXT NOT NULL DEFAULT '',
        parameter_names TEXT NOT NULL DEFAULT '[]',
        security_schemes TEXT NOT NULL DEFAULT '[]',
        FOREIGN KEY (artifact_id) REFERENCES context_artifacts(id) ON DELETE CASCADE,
        PRIMARY KEY (artifact_id, sequence_no)
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS context_archive_entries (
        artifact_id INTEGER NOT NULL,
        path TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        size_bytes INTEGER NOT NULL,
        FOREIGN KEY (artifact_id) REFERENCES context_artifacts(id) ON DELETE CASCADE,
        PRIMARY KEY (artifact_id, path)
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS context_dependencies (
        artifact_id INTEGER NOT NULL,
        sequence_no INTEGER NOT NULL,
        name TEXT NOT NULL,
        version_constraint TEXT NOT NULL DEFAULT '',
        ecosystem TEXT NOT NULL,
        development_only INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (artifact_id) REFERENCES context_artifacts(id) ON DELETE CASCADE,
        PRIMARY KEY (artifact_id, sequence_no)
      )
    ''');
    await db.execute('''
      CREATE TABLE IF NOT EXISTS context_prior_findings (
        artifact_id INTEGER NOT NULL,
        sequence_no INTEGER NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT '',
        evidence TEXT NOT NULL DEFAULT '',
        remediation TEXT NOT NULL DEFAULT '',
        FOREIGN KEY (artifact_id) REFERENCES context_artifacts(id) ON DELETE CASCADE,
        PRIMARY KEY (artifact_id, sequence_no)
      )
    ''');
    await db.execute(
      'CREATE INDEX IF NOT EXISTS idx_context_artifacts_project '
      'ON context_artifacts(project_id, ingested_at DESC)',
    );
  }

  Future<int> persist(ContextIngestionResult result) => db.transaction((
    txn,
  ) async {
    final artifact = result.artifact;
    final project = await txn.query(
      'projects',
      columns: const ['id'],
      where: 'id = ?',
      whereArgs: [artifact.projectId],
      limit: 1,
    );
    if (project.isEmpty) throw StateError('Context project does not exist.');
    final id = await txn.insert('context_artifacts', {
      'project_id': artifact.projectId,
      'type': artifact.type.name,
      'original_file_name': artifact.originalFileName,
      'sha256': artifact.sha256,
      'size_bytes': artifact.sizeBytes,
      'extraction_method': artifact.extractionMethod,
      'parser_version': result.provenance.parserVersion,
      'ingested_at': artifact.ingestedAt.toUtc().toIso8601String(),
      'normalized_text': result.normalizedText,
    });
    for (var index = 0; index < result.apiEndpoints.length; index++) {
      final endpoint = result.apiEndpoints[index];
      await txn.insert('context_api_endpoints', {
        'artifact_id': id,
        'sequence_no': index + 1,
        'method': endpoint.method,
        'path': endpoint.path,
        'operation_id': endpoint.operationId,
        'parameter_names': jsonEncode(endpoint.parameterNames),
        'security_schemes': jsonEncode(endpoint.securitySchemes),
      });
    }
    for (final entry in result.archiveEntries) {
      await txn.insert('context_archive_entries', {
        'artifact_id': id,
        'path': entry.path,
        'sha256': entry.sha256,
        'size_bytes': entry.sizeBytes,
      });
    }
    for (var index = 0; index < result.dependencies.length; index++) {
      final dependency = result.dependencies[index];
      await txn.insert('context_dependencies', {
        'artifact_id': id,
        'sequence_no': index + 1,
        'name': dependency.name,
        'version_constraint': dependency.versionConstraint,
        'ecosystem': dependency.ecosystem,
        'development_only': dependency.developmentOnly ? 1 : 0,
      });
    }
    for (var index = 0; index < result.priorFindings.length; index++) {
      final finding = result.priorFindings[index];
      await txn.insert('context_prior_findings', {
        'artifact_id': id,
        'sequence_no': index + 1,
        'title': finding.title,
        'severity': finding.severity,
        'status': finding.status,
        'evidence': finding.evidence,
        'remediation': finding.remediation,
      });
    }
    final stored = (await txn.query(
      'context_artifacts',
      columns: const [
        'sha256',
        'size_bytes',
        'parser_version',
        'normalized_text',
      ],
      where: 'id = ?',
      whereArgs: [id],
      limit: 1,
    )).single;
    if (stored['sha256'] != artifact.sha256 ||
        stored['size_bytes'] != artifact.sizeBytes ||
        stored['parser_version'] != result.provenance.parserVersion ||
        stored['normalized_text'] != result.normalizedText) {
      throw StateError(
        'Persisted context artifact failed integrity verification.',
      );
    }
    return id;
  });

  Future<ContextIngestionResult> get(int artifactId) async {
    final rows = await db.query(
      'context_artifacts',
      where: 'id = ?',
      whereArgs: [artifactId],
      limit: 1,
    );
    if (rows.isEmpty) throw StateError('Context artifact does not exist.');
    final row = rows.single;
    final endpointRows = await db.query(
      'context_api_endpoints',
      where: 'artifact_id = ?',
      whereArgs: [artifactId],
      orderBy: 'sequence_no ASC',
    );
    final archiveRows = await db.query(
      'context_archive_entries',
      where: 'artifact_id = ?',
      whereArgs: [artifactId],
      orderBy: 'path ASC',
    );
    final dependencyRows = await db.query(
      'context_dependencies',
      where: 'artifact_id = ?',
      whereArgs: [artifactId],
      orderBy: 'sequence_no ASC',
    );
    final findingRows = await db.query(
      'context_prior_findings',
      where: 'artifact_id = ?',
      whereArgs: [artifactId],
      orderBy: 'sequence_no ASC',
    );
    final ingestedAt = DateTime.parse(row['ingested_at'] as String).toUtc();
    final digest = row['sha256'] as String;
    final sourceName = row['original_file_name'] as String;
    return ContextIngestionResult(
      artifact: ContextArtifact(
        id: row['id'] as int,
        projectId: row['project_id'] as int,
        type: ContextArtifactType.values.firstWhere(
          (value) => value.name == row['type'],
          orElse: () => ContextArtifactType.unknown,
        ),
        originalFileName: sourceName,
        sha256: digest,
        sizeBytes: row['size_bytes'] as int,
        extractionMethod: row['extraction_method'] as String,
        ingestedAt: ingestedAt,
      ),
      provenance: ContextProvenance(
        sourceDigest: digest,
        parserVersion: row['parser_version'] as String,
        sourceName: sourceName,
        extractedAt: ingestedAt,
      ),
      apiEndpoints: endpointRows
          .map(
            (endpoint) => ApiEndpointContext(
              method: endpoint['method'] as String,
              path: endpoint['path'] as String,
              operationId: endpoint['operation_id'] as String,
              parameterNames:
                  (jsonDecode(endpoint['parameter_names'] as String) as List)
                      .map((value) => value.toString())
                      .toList(growable: false),
              securitySchemes:
                  (jsonDecode(endpoint['security_schemes'] as String) as List)
                      .map((value) => value.toString())
                      .toList(growable: false),
            ),
          )
          .toList(growable: false),
      archiveEntries: archiveRows
          .map(
            (entry) => ContextArchiveEntry(
              path: entry['path'] as String,
              sha256: entry['sha256'] as String,
              sizeBytes: entry['size_bytes'] as int,
            ),
          )
          .toList(growable: false),
      dependencies: dependencyRows
          .map(
            (dependency) => DependencyContext(
              name: dependency['name'] as String,
              versionConstraint: dependency['version_constraint'] as String,
              ecosystem: dependency['ecosystem'] as String,
              developmentOnly: dependency['development_only'] == 1,
            ),
          )
          .toList(growable: false),
      priorFindings: findingRows
          .map(
            (finding) => PriorFindingContext(
              title: finding['title'] as String,
              severity: finding['severity'] as String,
              status: finding['status'] as String,
              evidence: finding['evidence'] as String,
              remediation: finding['remediation'] as String,
            ),
          )
          .toList(growable: false),
      normalizedText: row['normalized_text'] as String,
    );
  }

  Future<List<ContextArtifact>> forProject(int projectId) async {
    final rows = await db.query(
      'context_artifacts',
      where: 'project_id = ?',
      whereArgs: [projectId],
      orderBy: 'ingested_at DESC, id DESC',
    );
    return rows
        .map(
          (row) => ContextArtifact(
            id: row['id'] as int,
            projectId: row['project_id'] as int,
            type: ContextArtifactType.values.firstWhere(
              (value) => value.name == row['type'],
              orElse: () => ContextArtifactType.unknown,
            ),
            originalFileName: row['original_file_name'] as String,
            sha256: row['sha256'] as String,
            sizeBytes: row['size_bytes'] as int,
            extractionMethod: row['extraction_method'] as String,
            ingestedAt: DateTime.parse(row['ingested_at'] as String).toUtc(),
          ),
        )
        .toList(growable: false);
  }
}

import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/context_artifact_repository.dart';
import 'package:llmtary/services/context_ingestion_service.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  sqfliteFfiInit();

  test(
    'fails closed when persisted context integrity does not match',
    () async {
      final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
      addTearDown(db.close);
      await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
      await db.insert('projects', {'id': 5});
      await ContextArtifactRepository.createTables(db);
      await db.execute('''
      CREATE TRIGGER corrupt_context AFTER INSERT ON context_artifacts
      BEGIN
        UPDATE context_artifacts SET sha256 = 'corrupted' WHERE id = NEW.id;
      END
    ''');
      final result = ContextIngestionService().ingestBytes(
        projectId: 5,
        fileName: 'architecture.md',
        bytes: utf8.encode('# Architecture'),
        ingestedAt: DateTime.utc(2026, 11, 1, 19, 10),
      );

      await expectLater(
        ContextArtifactRepository(db).persist(result),
        throwsStateError,
      );
    },
  );

  test('persists normalized prior findings', () async {
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
    await db.insert('projects', {'id': 5});
    await ContextArtifactRepository.createTables(db);
    final repository = ContextArtifactRepository(db);
    final result = ContextIngestionService().ingestBytes(
      projectId: 5,
      fileName: 'prior-report.json',
      bytes: utf8.encode(
        jsonEncode({
          'findings': [
            {'title': 'Legacy issue', 'severity': 'medium', 'status': 'open'},
          ],
        }),
      ),
      ingestedAt: DateTime.utc(2026, 11, 1, 18, 55),
    );

    final loaded = await repository.get(await repository.persist(result));

    expect(loaded.priorFindings.single.title, 'Legacy issue');
    expect(loaded.priorFindings.single.severity, 'MEDIUM');
  });

  test('persists normalized dependency context', () async {
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
    await db.insert('projects', {'id': 5});
    await ContextArtifactRepository.createTables(db);
    final repository = ContextArtifactRepository(db);
    final result = ContextIngestionService().ingestBytes(
      projectId: 5,
      fileName: 'package.json',
      bytes: utf8.encode(
        jsonEncode({
          'dependencies': {'express': '^5.0.0'},
        }),
      ),
      ingestedAt: DateTime.utc(2026, 11, 1, 18, 50),
    );

    final artifactId = await repository.persist(result);
    final loaded = await repository.get(artifactId);

    expect(loaded.dependencies.single.name, 'express');
    expect(loaded.dependencies.single.versionConstraint, '^5.0.0');
    expect(loaded.dependencies.single.ecosystem, 'npm');
  });

  test('persists context provenance and deterministic API endpoints', () async {
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
    await db.insert('projects', {'id': 5});
    await ContextArtifactRepository.createTables(db);
    final repository = ContextArtifactRepository(db);
    final result = ContextIngestionService().ingestBytes(
      projectId: 5,
      fileName: 'service.openapi.json',
      bytes: utf8.encode(
        jsonEncode({
          'openapi': '3.0.3',
          'paths': {
            '/health': {
              'get': {'operationId': 'health'},
            },
          },
        }),
      ),
      ingestedAt: DateTime.utc(2026, 11, 1, 18),
    );

    final artifactId = await repository.persist(result);
    final loaded = await repository.get(artifactId);

    expect(loaded.artifact.id, artifactId);
    expect(loaded.provenance.sourceDigest, result.provenance.sourceDigest);
    expect(loaded.apiEndpoints, hasLength(1));
    expect(loaded.apiEndpoints.single.operationId, 'health');
    expect((await repository.forProject(5)).single.id, artifactId);
  });
}

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/browser_evidence_screenshot_sink.dart';
import 'package:llmtary/services/evidence_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  test('stores browser screenshot as finding-linked evidence under bounded root', () async {
    sqfliteFfiInit();
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    await db.execute('CREATE TABLE projects (id INTEGER PRIMARY KEY)');
    await db.execute(
      'CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, projectId INTEGER NOT NULL)',
    );
    await db.insert('projects', {'id': 3});
    await db.insert('vulnerabilities', {'id': 9, 'projectId': 3});
    await EvidenceRepository.createTable(db);

    final root = await Directory.systemTemp.createTemp('llmtary-browser-evidence-');
    addTearDown(() => root.delete(recursive: true));
    final sink = BrowserEvidenceScreenshotSink(
      evidenceRoot: root,
      projectId: 3,
      vulnerabilityId: 9,
      repository: EvidenceRepository(db),
      now: () => DateTime.utc(2026, 11, 4, 12),
    );

    final id = await sink.capture(const [0x89, 0x50, 0x4e, 0x47]);

    expect(id, greaterThan(0));
    final artifacts = await EvidenceRepository(db).forVulnerability(9);
    expect(artifacts, hasLength(1));
    expect(artifacts.single.mediaType, 'image/png');
    final file = File('${root.path}/${artifacts.single.relativePath}');
    expect(await file.exists(), isTrue);
    expect(await file.readAsBytes(), const [0x89, 0x50, 0x4e, 0x47]);
    expect(file.path.startsWith(root.path), isTrue);
  });

  test('rejects empty or oversized screenshots', () async {
    sqfliteFfiInit();
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    final root = await Directory.systemTemp.createTemp('llmtary-browser-evidence-');
    addTearDown(() => root.delete(recursive: true));
    final sink = BrowserEvidenceScreenshotSink(
      evidenceRoot: root,
      projectId: 1,
      vulnerabilityId: 1,
      repository: EvidenceRepository(db),
      maxBytes: 3,
    );

    expect(() => sink.capture(const []), throwsArgumentError);
    expect(() => sink.capture(const [1, 2, 3, 4]), throwsArgumentError);
  });
}

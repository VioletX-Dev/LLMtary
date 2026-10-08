import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';
import 'package:llmtary/services/evidence_repository.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

void main() {
  sqfliteFfiInit();

  test('evidence repository persists and isolates finding evidence', () async {
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
    await db.insert('vulnerabilities', {'id': 13, 'projectId': 3});
    await db.insert('vulnerabilities', {'id': 14, 'projectId': 4});
    await EvidenceRepository.createTable(db);
    final repository = EvidenceRepository(db);

    EvidenceArtifact artifact(int finding, String name, DateTime capturedAt) =>
        EvidenceArtifact(
          projectId: 3,
          vulnerabilityId: finding,
          fileName: name,
          relativePath: 'evidence/finding-$finding/$name',
          mediaType: 'image/png',
          caption: name,
          source: EvidenceSource.imported,
          capturedAt: capturedAt,
          sha256: 'a' * 64,
          sizeBytes: 10,
        );

    final olderId = await repository.insert(
      artifact(12, 'older.png', DateTime.utc(2026, 1, 1)),
    );
    await repository.insert(
      artifact(12, 'newer.png', DateTime.utc(2026, 1, 2)),
    );
    await repository.insert(
      artifact(13, 'other.png', DateTime.utc(2026, 1, 3)),
    );

    final findingEvidence = await repository.forVulnerability(12);
    expect(findingEvidence.map((item) => item.fileName), [
      'newer.png',
      'older.png',
    ]);
    expect(await repository.forProject(3), hasLength(3));

    final deleted = await repository.delete(olderId);
    expect(deleted?.relativePath, endsWith('older.png'));
    expect(await repository.forVulnerability(12), hasLength(1));

    final findingFiles = await repository.deleteForVulnerability(12);
    expect(findingFiles.single.fileName, 'newer.png');
    expect(await repository.forVulnerability(12), isEmpty);
    expect(await repository.forProject(3), hasLength(1));

    await expectLater(
      repository.insert(
        artifact(14, 'wrong-project.png', DateTime.utc(2026, 1, 4)),
      ),
      throwsStateError,
    );

    await repository.reassignVulnerability(fromId: 13, toId: 12);
    expect(await repository.forVulnerability(12), hasLength(1));
    expect(await repository.forVulnerability(13), isEmpty);

    final removed = await repository.deleteForVulnerabilities([12, 13]);
    expect(removed.map((item) => item.fileName), ['other.png']);
    expect(await repository.forProject(3), isEmpty);
  });
}

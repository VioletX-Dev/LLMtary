import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/evidence_portability_service.dart';
import 'package:llmtary/services/evidence_storage_service.dart';

void main() {
  test('exports and restores evidence with remapped finding IDs', () async {
    final root = await Directory.systemTemp.createTemp('llmtary-portability-');
    addTearDown(() async {
      if (await root.exists()) await root.delete(recursive: true);
    });
    final sourceProject = Project(
      id: 3,
      name: 'Source',
      folderPath: '${root.path}/source',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );
    final destinationProject = Project(
      id: 4,
      name: 'Destination',
      folderPath: '${root.path}/destination',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );
    final source = File('${root.path}/source.png');
    await source.writeAsBytes(
      base64Decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC'
        'AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
      ),
    );
    final artifact = await EvidenceStorageService.importImage(
      project: sourceProject,
      vulnerabilityId: 12,
      sourcePath: source.path,
      caption: 'Authenticated dashboard',
      source: EvidenceSource.captured,
      capturedAt: DateTime.utc(2026, 10, 7),
    );

    final bundle = await EvidencePortabilityService.export(
      project: sourceProject,
      artifacts: [artifact],
    );
    final restored = await EvidencePortabilityService.restore(
      project: destinationProject,
      entries: [...bundle.entries, ...bundle.entries],
      vulnerabilityIdMap: const {12: 22},
      loadBytes: (path) async => bundle.files[path]!,
    );

    expect(restored, hasLength(2));
    expect(restored.first.projectId, 4);
    expect(restored.first.vulnerabilityId, 22);
    expect(restored.first.caption, artifact.caption);
    expect(restored.first.sha256, artifact.sha256);
    expect(restored[0].relativePath, isNot(restored[1].relativePath));
    expect(
      await File(
        '${destinationProject.folderPath}/${restored.first.relativePath}',
      ).exists(),
      isTrue,
    );
    expect(
      await File(
        '${destinationProject.folderPath}/${restored.last.relativePath}',
      ).exists(),
      isTrue,
    );
  });

  test(
    'fails closed when private temporary permissions cannot be set',
    () async {
      await expectLater(
        EvidencePortabilityService.ensureOwnerOnly(
          '/tmp/evidence',
          directory: true,
          runProcess: (_, __) async => ProcessResult(1, 1, '', 'denied'),
        ),
        throwsA(isA<FileSystemException>()),
      );
    },
  );
}

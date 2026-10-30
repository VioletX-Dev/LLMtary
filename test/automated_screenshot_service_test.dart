import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/automated_screenshot_service.dart';

void main() {
  test(
    'automatically stores command screenshot without raw command secrets',
    () async {
      final temp = await Directory.systemTemp.createTemp('auto-shot-test-');
      addTearDown(() async {
        if (await temp.exists()) await temp.delete(recursive: true);
      });
      final source = File('${temp.path}/source.png');
      await source.writeAsBytes(
        base64Decode(
          'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC'
          'AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
        ),
      );
      final project = Project(
        id: 7,
        name: 'Automated Evidence',
        folderPath: '${temp.path}/project',
        createdAt: DateTime.utc(2026),
        lastOpenedAt: DateTime.utc(2026),
      );

      final relative = await AutomatedScreenshotService.captureOperational(
        project: project,
        phase: 'SCOPE / RECON',
        targetLabel: '172.16.2.5',
        command: 'scanner --password super-secret',
        captureDesktop: () async => source.path,
        capturedAt: DateTime.utc(2026, 10, 30, 12),
      );

      expect(relative, startsWith('evidence/automated/scope-recon/'));
      expect(await File('${project.folderPath}/$relative').exists(), isTrue);
      final metadata = await File(
        '${project.folderPath}/${relative.replaceAll('.png', '.json')}',
      ).readAsString();
      expect(metadata, contains('command_sha256'));
      expect(metadata, isNot(contains('super-secret')));
    },
  );

  test('automatically links proof screenshot to its finding', () async {
    final temp = await Directory.systemTemp.createTemp(
      'auto-finding-shot-test-',
    );
    addTearDown(() async {
      if (await temp.exists()) await temp.delete(recursive: true);
    });
    final source = File('${temp.path}/source.png');
    await source.writeAsBytes(
      base64Decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC'
        'AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
      ),
    );
    final project = Project(
      id: 9,
      name: 'Finding Evidence',
      folderPath: '${temp.path}/project',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );
    EvidenceArtifact? inserted;

    final artifact = await AutomatedScreenshotService.captureFinding(
      project: project,
      vulnerabilityId: 42,
      phase: 'PROOF / EXPLOIT',
      targetLabel: '172.16.2.5',
      command: 'safe proof command',
      captureDesktop: () async => source.path,
      insertArtifact: (value) async => inserted = value,
    );

    expect(artifact.vulnerabilityId, 42);
    expect(artifact.source, EvidenceSource.captured);
    expect(inserted?.sha256, artifact.sha256);
    expect(artifact.caption, contains('Automatically captured'));
  });

  test('rejects automated evidence symlink escape', () async {
    if (!Platform.isLinux) return;
    final temp = await Directory.systemTemp.createTemp('auto-shot-link-test-');
    addTearDown(() async {
      if (await temp.exists()) await temp.delete(recursive: true);
    });
    final projectRoot = Directory('${temp.path}/project');
    final outside = Directory('${temp.path}/outside');
    await projectRoot.create();
    await outside.create();
    await Link('${projectRoot.path}/evidence').create(outside.path);
    final source = File('${temp.path}/source.png');
    await source.writeAsBytes(
      base64Decode(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC'
        'AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
      ),
    );
    final project = Project(
      id: 11,
      name: 'Escape Test',
      folderPath: projectRoot.path,
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
    );

    await expectLater(
      AutomatedScreenshotService.captureOperational(
        project: project,
        phase: 'SCOPE / RECON',
        targetLabel: 'target',
        command: 'command',
        captureDesktop: () async => source.path,
      ),
      throwsStateError,
    );
  });
}

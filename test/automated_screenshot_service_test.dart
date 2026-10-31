import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/automated_screenshot_service.dart';
import 'package:llmtary/services/evidence_storage_service.dart';

void main() {
  test(
    'automatically renders command and output instead of the LLMtary desktop',
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

      String? renderedOutput;
      final relative = await AutomatedScreenshotService.captureOperational(
        project: project,
        phase: 'SCOPE / RECON',
        targetLabel: '172.16.2.5',
        command: 'scanner --password super-secret',
        output: '443/tcp open https',
        renderCommandOutput:
            ({
              required phase,
              required targetLabel,
              required command,
              required output,
            }) async {
              renderedOutput = output;
              return source.path;
            },
        capturedAt: DateTime.utc(2026, 10, 30, 12),
      );

      expect(relative, startsWith('evidence/automated/scope-recon/'));
      expect(await File('${project.folderPath}/$relative').exists(), isTrue);
      final metadata = await File(
        '${project.folderPath}/${relative.replaceAll('.png', '.json')}',
      ).readAsString();
      expect(metadata, contains('command_sha256'));
      expect(metadata, contains('output_sha256'));
      expect(metadata, contains('terminal_output'));
      expect(metadata, isNot(contains('super-secret')));
      expect(metadata, isNot(contains('443/tcp open https')));
      expect(renderedOutput, '443/tcp open https');
    },
  );

  test(
    'renders a validated terminal-output PNG without desktop capture',
    () async {
      final path = await EvidenceStorageService.renderCommandOutput(
        phase: 'SCOPE / RECON',
        targetLabel: '172.16.2.5',
        command: 'nmap -sV 172.16.2.5',
        output: '443/tcp open https',
      );
      addTearDown(() => EvidenceStorageService.deleteTemporaryCapture(path));

      final image = await EvidenceStorageService.validateImageFile(path);
      expect(image.extension, 'png');
      expect(image.width, 1600);
      expect(image.height, 1200);

      final secretPath = await EvidenceStorageService.renderCommandOutput(
        phase: 'PROOF / EXPLOIT',
        targetLabel: '172.16.2.5',
        command: 'scanner --password super-secret',
        output: 'token=output-secret',
      );
      final redactedPath = await EvidenceStorageService.renderCommandOutput(
        phase: 'PROOF / EXPLOIT',
        targetLabel: '172.16.2.5',
        command: 'scanner --password [REDACTED]',
        output: 'token=[REDACTED]',
      );
      addTearDown(
        () => EvidenceStorageService.deleteTemporaryCapture(secretPath),
      );
      addTearDown(
        () => EvidenceStorageService.deleteTemporaryCapture(redactedPath),
      );
      expect(
        await File(secretPath).readAsBytes(),
        await File(redactedPath).readAsBytes(),
      );
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
      output: 'validated access to the authorized target',
      renderCommandOutput:
          ({
            required phase,
            required targetLabel,
            required command,
            required output,
          }) async => source.path,
      insertArtifact: (value) async => inserted = value,
    );

    expect(artifact.vulnerabilityId, 42);
    expect(artifact.source, EvidenceSource.captured);
    expect(inserted?.sha256, artifact.sha256);
    expect(artifact.caption, contains('Automatically rendered'));
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
        output: 'output',
        renderCommandOutput:
            ({
              required phase,
              required targetLabel,
              required command,
              required output,
            }) async => source.path,
      ),
      throwsStateError,
    );
  });
}

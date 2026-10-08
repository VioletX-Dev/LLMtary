import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/evidence_package_builder.dart';
import 'package:llmtary/services/evidence_storage_service.dart';

void main() {
  group('EvidenceStorageService', () {
    late Directory temp;
    late Project project;

    setUp(() async {
      temp = await Directory.systemTemp.createTemp('llmtary-evidence-test-');
      project = Project(
        id: 3,
        name: 'Magic Link Test',
        folderPath: '${temp.path}/project',
        createdAt: DateTime.utc(2026),
        lastOpenedAt: DateTime.utc(2026),
      );
    });

    List<int> validPng() => base64Decode(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC'
      'AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=',
    );

    tearDown(() async {
      if (await temp.exists()) await temp.delete(recursive: true);
    });

    test(
      'imports a validated image into project-local evidence storage',
      () async {
        final source = File('${temp.path}/browser-shot.png');
        await source.writeAsBytes(validPng());

        final preview = await EvidenceStorageService.validateImageFile(
          source.path,
        );
        expect(preview.width, 1);
        expect(preview.height, 1);

        final artifact = await EvidenceStorageService.importImage(
          project: project,
          vulnerabilityId: 12,
          sourcePath: source.path,
          caption: 'Admin dashboard after bypass',
          source: EvidenceSource.imported,
          capturedAt: DateTime.utc(2026, 10, 7, 20, 30),
        );

        expect(artifact.projectId, 3);
        expect(artifact.vulnerabilityId, 12);
        expect(artifact.fileName, 'browser-shot.png');
        expect(artifact.relativePath, startsWith('evidence/finding-12/'));
        expect(artifact.relativePath, endsWith('.png'));
        expect(artifact.mediaType, 'image/png');
        expect(artifact.width, 1);
        expect(artifact.height, 1);
        expect(artifact.sha256, hasLength(64));
        expect(artifact.sizeBytes, await source.length());
        expect(artifact.toMap().toString(), isNot(contains(temp.path)));
        expect(
          await File(
            '${project.folderPath}/${artifact.relativePath}',
          ).readAsBytes(),
          await source.readAsBytes(),
        );
        if (Platform.isLinux) {
          final stored = File('${project.folderPath}/${artifact.relativePath}');
          expect((await stored.stat()).mode & 0x1ff, 0x180); // 0600
          expect((await stored.parent.stat()).mode & 0x1ff, 0x1c0); // 0700
        }

        final reportEvidence = await EvidenceStorageService.loadReportEvidence(
          project: project,
          artifacts: [artifact],
        );
        expect(
          reportEvidence.single.dataUri,
          startsWith('data:image/png;base64,'),
        );
        expect(reportEvidence.single.artifact.sha256, artifact.sha256);

        final staged = await EvidenceStorageService.stageEvidenceDeletion(
          project: project,
          artifact: artifact,
        );
        expect(
          await File('${project.folderPath}/${artifact.relativePath}').exists(),
          isFalse,
        );
        await EvidenceStorageService.restoreStagedDeletion(staged);
        expect(
          await File('${project.folderPath}/${artifact.relativePath}').exists(),
          isTrue,
        );
        final stagedAgain = await EvidenceStorageService.stageEvidenceDeletion(
          project: project,
          artifact: artifact,
        );
        await EvidenceStorageService.finalizeStagedDeletion(stagedAgain);
        expect(await File(stagedAgain.stagedPath).exists(), isFalse);
        await EvidenceStorageService.restoreStagedDeletion(stagedAgain);
        expect(
          await File('${project.folderPath}/${artifact.relativePath}').exists(),
          isTrue,
        );
      },
    );

    test(
      'captures the Linux desktop with a fixed delayed command',
      () async {
        String? executable;
        List<String>? arguments;

        final path = await EvidenceStorageService.captureDesktop(
          delaySeconds: 3,
          runProcess: (command, args) async {
            executable = command;
            arguments = args;
            await File(args.last).writeAsBytes(<int>[
              0x89,
              0x50,
              0x4e,
              0x47,
              0x0d,
              0x0a,
              0x1a,
              0x0a,
            ]);
            return ProcessResult(1, 0, '', '');
          },
        );
        addTearDown(() async {
          final file = File(path);
          if (await file.exists()) await file.delete();
        });

        expect(executable, 'scrot');
        expect(arguments, ['-d', '3', path]);
        expect(await File(path).exists(), isTrue);
        expect(File(path).parent.path, contains('llmtary-evidence-'));
        expect((await File(path).stat()).mode & 0x1ff, 0x180); // 0600
        final captureDirectory = File(path).parent;
        await EvidenceStorageService.deleteTemporaryCapture(path);
        expect(await captureDirectory.exists(), isFalse);
      },
      skip: !Platform.isLinux,
    );

    test(
      'removes the private capture directory when capture fails',
      () async {
        String? attemptedPath;
        await expectLater(
          EvidenceStorageService.captureDesktop(
            runProcess: (_, args) async {
              attemptedPath = args.last;
              await File(args.last).writeAsBytes(validPng());
              return ProcessResult(1, 1, '', 'capture failed');
            },
          ),
          throwsA(isA<FileSystemException>()),
        );
        expect(attemptedPath, isNotNull);
        expect(await File(attemptedPath!).parent.exists(), isFalse);
      },
      skip: !Platform.isLinux,
    );

    test('removes stale private capture directories', () async {
      final stale = await Directory.systemTemp.createTemp('llmtary-evidence-');
      await File('${stale.path}/screenshot.png').writeAsBytes(validPng());

      await EvidenceStorageService.cleanupStaleCaptures(maxAge: Duration.zero);

      expect(await stale.exists(), isFalse);
    }, skip: !Platform.isLinux);

    test(
      'rejects a symlinked evidence directory that escapes the project root',
      () async {
        final source = File('${temp.path}/browser-shot.png');
        await source.writeAsBytes(validPng());
        final projectDirectory = Directory(project.folderPath);
        final outside = Directory('${temp.path}/outside');
        await projectDirectory.create(recursive: true);
        await outside.create(recursive: true);
        await Link('${project.folderPath}/evidence').create(outside.path);

        expect(
          () => EvidenceStorageService.importImage(
            project: project,
            vulnerabilityId: 12,
            sourcePath: source.path,
            caption: 'Should not escape',
            source: EvidenceSource.imported,
          ),
          throwsA(isA<StateError>()),
        );
        expect(await outside.list().toList(), isEmpty);
      },
      skip: !Platform.isLinux,
    );

    test('rejects a non-image renamed with an image extension', () async {
      final source = File('${temp.path}/fake.png');
      await source.writeAsString('not an image');

      expect(
        () => EvidenceStorageService.importImage(
          project: project,
          vulnerabilityId: 12,
          sourcePath: source.path,
          caption: 'Fake',
          source: EvidenceSource.imported,
        ),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects a malformed image with a valid PNG signature', () async {
      final source = File('${temp.path}/malformed.png');
      await source.writeAsBytes(<int>[
        0x89,
        0x50,
        0x4e,
        0x47,
        0x0d,
        0x0a,
        0x1a,
        0x0a,
        ...List<int>.filled(24, 0),
      ]);

      expect(
        () => EvidenceStorageService.importImage(
          project: project,
          vulnerabilityId: 12,
          sourcePath: source.path,
          caption: 'Malformed',
          source: EvidenceSource.imported,
        ),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => EvidenceStorageService.validateImageFile(source.path),
        throwsA(isA<FormatException>()),
      );
    });

    test(
      'removes copied evidence when private permission setup fails',
      () async {
        final source = File('${temp.path}/permission-failure.png');
        await source.writeAsBytes(validPng());

        await expectLater(
          EvidenceStorageService.importImage(
            project: project,
            vulnerabilityId: 12,
            sourcePath: source.path,
            caption: 'must roll back',
            source: EvidenceSource.imported,
            setOwnerOnly: (path, {required directory}) async {
              if (!directory) throw StateError('chmod failed');
            },
          ),
          throwsStateError,
        );
        final evidenceDirectory = Directory('${project.folderPath}/evidence');
        final files = await evidenceDirectory.exists()
            ? await evidenceDirectory
                  .list(recursive: true)
                  .where((entry) => entry is File)
                  .toList()
            : <FileSystemEntity>[];
        expect(files, isEmpty);
      },
    );

    test('rejects oversized report evidence before reading files', () async {
      final oversized = EvidenceArtifact(
        projectId: 3,
        vulnerabilityId: 12,
        fileName: 'oversized.png',
        relativePath: 'evidence/finding-12/oversized.png',
        mediaType: 'image/png',
        caption: 'oversized',
        source: EvidenceSource.imported,
        capturedAt: DateTime.utc(2026),
        sha256: 'd' * 64,
        sizeBytes: EvidencePackageBuilder.maxAggregateEvidenceBytes + 1,
      );

      await expectLater(
        EvidenceStorageService.loadReportEvidence(
          project: project,
          artifacts: [oversized],
        ),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('50 MiB'),
          ),
        ),
      );
    });
  });
}

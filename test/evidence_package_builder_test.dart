import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';
import 'package:llmtary/services/evidence_package_builder.dart';

void main() {
  group('EvidencePackageBuilder', () {
    final artifact = EvidenceArtifact(
      id: 9,
      projectId: 3,
      vulnerabilityId: 12,
      fileName: 'auth bypass.png',
      relativePath: 'evidence/finding-12/ev-9.png',
      mediaType: 'image/png',
      caption: 'Authenticated administrative page',
      source: EvidenceSource.captured,
      capturedAt: DateTime.utc(2026, 10, 7, 20, 30),
      sha256:
          '2d4566582844690f8634a8b2534ea5221560038c6c0650c99140759bad603ae2',
      sizeBytes: 7,
      width: 1440,
      height: 900,
    );

    test(
      'includes evidence, manifest, and report without absolute paths',
      () async {
        final bytes = await EvidencePackageBuilder.build(
          projectName: 'Magic Link Test',
          artifacts: [artifact],
          findingMetadata: {
            12: {
              'title': 'Authorization bypass',
              'severity': 'HIGH',
              'target': 'https://example.test',
            },
          },
          loadBytes: (_) async => Uint8List.fromList(utf8.encode('PNGDATA')),
          reportHtml: '<html><body>Report</body></html>',
        );

        final archive = ZipDecoder().decodeBytes(bytes);
        final names = archive.files.map((file) => file.name).toList();
        expect(names, contains('manifest.json'));
        expect(names, contains('report/report.html'));
        expect(names, contains('evidence/finding-12/auth_bypass.png'));
        expect(
          names.every((name) => !name.startsWith('/') && !name.contains('..')),
          isTrue,
        );

        final manifest =
            jsonDecode(
                  utf8.decode(
                    archive.findFile('manifest.json')!.content as List<int>,
                  ),
                )
                as Map<String, dynamic>;
        expect(manifest['project_name'], 'Magic Link Test');
        expect(manifest['evidence_count'], 1);
        final entry =
            (manifest['evidence'] as List).single as Map<String, dynamic>;
        expect(entry['vulnerability_id'], 12);
        expect(entry['caption'], contains('administrative'));
        expect(entry['sha256'], artifact.sha256);
        expect(entry['finding_title'], 'Authorization bypass');
        expect(entry['severity'], 'HIGH');
        expect(entry['target'], 'https://example.test');
        expect(entry['path'], 'evidence/finding-12/auth_bypass.png');
        expect(jsonEncode(manifest), isNot(contains(artifact.relativePath)));
      },
    );

    test(
      'rejects evidence whose bytes do not match recorded integrity hash',
      () async {
        expect(
          () => EvidencePackageBuilder.build(
            projectName: 'Magic Link Test',
            artifacts: [artifact],
            loadBytes: (_) async => Uint8List.fromList(utf8.encode('TAMPERED')),
          ),
          throwsA(isA<StateError>()),
        );
      },
    );

    test(
      'assigns unique paths across repeated archive-name collisions',
      () async {
        final bytes = await EvidencePackageBuilder.build(
          projectName: 'Collision Test',
          artifacts: [artifact, artifact, artifact],
          loadBytes: (_) async => Uint8List.fromList(utf8.encode('PNGDATA')),
        );
        final archive = ZipDecoder().decodeBytes(bytes);
        final evidenceNames = archive.files
            .map((file) => file.name)
            .where((name) => name.startsWith('evidence/'))
            .toList();

        expect(evidenceNames, hasLength(3));
        expect(evidenceNames.toSet(), hasLength(3));
      },
    );

    test(
      'rejects packages above the aggregate evidence limit before loading',
      () async {
        var loads = 0;
        final oversized = EvidenceArtifact(
          id: 20,
          projectId: 3,
          vulnerabilityId: 12,
          fileName: 'large.png',
          relativePath: 'evidence/finding-12/large.png',
          mediaType: 'image/png',
          caption: 'large',
          source: EvidenceSource.imported,
          capturedAt: DateTime.utc(2026),
          sha256: 'c' * 64,
          sizeBytes: EvidencePackageBuilder.maxAggregateEvidenceBytes + 1,
        );

        await expectLater(
          EvidencePackageBuilder.build(
            projectName: 'Oversized',
            artifacts: [oversized],
            loadBytes: (_) async {
              loads++;
              return Uint8List(0);
            },
          ),
          throwsStateError,
        );
        expect(loads, 0);
      },
    );

    test('writes a package atomically without leaving partial files', () async {
      final directory = await Directory.systemTemp.createTemp(
        'llmtary-package-write-',
      );
      addTearDown(() async {
        if (await directory.exists()) await directory.delete(recursive: true);
      });
      final destination = File('${directory.path}/evidence.zip');
      await destination.writeAsString('old');

      await EvidencePackageBuilder.writeAtomically(
        destination.path,
        Uint8List.fromList([1, 2, 3]),
      );

      expect(await destination.readAsBytes(), [1, 2, 3]);
      expect(
        await directory
            .list()
            .where((entry) => entry.path.contains('.partial-'))
            .toList(),
        isEmpty,
      );
    });
  });
}

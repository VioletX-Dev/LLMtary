import 'dart:typed_data';
import 'dart:convert';

import 'package:archive/archive.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/project_porter.dart';

void main() {
  test('project archive envelope accepts a small ordinary ZIP', () {
    final archive = Archive()
      ..addFile(
        ArchiveFile('manifest.json', 2, Uint8List.fromList([123, 125])),
      );
    final bytes = Uint8List.fromList(ZipEncoder().encode(archive));

    expect(() => ProjectPorter.validateZipEnvelope(bytes), returnsNormally);
  });

  test('project archive envelope rejects extreme expansion ratios', () {
    final content = Uint8List(2 * 1024 * 1024);
    final archive = Archive()
      ..addFile(ArchiveFile('bomb.bin', content.length, content));
    final bytes = Uint8List.fromList(ZipEncoder().encode(archive));

    expect(
      () => ProjectPorter.validateZipEnvelope(bytes),
      throwsA(isA<FormatException>()),
    );
  });

  test('project manifest rejects excessive collection counts', () async {
    final manifest = <String, Object?>{
      'project': <String, Object?>{'name': 'Bounded'},
      'targets': List<Object?>.filled(1001, <String, Object?>{}),
    };
    await expectLater(
      ProjectPorter.parseManifestForTesting(
        Uint8List.fromList(utf8.encode(jsonEncode(manifest))),
      ),
      throwsA(isA<FormatException>()),
    );
  });

  test('project manifest accepts bounded ordinary content', () async {
    final manifest = <String, Object?>{
      'project': <String, Object?>{'name': 'Bounded'},
      'targets': <Object?>[],
      'vulnerabilities': <Object?>[],
    };
    final parsed = await ProjectPorter.parseManifestForTesting(
      Uint8List.fromList(utf8.encode(jsonEncode(manifest))),
    );
    expect((parsed['project'] as Map)['name'], 'Bounded');
  });
}

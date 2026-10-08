import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/storage_service.dart';
import 'dart:io';

void main() {
  test('project directory names reject traversal and path separators', () {
    expect(
      StorageService.validateProjectName('Client Portal'),
      'Client Portal',
    );
    for (final unsafe in <String>[
      '../outside',
      '/absolute',
      r'..\outside',
      'nested/project',
      '..',
      'control\u0000name',
    ]) {
      expect(
        () => StorageService.validateProjectName(unsafe),
        throwsA(isA<FormatException>()),
        reason: unsafe,
      );
    }
  });

  test('target directories and portable filenames reject traversal', () {
    expect(
      StorageService.safeTargetDirectoryName('192.168.1.1'),
      '192.168.1.1',
    );
    expect(StorageService.safeTargetDirectoryName('.'), isNot('.'));
    expect(StorageService.safeTargetDirectoryName('..'), isNot('..'));
    expect(
      StorageService.safeTargetDirectoryName('a/b'),
      isNot(StorageService.safeTargetDirectoryName('a?b')),
    );
    expect(
      () => StorageService.validatePortableFileName(r'..\escape.txt'),
      throwsA(isA<FormatException>()),
    );
    final encoded = StorageService.portableArchiveFileName(r'a\b.txt');
    expect(encoded, isNot(r'a\b.txt'));
    expect(StorageService.validatePortableFileName(encoded), encoded);
  });

  test('new project paths never reuse an existing directory', () async {
    final root = await Directory.systemTemp.createTemp('llmtary-storage-');
    addTearDown(() async {
      StorageService.setCustomBasePath(null);
      if (await root.exists()) await root.delete(recursive: true);
    });
    StorageService.setCustomBasePath(root.path);
    await Directory('${root.path}/Existing').create();

    await expectLater(
      StorageService.createNewProjectPath('Existing'),
      throwsA(isA<FileSystemException>()),
    );
  });
}

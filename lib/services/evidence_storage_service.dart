import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:image/image.dart' as img;

import 'package:path/path.dart' as p;

import '../models/evidence_artifact.dart';
import '../models/project.dart';
import '../models/report_evidence.dart';
import 'evidence_package_builder.dart';

typedef OwnerOnlySetter =
    Future<void> Function(String path, {required bool directory});

class ValidatedEvidenceImage {
  final Uint8List bytes;
  final String extension;
  final String mediaType;
  final int width;
  final int height;

  const ValidatedEvidenceImage({
    required this.bytes,
    required this.extension,
    required this.mediaType,
    required this.width,
    required this.height,
  });
}

class StagedEvidenceDeletion {
  final String originalPath;
  final String stagedPath;
  final Uint8List? backupBytes;

  const StagedEvidenceDeletion({
    required this.originalPath,
    required this.stagedPath,
    this.backupBytes,
  });
}

class EvidenceStorageService {
  static const int maxImageBytes = 25 * 1024 * 1024;
  static const int maxImageDimension = 16384;
  static const int maxImagePixels = 40000000;
  static const int maxCaptionCharacters = 2000;

  static Future<EvidenceArtifact> importImage({
    required Project project,
    required int vulnerabilityId,
    required String sourcePath,
    required String caption,
    required EvidenceSource source,
    DateTime? capturedAt,
    OwnerOnlySetter? setOwnerOnly,
  }) async {
    if (project.id == null) {
      throw StateError('Evidence requires a saved project');
    }
    if (vulnerabilityId <= 0) {
      throw ArgumentError.value(
        vulnerabilityId,
        'vulnerabilityId',
        'Evidence requires a saved finding',
      );
    }
    final normalizedCaption = caption.trim();
    if (normalizedCaption.length > maxCaptionCharacters) {
      throw ArgumentError.value(
        caption,
        'caption',
        'Caption exceeds $maxCaptionCharacters characters',
      );
    }

    final validated = await validateImageFile(sourcePath);
    final bytes = validated.bytes;
    final permissionSetter = setOwnerOnly ?? _setOwnerOnly;

    final digest = await Isolate.run(
      () => EvidencePackageBuilder.sha256Hex(bytes),
    );
    final time = (capturedAt ?? DateTime.now()).toUtc();
    final projectRoot = p.normalize(p.absolute(project.folderPath));
    final relativeDirectory = p.join('evidence', 'finding-$vulnerabilityId');
    final destinationDirectory = p.normalize(
      p.join(projectRoot, relativeDirectory),
    );
    if (!p.isWithin(projectRoot, destinationDirectory)) {
      throw StateError('Evidence destination escaped the project folder');
    }
    await Directory(destinationDirectory).create(recursive: true);
    final canonicalRoot = p.normalize(
      await Directory(projectRoot).resolveSymbolicLinks(),
    );
    final canonicalDestinationDirectory = p.normalize(
      await Directory(destinationDirectory).resolveSymbolicLinks(),
    );
    if (!p.isWithin(canonicalRoot, canonicalDestinationDirectory)) {
      throw StateError('Evidence destination escaped the project folder');
    }
    await permissionSetter(canonicalDestinationDirectory, directory: true);

    final destinationStem =
        '${time.microsecondsSinceEpoch}-${digest.substring(0, 12)}';
    var collision = 0;
    var destinationPath = p.join(
      canonicalDestinationDirectory,
      '$destinationStem.${validated.extension}',
    );
    while (await File(destinationPath).exists() ||
        await File('$destinationPath.part').exists()) {
      collision++;
      destinationPath = p.join(
        canonicalDestinationDirectory,
        '$destinationStem-$collision.${validated.extension}',
      );
    }
    final temporaryPath = '$destinationPath.part';
    var renamed = false;
    try {
      await File(temporaryPath).writeAsBytes(bytes, flush: true);
      await File(temporaryPath).rename(destinationPath);
      renamed = true;
      await permissionSetter(destinationPath, directory: false);
    } catch (_) {
      final temporary = File(temporaryPath);
      if (await temporary.exists()) await temporary.delete();
      if (renamed) {
        final destination = File(destinationPath);
        if (await destination.exists()) await destination.delete();
      }
      rethrow;
    }

    final relativePath = p
        .relative(destinationPath, from: canonicalRoot)
        .replaceAll('\\', '/');
    return EvidenceArtifact(
      projectId: project.id!,
      vulnerabilityId: vulnerabilityId,
      fileName: p.basename(sourcePath),
      relativePath: relativePath,
      mediaType: validated.mediaType,
      caption: normalizedCaption,
      source: source,
      capturedAt: time,
      sha256: digest,
      sizeBytes: bytes.length,
      width: validated.width,
      height: validated.height,
    );
  }

  static Future<ValidatedEvidenceImage> validateImageFile(
    String sourcePath,
  ) async {
    final sourceFile = File(sourcePath);
    if (!await sourceFile.exists()) {
      throw FileSystemException('Evidence image does not exist', sourcePath);
    }
    final size = await sourceFile.length();
    if (size <= 0 || size > maxImageBytes) {
      throw FormatException(
        'Evidence image must be between 1 byte and $maxImageBytes bytes',
      );
    }
    final bytes = await sourceFile.readAsBytes();
    if (bytes.isEmpty || bytes.length > maxImageBytes) {
      throw const FormatException('Evidence image exceeds safe size limits.');
    }
    final imageType = _detectImageType(bytes);
    if (imageType == null) {
      throw const FormatException(
        'Evidence must be a PNG, JPEG, or WebP image',
      );
    }
    final dimensions = await _decodeAndValidateImage(
      bytes,
      imageType.extension,
    );
    return ValidatedEvidenceImage(
      bytes: bytes,
      extension: imageType.extension,
      mediaType: imageType.mediaType,
      width: dimensions.$1,
      height: dimensions.$2,
    );
  }

  static Future<(int, int)> _decodeAndValidateImage(
    Uint8List bytes,
    String expectedExtension,
  ) async {
    final result = await Isolate.run<List<Object>?>(() {
      final decoder = img.findDecoderForData(bytes);
      if (decoder == null) return null;
      final expectedFormat = switch (expectedExtension) {
        'png' => img.ImageFormat.png,
        'jpg' => img.ImageFormat.jpg,
        'webp' => img.ImageFormat.webp,
        _ => img.ImageFormat.invalid,
      };
      if (decoder.format != expectedFormat) return null;
      final info = decoder.startDecode(bytes);
      if (info == null) return null;
      final width = info.width;
      final height = info.height;
      if (width <= 0 ||
          height <= 0 ||
          width > maxImageDimension ||
          height > maxImageDimension ||
          width * height > maxImagePixels) {
        return <Object>['dimensions', width, height];
      }
      if (decoder.decodeFrame(0) == null) return null;
      return <Object>['ok', width, height];
    });
    if (result == null) {
      throw const FormatException(
        'Evidence image is malformed or undecodable.',
      );
    }
    if (result.first == 'dimensions') {
      throw const FormatException(
        'Evidence image dimensions exceed safe limits.',
      );
    }
    return (result[1] as int, result[2] as int);
  }

  static Future<String> captureDesktop({
    int delaySeconds = 3,
    Future<ProcessResult> Function(String, List<String>)? runProcess,
  }) async {
    if (!Platform.isLinux) {
      throw UnsupportedError(
        'Desktop capture is currently available on Linux; import an image on this platform.',
      );
    }
    await cleanupStaleCaptures();
    final delay = delaySeconds.clamp(1, 10);
    final captureDirectory = await Directory.systemTemp.createTemp(
      'llmtary-evidence-',
    );
    await _setOwnerOnly(captureDirectory.path, directory: true);
    final path = p.join(captureDirectory.path, 'screenshot.png');
    final runner =
        runProcess ??
        (String executable, List<String> arguments) =>
            Process.run(executable, arguments);

    try {
      ProcessResult result;
      try {
        result = await runner('scrot', ['-d', '$delay', path]);
      } on ProcessException {
        result = await runner('gnome-screenshot', ['-d', '$delay', '-f', path]);
      }
      final file = File(path);
      if (result.exitCode != 0 ||
          !await file.exists() ||
          await file.length() == 0) {
        throw FileSystemException('Desktop screenshot capture failed', path);
      }
      await _setOwnerOnly(path, directory: false);
      return path;
    } catch (_) {
      await deleteTemporaryCapture(path);
      rethrow;
    }
  }

  static Future<void> deleteTemporaryCapture(String screenshotPath) async {
    final parent = File(p.absolute(screenshotPath)).parent;
    final systemTemp = p.normalize(p.absolute(Directory.systemTemp.path));
    final normalizedParent = p.normalize(parent.path);
    if (!p.isWithin(systemTemp, normalizedParent) ||
        !p.basename(normalizedParent).startsWith('llmtary-evidence-')) {
      throw StateError('Refusing to delete a non-LLMtary temporary directory');
    }
    if (await parent.exists()) await parent.delete(recursive: true);
  }

  static void deleteTemporaryCaptureSync(String screenshotPath) {
    final parent = File(p.absolute(screenshotPath)).parent;
    final systemTemp = p.normalize(p.absolute(Directory.systemTemp.path));
    final normalizedParent = p.normalize(parent.path);
    if (!p.isWithin(systemTemp, normalizedParent) ||
        !p.basename(normalizedParent).startsWith('llmtary-evidence-')) {
      throw StateError('Refusing to delete a non-LLMtary temporary directory');
    }
    if (parent.existsSync()) parent.deleteSync(recursive: true);
  }

  static Future<void> cleanupStaleCaptures({
    Duration maxAge = const Duration(hours: 24),
  }) async {
    final now = DateTime.now();
    await for (final entry in Directory.systemTemp.list(followLinks: false)) {
      if (entry is! Directory ||
          !p.basename(entry.path).startsWith('llmtary-evidence-')) {
        continue;
      }
      try {
        final modified = (await entry.stat()).modified;
        if (now.difference(modified) >= maxAge) {
          await entry.delete(recursive: true);
        }
      } on FileSystemException {
        // A concurrent process may already have removed the directory.
      }
    }
  }

  static Future<void> _setOwnerOnly(
    String path, {
    required bool directory,
  }) async {
    if (!Platform.isLinux && !Platform.isMacOS) return;
    final result = await Process.run('chmod', [
      directory ? '700' : '600',
      path,
    ]);
    if (result.exitCode != 0) {
      throw FileSystemException(
        'Unable to restrict evidence permissions',
        path,
      );
    }
  }

  static Future<Uint8List> loadEvidenceBytes({
    required Project project,
    required EvidenceArtifact artifact,
  }) async {
    final file = await _resolveStoredFile(project, artifact);
    if (!await file.exists()) {
      throw FileSystemException('Evidence file is missing', file.path);
    }
    final bytes = await file.readAsBytes();
    final digest = await Isolate.run(
      () => EvidencePackageBuilder.sha256Hex(bytes),
    );
    if (bytes.length != artifact.sizeBytes || digest != artifact.sha256) {
      throw StateError(
        'Evidence integrity check failed for ${artifact.fileName}',
      );
    }
    return bytes;
  }

  static Future<List<ReportEvidence>> loadReportEvidence({
    required Project project,
    required List<EvidenceArtifact> artifacts,
  }) async {
    final aggregateBytes = artifacts.fold<int>(
      0,
      (total, artifact) => total + artifact.sizeBytes,
    );
    if (aggregateBytes > EvidencePackageBuilder.maxAggregateEvidenceBytes) {
      throw StateError(
        'Visual evidence exceeds the 50 MiB report/package limit',
      );
    }
    final result = <ReportEvidence>[];
    for (final artifact in artifacts) {
      final bytes = await loadEvidenceBytes(
        project: project,
        artifact: artifact,
      );
      final dataUri = await Isolate.run(
        () => 'data:${artifact.mediaType};base64,${base64Encode(bytes)}',
      );
      result.add(ReportEvidence(artifact: artifact, dataUri: dataUri));
    }
    return result;
  }

  static Future<void> deleteEvidenceFile({
    required Project project,
    required EvidenceArtifact artifact,
  }) async {
    final staged = await stageEvidenceDeletion(
      project: project,
      artifact: artifact,
    );
    await finalizeStagedDeletion(staged);
  }

  static Future<StagedEvidenceDeletion> stageEvidenceDeletion({
    required Project project,
    required EvidenceArtifact artifact,
  }) async {
    final file = await _resolveStoredFile(project, artifact);
    final stagedPath =
        '${file.path}.deleting-${DateTime.now().microsecondsSinceEpoch}';
    Uint8List? backupBytes;
    if (await file.exists()) {
      backupBytes = await file.readAsBytes();
      await file.rename(stagedPath);
    }
    return StagedEvidenceDeletion(
      originalPath: file.path,
      stagedPath: stagedPath,
      backupBytes: backupBytes,
    );
  }

  static Future<void> restoreStagedDeletion(
    StagedEvidenceDeletion staged,
  ) async {
    final stagedFile = File(staged.stagedPath);
    if (await File(staged.originalPath).exists()) {
      throw FileSystemException(
        'Cannot restore evidence because the original path exists',
        staged.originalPath,
      );
    }
    if (await stagedFile.exists()) {
      await stagedFile.rename(staged.originalPath);
      return;
    }
    if (staged.backupBytes != null) {
      await Directory(p.dirname(staged.originalPath)).create(recursive: true);
      await File(
        staged.originalPath,
      ).writeAsBytes(staged.backupBytes!, flush: true);
      await _setOwnerOnly(staged.originalPath, directory: false);
    }
  }

  static Future<void> finalizeStagedDeletion(
    StagedEvidenceDeletion staged,
  ) async {
    final stagedFile = File(staged.stagedPath);
    if (await stagedFile.exists()) await stagedFile.delete();
  }

  static Future<File> _resolveStoredFile(
    Project project,
    EvidenceArtifact artifact,
  ) async {
    if (project.id == null || artifact.projectId != project.id) {
      throw StateError('Evidence does not belong to the current project');
    }
    if (p.isAbsolute(artifact.relativePath)) {
      throw StateError('Evidence path must be project-relative');
    }
    final root = p.normalize(p.absolute(project.folderPath));
    final resolved = p.normalize(p.join(root, artifact.relativePath));
    if (!p.isWithin(root, resolved)) {
      throw StateError('Evidence path escaped the project folder');
    }
    final canonicalRoot = p.normalize(
      await Directory(root).resolveSymbolicLinks(),
    );
    final canonicalParent = p.normalize(
      await File(resolved).parent.resolveSymbolicLinks(),
    );
    final canonicalResolved = p.join(canonicalParent, p.basename(resolved));
    if (!p.isWithin(canonicalRoot, canonicalResolved)) {
      throw StateError('Evidence path escaped the project folder');
    }
    return File(canonicalResolved);
  }

  static _ImageType? _detectImageType(Uint8List bytes) {
    if (bytes.length >= 8 &&
        bytes[0] == 0x89 &&
        bytes[1] == 0x50 &&
        bytes[2] == 0x4e &&
        bytes[3] == 0x47 &&
        bytes[4] == 0x0d &&
        bytes[5] == 0x0a &&
        bytes[6] == 0x1a &&
        bytes[7] == 0x0a) {
      return const _ImageType('png', 'image/png');
    }
    if (bytes.length >= 3 &&
        bytes[0] == 0xff &&
        bytes[1] == 0xd8 &&
        bytes[2] == 0xff) {
      return const _ImageType('jpg', 'image/jpeg');
    }
    if (bytes.length >= 12 &&
        String.fromCharCodes(bytes.sublist(0, 4)) == 'RIFF' &&
        String.fromCharCodes(bytes.sublist(8, 12)) == 'WEBP') {
      return const _ImageType('webp', 'image/webp');
    }
    return null;
  }
}

class _ImageType {
  final String extension;
  final String mediaType;

  const _ImageType(this.extension, this.mediaType);
}

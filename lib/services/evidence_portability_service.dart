import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import '../models/evidence_artifact.dart';
import '../models/project.dart';
import 'evidence_package_builder.dart';
import 'evidence_storage_service.dart';

class PortableEvidenceBundle {
  final List<Map<String, Object?>> entries;
  final Map<String, Uint8List> files;

  const PortableEvidenceBundle({required this.entries, required this.files});
}

class EvidencePortabilityService {
  static Future<void> ensureOwnerOnly(
    String path, {
    required bool directory,
    Future<ProcessResult> Function(String, List<String>)? runProcess,
  }) async {
    if (!Platform.isLinux && !Platform.isMacOS) return;
    final runner = runProcess ?? Process.run;
    final result = await runner('chmod', [directory ? '700' : '600', path]);
    if (result.exitCode != 0) {
      throw FileSystemException(
        'Unable to restrict portable evidence permissions',
        path,
      );
    }
  }

  static Future<PortableEvidenceBundle> export({
    required Project project,
    required List<EvidenceArtifact> artifacts,
  }) async {
    _checkAggregateSize(artifacts.map((artifact) => artifact.sizeBytes));
    final entries = <Map<String, Object?>>[];
    final files = <String, Uint8List>{};
    for (var index = 0; index < artifacts.length; index++) {
      final artifact = artifacts[index];
      final extension = switch (artifact.mediaType) {
        'image/png' => 'png',
        'image/jpeg' => 'jpg',
        'image/webp' => 'webp',
        _ => throw StateError('Unsupported portable evidence media type'),
      };
      final archivePath = 'evidence/${index + 1}.$extension';
      final bytes = await EvidenceStorageService.loadEvidenceBytes(
        project: project,
        artifact: artifact,
      );
      files[archivePath] = bytes;
      entries.add({
        'vulnerability_id': artifact.vulnerabilityId,
        'archive_path': archivePath,
        'file_name': artifact.fileName,
        'media_type': artifact.mediaType,
        'caption': artifact.caption,
        'source': artifact.source.name,
        'captured_at': artifact.capturedAt.toUtc().toIso8601String(),
        'sha256': artifact.sha256,
        'size_bytes': artifact.sizeBytes,
      });
    }
    return PortableEvidenceBundle(entries: entries, files: files);
  }

  static Future<List<EvidenceArtifact>> restore({
    required Project project,
    required List<Map<String, dynamic>> entries,
    required Map<int, int> vulnerabilityIdMap,
    required Future<Uint8List> Function(String archivePath) loadBytes,
  }) async {
    if (project.id == null)
      throw StateError('Destination project must be saved');
    _checkAggregateSize(
      entries.map((entry) => (entry['size_bytes'] as num?)?.toInt() ?? 0),
    );
    final restored = <EvidenceArtifact>[];
    try {
      for (final entry in entries) {
        final oldVulnerabilityId = (entry['vulnerability_id'] as num?)?.toInt();
        final newVulnerabilityId = oldVulnerabilityId == null
            ? null
            : vulnerabilityIdMap[oldVulnerabilityId];
        if (newVulnerabilityId == null) {
          throw StateError('Portable evidence references an unknown finding');
        }
        final archivePath = entry['archive_path'] as String? ?? '';
        if (!archivePath.startsWith('evidence/') ||
            archivePath.contains('..') ||
            archivePath.startsWith('/')) {
          throw StateError('Portable evidence path is unsafe');
        }
        final mediaType = entry['media_type'] as String? ?? '';
        final extension = switch (mediaType) {
          'image/png' => 'png',
          'image/jpeg' => 'jpg',
          'image/webp' => 'webp',
          _ => throw StateError('Unsupported portable evidence media type'),
        };
        final bytes = await loadBytes(archivePath);
        final expectedSize = (entry['size_bytes'] as num?)?.toInt() ?? -1;
        final expectedHash = entry['sha256'] as String? ?? '';
        final actualHash = await Isolate.run(
          () => EvidencePackageBuilder.sha256Hex(bytes),
        );
        if (bytes.length != expectedSize || actualHash != expectedHash) {
          throw StateError('Portable evidence integrity check failed');
        }
        final temp = await Directory.systemTemp.createTemp(
          'llmtary-evidence-import-',
        );
        try {
          await ensureOwnerOnly(temp.path, directory: true);
          final source = File('${temp.path}/source.$extension');
          await source.writeAsBytes(bytes, flush: true);
          await ensureOwnerOnly(source.path, directory: false);
          final imported = await EvidenceStorageService.importImage(
            project: project,
            vulnerabilityId: newVulnerabilityId,
            sourcePath: source.path,
            caption: entry['caption'] as String? ?? '',
            source: EvidenceSource.values.firstWhere(
              (source) => source.name == entry['source'],
              orElse: () => EvidenceSource.imported,
            ),
            capturedAt: DateTime.tryParse(
              entry['captured_at'] as String? ?? '',
            ),
          );
          restored.add(
            EvidenceArtifact(
              projectId: imported.projectId,
              vulnerabilityId: imported.vulnerabilityId,
              fileName: entry['file_name'] as String? ?? imported.fileName,
              relativePath: imported.relativePath,
              mediaType: imported.mediaType,
              caption: imported.caption,
              source: imported.source,
              capturedAt: imported.capturedAt,
              sha256: imported.sha256,
              sizeBytes: imported.sizeBytes,
              width: imported.width,
              height: imported.height,
            ),
          );
        } finally {
          if (await temp.exists()) await temp.delete(recursive: true);
        }
      }
      return restored;
    } catch (_) {
      for (final artifact in restored) {
        await EvidenceStorageService.deleteEvidenceFile(
          project: project,
          artifact: artifact,
        );
      }
      rethrow;
    }
  }

  static void _checkAggregateSize(Iterable<int> sizes) {
    final total = sizes.fold<int>(0, (sum, size) => sum + size);
    if (total > EvidencePackageBuilder.maxAggregateEvidenceBytes) {
      throw StateError('Portable evidence exceeds the 50 MiB limit');
    }
  }
}

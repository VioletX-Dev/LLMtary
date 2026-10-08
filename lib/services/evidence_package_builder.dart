import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:archive/archive.dart';
import 'package:pointycastle/digests/sha256.dart';

import '../models/evidence_artifact.dart';

class EvidencePackageBuilder {
  static const int maxAggregateEvidenceBytes = 50 * 1024 * 1024;

  static Future<Uint8List> build({
    required String projectName,
    required List<EvidenceArtifact> artifacts,
    required Future<Uint8List> Function(EvidenceArtifact artifact) loadBytes,
    Map<int, Map<String, String>> findingMetadata = const {},
    String? reportHtml,
  }) async {
    final aggregateBytes = artifacts.fold<int>(
      0,
      (total, artifact) => total + artifact.sizeBytes,
    );
    if (aggregateBytes > maxAggregateEvidenceBytes) {
      throw StateError(
        'Visual evidence exceeds the 50 MiB report/package limit',
      );
    }
    final archiveEntries = <Map<String, Object>>[];
    final manifestEntries = <Map<String, Object?>>[];
    final usedPaths = <String>{};

    for (final artifact in artifacts) {
      final bytes = await loadBytes(artifact);
      final digest = await Isolate.run(() => sha256Hex(bytes));
      if (digest != artifact.sha256 || bytes.length != artifact.sizeBytes) {
        throw StateError(
          'Evidence integrity check failed for ${artifact.fileName}',
        );
      }

      final basePath = artifact.packagePath;
      var packagePath = basePath;
      var collision = 0;
      while (!usedPaths.add(packagePath)) {
        collision++;
        final dot = basePath.lastIndexOf('.');
        final identity = artifact.id?.toString() ?? digest.substring(0, 12);
        final suffix = collision == 1 ? identity : '$identity-$collision';
        packagePath = dot > 0
            ? '${basePath.substring(0, dot)}-$suffix${basePath.substring(dot)}'
            : '$basePath-$suffix';
      }

      archiveEntries.add({'path': packagePath, 'bytes': bytes});
      final finding = findingMetadata[artifact.vulnerabilityId];
      manifestEntries.add({
        'id': artifact.id,
        'vulnerability_id': artifact.vulnerabilityId,
        'finding_title': finding?['title'],
        'severity': finding?['severity'],
        'target': finding?['target'],
        'file_name': artifact.fileName,
        'path': packagePath,
        'media_type': artifact.mediaType,
        'caption': artifact.caption,
        'source': artifact.source.name,
        'captured_at': artifact.capturedAt.toUtc().toIso8601String(),
        'sha256': digest,
        'size_bytes': bytes.length,
        'width': artifact.width,
        'height': artifact.height,
      });
    }

    if (reportHtml != null) {
      final reportBytes = utf8.encode(reportHtml);
      archiveEntries.add({
        'path': 'report/report.html',
        'bytes': Uint8List.fromList(reportBytes),
      });
    }

    final manifest = {
      'format': 'llmtary-evidence-package',
      'version': 1,
      'project_name': projectName,
      'generated_at': DateTime.now().toUtc().toIso8601String(),
      'evidence_count': manifestEntries.length,
      'report_path': reportHtml == null ? null : 'report/report.html',
      'evidence': manifestEntries,
    };
    final manifestBytes = utf8.encode(
      const JsonEncoder.withIndent('  ').convert(manifest),
    );
    archiveEntries.add({
      'path': 'manifest.json',
      'bytes': Uint8List.fromList(manifestBytes),
    });

    return Isolate.run(() {
      final archive = Archive();
      for (final entry in archiveEntries) {
        final bytes = entry['bytes'] as Uint8List;
        archive.addFile(
          ArchiveFile(entry['path'] as String, bytes.length, bytes),
        );
      }
      return Uint8List.fromList(ZipEncoder().encode(archive));
    });
  }

  static String sha256Hex(Uint8List bytes) {
    final digest = SHA256Digest().process(bytes);
    return digest.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  }

  static Future<void> writeAtomically(
    String destinationPath,
    Uint8List bytes,
  ) async {
    final destination = File(destinationPath);
    await destination.parent.create(recursive: true);
    final temporary = File(
      '$destinationPath.partial-${pid}-${DateTime.now().microsecondsSinceEpoch}',
    );
    try {
      await temporary.writeAsBytes(bytes, flush: true);
      if (Platform.isLinux || Platform.isMacOS) {
        final chmod = await Process.run('chmod', ['600', temporary.path]);
        if (chmod.exitCode != 0) {
          throw FileSystemException(
            'Unable to restrict evidence package permissions',
            temporary.path,
          );
        }
      }
      await temporary.rename(destinationPath);
    } catch (_) {
      if (await temporary.exists()) await temporary.delete();
      rethrow;
    }
  }
}

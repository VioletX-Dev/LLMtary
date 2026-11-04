import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as p;

import '../models/evidence_artifact.dart';
import 'evidence_repository.dart';

class BrowserEvidenceScreenshotSink {
  final Directory evidenceRoot;
  final int projectId;
  final int vulnerabilityId;
  final EvidenceRepository repository;
  final DateTime Function() now;
  final int maxBytes;

  BrowserEvidenceScreenshotSink({
    required this.evidenceRoot,
    required this.projectId,
    required this.vulnerabilityId,
    required this.repository,
    DateTime Function()? now,
    this.maxBytes = 20 * 1024 * 1024,
  }) : now = now ?? (() => DateTime.now().toUtc());

  Future<int?> capture(List<int> pngBytes) async {
    if (pngBytes.isEmpty || pngBytes.length > maxBytes) {
      throw ArgumentError.value(
        pngBytes.length,
        'pngBytes',
        'Screenshot must be non-empty and within the configured size limit',
      );
    }
    if (projectId <= 0 || vulnerabilityId <= 0) {
      throw ArgumentError('Project and vulnerability ids must be persisted ids');
    }

    final capturedAt = now().toUtc();
    final stamp = capturedAt.toIso8601String().replaceAll(RegExp(r'[^0-9]'), '');
    final fileName = 'browser-$stamp.png';
    final relativePath = p.join(
      'project-$projectId',
      'finding-$vulnerabilityId',
      'browser',
      fileName,
    );
    final rootPath = p.normalize(p.absolute(evidenceRoot.path));
    final destinationPath = p.normalize(p.join(rootPath, relativePath));
    if (!p.isWithin(rootPath, destinationPath)) {
      throw StateError('Evidence destination escaped the configured root');
    }

    final destination = File(destinationPath);
    await destination.parent.create(recursive: true);
    final temporary = File('$destinationPath.part');
    try {
      await temporary.writeAsBytes(pngBytes, flush: true);
      await temporary.rename(destinationPath);
      final id = await repository.insert(EvidenceArtifact(
        projectId: projectId,
        vulnerabilityId: vulnerabilityId,
        fileName: fileName,
        relativePath: relativePath,
        mediaType: 'image/png',
        caption: 'Browser target state captured during validation',
        source: EvidenceSource.captured,
        capturedAt: capturedAt,
        sha256: sha256.convert(pngBytes).toString(),
        sizeBytes: pngBytes.length,
      ));
      return id;
    } catch (_) {
      if (await temporary.exists()) await temporary.delete();
      if (await destination.exists()) await destination.delete();
      rethrow;
    }
  }
}

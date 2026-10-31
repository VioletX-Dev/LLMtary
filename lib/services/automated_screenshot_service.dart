import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../database/database_helper.dart';
import '../models/evidence_artifact.dart';
import '../models/project.dart';
import 'evidence_package_builder.dart';
import 'evidence_storage_service.dart';

typedef CommandOutputRenderer =
    Future<String> Function({
      required String phase,
      required String targetLabel,
      required String command,
      required String output,
    });

class AutomatedScreenshotService {
  static Future<EvidenceArtifact> captureFinding({
    required Project project,
    required int vulnerabilityId,
    required String phase,
    required String targetLabel,
    required String command,
    required String output,
    CommandOutputRenderer? renderCommandOutput,
    Future<void> Function(EvidenceArtifact)? insertArtifact,
    DateTime? capturedAt,
  }) async {
    final ownsCapture = renderCommandOutput == null;
    final sourcePath =
        await (renderCommandOutput?.call(
              phase: phase,
              targetLabel: targetLabel,
              command: command,
              output: output,
            ) ??
            EvidenceStorageService.renderCommandOutput(
              phase: phase,
              targetLabel: targetLabel,
              command: command,
              output: output,
            ));
    try {
      final artifact = await EvidenceStorageService.importImage(
        project: project,
        vulnerabilityId: vulnerabilityId,
        sourcePath: sourcePath,
        caption:
            'Automatically rendered $phase terminal command and output for ${targetLabel.trim().isEmpty ? 'the current target' : targetLabel.trim()}.',
        source: EvidenceSource.captured,
        capturedAt: capturedAt,
      );
      await (insertArtifact?.call(artifact) ??
          DatabaseHelper.insertEvidenceArtifact(artifact));
      return artifact;
    } finally {
      if (ownsCapture) {
        await EvidenceStorageService.deleteTemporaryCapture(sourcePath);
      }
    }
  }

  static Future<String> captureOperational({
    required Project project,
    required String phase,
    required String targetLabel,
    required String command,
    required String output,
    CommandOutputRenderer? renderCommandOutput,
    DateTime? capturedAt,
  }) async {
    final ownsCapture = renderCommandOutput == null;
    final sourcePath =
        await (renderCommandOutput?.call(
              phase: phase,
              targetLabel: targetLabel,
              command: command,
              output: output,
            ) ??
            EvidenceStorageService.renderCommandOutput(
              phase: phase,
              targetLabel: targetLabel,
              command: command,
              output: output,
            ));
    try {
      final image = await EvidenceStorageService.validateImageFile(sourcePath);
      final time = (capturedAt ?? DateTime.now()).toUtc();
      final phaseSlug = _slug(phase);
      final targetSlug = _slug(targetLabel.isEmpty ? 'project' : targetLabel);
      final root = p.normalize(p.absolute(project.folderPath));
      final directory = p.normalize(
        p.join(root, 'evidence', 'automated', phaseSlug, targetSlug),
      );
      if (!p.isWithin(root, directory)) {
        throw StateError(
          'Automated evidence destination escaped project folder',
        );
      }
      await Directory(directory).create(recursive: true);
      final canonicalRoot = p.normalize(
        await Directory(root).resolveSymbolicLinks(),
      );
      final canonicalDirectory = p.normalize(
        await Directory(directory).resolveSymbolicLinks(),
      );
      if (!p.isWithin(canonicalRoot, canonicalDirectory)) {
        throw StateError(
          'Automated evidence destination escaped project folder',
        );
      }
      if (Platform.isLinux) {
        await Process.run('chmod', ['0700', canonicalDirectory]);
      }
      final imageDigest = EvidencePackageBuilder.sha256Hex(image.bytes);
      final commandDigest = EvidencePackageBuilder.sha256Hex(
        utf8.encode(command),
      );
      final outputDigest = EvidencePackageBuilder.sha256Hex(
        utf8.encode(output),
      );
      final stem =
          '${time.microsecondsSinceEpoch}-${imageDigest.substring(0, 12)}';
      final imagePath = p.join(canonicalDirectory, '$stem.${image.extension}');
      final metadataPath = p.join(canonicalDirectory, '$stem.json');
      await File(imagePath).writeAsBytes(image.bytes, flush: true);
      await File(metadataPath).writeAsString(
        const JsonEncoder.withIndent('  ').convert({
          'captured_at': time.toIso8601String(),
          'phase': phase,
          'target': targetLabel,
          'image_sha256': imageDigest,
          'command_sha256': commandDigest,
          'output_sha256': outputDigest,
          'capture': 'terminal_output',
        }),
        flush: true,
      );
      if (Platform.isLinux) {
        await Process.run('chmod', ['0600', imagePath, metadataPath]);
      }
      return p.relative(imagePath, from: canonicalRoot).replaceAll('\\', '/');
    } finally {
      if (ownsCapture) {
        await EvidenceStorageService.deleteTemporaryCapture(sourcePath);
      }
    }
  }

  static String _slug(String value) {
    final slug = value
        .toLowerCase()
        .replaceAll(RegExp(r'[^a-z0-9.-]+'), '-')
        .replaceAll(RegExp(r'^-+|-+$'), '');
    return slug.isEmpty
        ? 'unspecified'
        : slug.substring(0, slug.length.clamp(0, 80));
  }
}

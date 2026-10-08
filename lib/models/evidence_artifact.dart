import 'package:path/path.dart' as p;

enum EvidenceSource { captured, imported }

class EvidenceArtifact {
  final int? id;
  final int projectId;
  final int vulnerabilityId;
  final String fileName;
  final String relativePath;
  final String mediaType;
  final String caption;
  final EvidenceSource source;
  final DateTime capturedAt;
  final String sha256;
  final int sizeBytes;
  final int? width;
  final int? height;

  const EvidenceArtifact({
    this.id,
    required this.projectId,
    required this.vulnerabilityId,
    required this.fileName,
    required this.relativePath,
    required this.mediaType,
    required this.caption,
    required this.source,
    required this.capturedAt,
    required this.sha256,
    required this.sizeBytes,
    this.width,
    this.height,
  });

  String get packagePath {
    final base = p.basename(fileName);
    final extension = p.extension(base).toLowerCase();
    final stem = p
        .basenameWithoutExtension(base)
        .replaceAll(RegExp(r'[^a-zA-Z0-9._-]+'), '_')
        .replaceAll(RegExp(r'^[_\.]+|[_\.]+$'), '');
    final safeStem = stem.isEmpty ? 'evidence' : stem;
    return 'evidence/finding-$vulnerabilityId/$safeStem$extension';
  }

  Map<String, Object?> toMap() => {
    'id': id,
    'project_id': projectId,
    'vulnerability_id': vulnerabilityId,
    'file_name': fileName,
    'relative_path': relativePath,
    'media_type': mediaType,
    'caption': caption,
    'source': source.name,
    'captured_at': capturedAt.toUtc().toIso8601String(),
    'sha256': sha256,
    'size_bytes': sizeBytes,
    'width': width,
    'height': height,
  };

  factory EvidenceArtifact.fromMap(Map<String, Object?> map) =>
      EvidenceArtifact(
        id: map['id'] as int?,
        projectId: map['project_id'] as int,
        vulnerabilityId: map['vulnerability_id'] as int,
        fileName: map['file_name'] as String,
        relativePath: map['relative_path'] as String,
        mediaType: map['media_type'] as String,
        caption: map['caption'] as String? ?? '',
        source: EvidenceSource.values.firstWhere(
          (value) => value.name == map['source'],
          orElse: () => EvidenceSource.imported,
        ),
        capturedAt: DateTime.parse(map['captured_at'] as String).toUtc(),
        sha256: map['sha256'] as String,
        sizeBytes: map['size_bytes'] as int,
        width: map['width'] as int?,
        height: map['height'] as int?,
      );
}

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';

void main() {
  group('EvidenceArtifact', () {
    test('round-trips persistence metadata without an absolute path', () {
      final capturedAt = DateTime.utc(2026, 10, 7, 20, 30);
      final artifact = EvidenceArtifact(
        id: 9,
        projectId: 3,
        vulnerabilityId: 12,
        fileName: 'login bypass.png',
        relativePath: 'evidence/finding-12/ev-9.png',
        mediaType: 'image/png',
        caption: 'Administrative session after authentication bypass',
        source: EvidenceSource.captured,
        capturedAt: capturedAt,
        sha256: 'a' * 64,
        sizeBytes: 4096,
        width: 1440,
        height: 900,
      );

      final restored = EvidenceArtifact.fromMap(artifact.toMap());

      expect(restored.id, 9);
      expect(restored.projectId, 3);
      expect(restored.vulnerabilityId, 12);
      expect(restored.relativePath, 'evidence/finding-12/ev-9.png');
      expect(restored.caption, contains('authentication bypass'));
      expect(restored.source, EvidenceSource.captured);
      expect(restored.capturedAt, capturedAt);
      expect(restored.sha256, 'a' * 64);
      expect(restored.width, 1440);
      expect(restored.height, 900);
      expect(artifact.toMap().containsKey('absolutePath'), isFalse);
    });

    test('creates a traversal-safe package path', () {
      final artifact = EvidenceArtifact(
        projectId: 3,
        vulnerabilityId: 12,
        fileName: '../../admin session.PNG',
        relativePath: 'evidence/finding-12/ev.png',
        mediaType: 'image/png',
        caption: '',
        source: EvidenceSource.imported,
        capturedAt: DateTime.utc(2026),
        sha256: 'b' * 64,
        sizeBytes: 10,
      );

      expect(artifact.packagePath, 'evidence/finding-12/admin_session.png');
      expect(artifact.packagePath, isNot(contains('..')));
    });
  });
}

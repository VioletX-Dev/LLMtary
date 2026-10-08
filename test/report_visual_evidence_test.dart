import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/evidence_artifact.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/models/report_evidence.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/report_generator.dart';

void main() {
  final project = Project(
    id: 3,
    name: 'Magic Link Test',
    folderPath: '/tmp/project',
    createdAt: DateTime.utc(2026),
    lastOpenedAt: DateTime.utc(2026),
  );
  final vulnerability = Vulnerability(
    id: 12,
    projectId: 3,
    problem: 'Authentication bypass',
    description: 'A crafted magic link bypasses authentication.',
    severity: 'HIGH',
    confidence: 'HIGH',
    evidence: 'Server returned an authenticated session.',
    recommendation: 'Bind links to the requesting user.',
    status: VulnerabilityStatus.confirmed,
  );
  final artifact = EvidenceArtifact(
    id: 9,
    projectId: 3,
    vulnerabilityId: 12,
    fileName: 'auth bypass.png',
    relativePath: 'evidence/finding-12/ev-9.png',
    mediaType: 'image/png',
    caption: 'Administrative dashboard reached without authentication',
    source: EvidenceSource.captured,
    capturedAt: DateTime.utc(2026, 10, 7, 20, 30),
    sha256: 'a' * 64,
    sizeBytes: 7,
  );
  final reportEvidence = ReportEvidence(
    artifact: artifact,
    dataUri: 'data:image/png;base64,UE5HREFUQQ==',
  );

  test('HTML report embeds visual evidence under its finding', () {
    final html = ReportGenerator.generateHtml(
      project: project,
      targets: const [],
      vulnerabilities: [vulnerability],
      visualEvidence: [reportEvidence],
    );

    expect(html, contains('Visual Evidence'));
    expect(html, contains(reportEvidence.dataUri));
    expect(html, contains(artifact.caption));
    expect(html, contains(artifact.sha256));
  });

  test('Markdown report embeds visual evidence under its finding', () {
    final markdown = ReportGenerator.generateMarkdown(
      project: project,
      targets: const [],
      vulnerabilities: [vulnerability],
      visualEvidence: [reportEvidence],
    );

    expect(markdown, contains('**Visual Evidence:**'));
    expect(
      markdown,
      contains('![${artifact.caption}](${reportEvidence.dataUri})'),
    );
    expect(markdown, contains('SHA-256: `${artifact.sha256}`'));
  });

  test('Markdown report neutralizes markup in evidence captions', () {
    final unsafeArtifact = EvidenceArtifact(
      id: 10,
      projectId: 3,
      vulnerabilityId: 12,
      fileName: 'unsafe.png',
      relativePath: 'evidence/finding-12/unsafe.png',
      mediaType: 'image/png',
      caption: '<script>alert(1)</script>](',
      source: EvidenceSource.imported,
      capturedAt: DateTime.utc(2026, 10, 7),
      sha256: 'b' * 64,
      sizeBytes: 7,
    );
    final markdown = ReportGenerator.generateMarkdown(
      project: project,
      targets: const [],
      vulnerabilities: [vulnerability],
      visualEvidence: [
        ReportEvidence(
          artifact: unsafeArtifact,
          dataUri: reportEvidence.dataUri,
        ),
      ],
    );

    expect(markdown, isNot(contains('<script>')));
    expect(markdown, contains('&lt;script&gt;'));
    expect(markdown, contains(r'\]\('));
  });
}

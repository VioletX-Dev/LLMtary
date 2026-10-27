import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/candidate_closure.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/legacy_closure_mapper.dart';

Vulnerability vuln(VulnerabilityStatus status, String reason) => Vulnerability(
  id: 5,
  projectId: 2,
  targetId: 3,
  targetAddress: '192.0.2.5',
  problem: 'Test',
  description: 'Test',
  severity: 'LOW',
  confidence: 'LOW',
  evidence: '',
  recommendation: '',
  status: status,
  statusReason: reason,
);

void main() {
  test('maps legacy terminal statuses without changing finding status', () {
    expect(
      LegacyClosureMapper.map(
        vuln(VulnerabilityStatus.confirmed, 'direct proof'),
      ).disposition,
      CandidateDisposition.verifiedFinding,
    );
    expect(
      LegacyClosureMapper.map(
        vuln(VulnerabilityStatus.notVulnerable, 'rejected'),
      ).disposition,
      CandidateDisposition.verifiedNegative,
    );
  });

  test('maps known blockers to explicit closure reasons', () {
    expect(
      LegacyClosureMapper.map(
        vuln(VulnerabilityStatus.undetermined, 'authentication required'),
      ).disposition,
      CandidateDisposition.blockedMissingCredentials,
    );
    expect(
      LegacyClosureMapper.map(
        vuln(VulnerabilityStatus.undetermined, 'maximum iterations reached'),
      ).disposition,
      CandidateDisposition.technicallyInconclusiveBounded,
    );
  });

  test('does not claim bounded exhaustion when no attempt reason exists', () {
    final closure = LegacyClosureMapper.map(
      vuln(VulnerabilityStatus.pending, ''),
    );
    expect(
      closure.disposition,
      CandidateDisposition.pendingCustomerClarification,
    );
    expect(closure.nextAction, isNotEmpty);
  });
}

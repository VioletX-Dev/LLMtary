import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/target.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/phase_rerun_policy.dart';

Vulnerability _finding({
  required int id,
  String type = 'Network',
  VulnerabilityStatus status = VulnerabilityStatus.pending,
  bool selected = false,
}) => Vulnerability(
  id: id,
  problem: 'Finding $id',
  description: 'description',
  severity: 'HIGH',
  confidence: 'HIGH',
  evidence: 'evidence',
  recommendation: 'recommendation',
  vulnerabilityType: type,
  status: status,
  selected: selected,
);

void main() {
  group('PhaseRerunPolicy', () {
    test(
      'ordinary recon skips completed addresses while rerun includes them',
      () {
        final targets = [
          Target(address: '192.0.2.10', status: TargetStatus.complete),
          Target(address: '192.0.2.11', status: TargetStatus.pending),
        ];

        expect(
          PhaseRerunPolicy.reconAddresses(
            const ['192.0.2.10', '192.0.2.11', '192.0.2.10'],
            targets,
            forceRerun: false,
          ),
          ['192.0.2.11'],
        );
        expect(
          PhaseRerunPolicy.reconAddresses(
            const ['192.0.2.10', '192.0.2.11', '192.0.2.10'],
            targets,
            forceRerun: true,
          ),
          ['192.0.2.10', '192.0.2.11'],
        );
      },
    );

    test('failed recon rerun preserves a previously completed target', () {
      final completed = Target(
        address: '192.0.2.10',
        status: TargetStatus.complete,
      );

      expect(
        PhaseRerunPolicy.preservePriorReconResult(completed, forceRerun: true),
        isTrue,
      );
      expect(
        PhaseRerunPolicy.preservePriorReconResult(completed, forceRerun: false),
        isFalse,
      );
    });

    test('analysis rerun includes every completed target', () {
      final targets = [
        Target(
          address: '192.0.2.10',
          status: TargetStatus.complete,
          analysisComplete: true,
        ),
        Target(
          address: '192.0.2.11',
          status: TargetStatus.complete,
          analysisComplete: false,
        ),
        Target(address: '192.0.2.12', status: TargetStatus.pending),
      ];

      expect(
        PhaseRerunPolicy.analysisTargets(
          targets,
          forceRerun: false,
        ).map((target) => target.address),
        ['192.0.2.11'],
      );
      expect(
        PhaseRerunPolicy.analysisTargets(
          targets,
          forceRerun: true,
        ).map((target) => target.address),
        ['192.0.2.10', '192.0.2.11'],
      );
    });

    test(
      'proof rerun includes all real findings and excludes attack chains',
      () {
        final findings = [
          _finding(id: 1, status: VulnerabilityStatus.confirmed),
          _finding(id: 2, selected: true),
          _finding(id: 3, type: 'AttackChain', selected: true),
        ];

        expect(
          PhaseRerunPolicy.proofFindings(
            findings,
            forceRerun: false,
          ).map((finding) => finding.id),
          [2],
        );
        expect(
          PhaseRerunPolicy.proofFindings(
            findings,
            forceRerun: true,
          ).map((finding) => finding.id),
          [1, 2],
        );
      },
    );
  });
}

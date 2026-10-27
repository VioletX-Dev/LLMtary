import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/command_log.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/models/candidate_closure.dart';
import 'package:llmtary/services/candidate_closure_finalizer.dart';
import 'package:llmtary/services/human_validation_work_item_factory.dart';

Vulnerability candidate({
  VulnerabilityStatus status = VulnerabilityStatus.confirmed,
  String problem = 'Missing X-Frame-Options header',
  String evidence = '',
  String? proofCommand,
  String statusReason = '',
}) => Vulnerability(
  id: 42,
  projectId: 7,
  targetId: 3,
  problem: problem,
  description: problem,
  evidence: evidence,
  status: status,
  proofCommand: proofCommand,
  statusReason: statusReason,
  severity: 'Medium',
  confidence: 'HIGH',
  recommendation: 'Add the missing control.',
);

CommandLog log(String command, String output, {int exitCode = 0}) => CommandLog(
  projectId: 7,
  targetId: 3,
  vulnerabilityId: 42,
  command: command,
  output: output,
  exitCode: exitCode,
  timestamp: DateTime.utc(2026, 10, 27),
);

void main() {
  group('deterministic closure finalization', () {
    test(
      'does not turn an unsupported confirmed status into a verified finding',
      () {
        final result = CandidateClosureFinalizer.finalize(
          candidate(),
          const [],
        );

        expect(
          result.disposition,
          CandidateDisposition.pendingCustomerClarification,
        );
        expect(
          result.reasonCode,
          ClosureReasonCode.customerClarificationRequired,
        );
      },
    );

    test('accepts direct finding-specific initial evidence', () {
      final result = CandidateClosureFinalizer.finalize(
        candidate(
          evidence:
              'HTTP response headers observed: X-Frame-Options header absent',
          proofCommand: 'Initial Evidence Analysis',
        ),
        const [],
      );

      expect(result.disposition, CandidateDisposition.verifiedFinding);
      expect(result.reasonCode, ClosureReasonCode.directEvidenceVerified);
    });

    test(
      'does not turn an unsupported negative status into a verified negative',
      () {
        final result = CandidateClosureFinalizer.finalize(
          candidate(status: VulnerabilityStatus.notVulnerable),
          const [],
        );

        expect(
          result.disposition,
          CandidateDisposition.pendingCustomerClarification,
        );
      },
    );

    test('accepts a linked claim-specific successful negative observation', () {
      const command = 'curl -sS -D - https://example.test/ -o /dev/null';
      final result = CandidateClosureFinalizer.finalize(
        candidate(
          status: VulnerabilityStatus.notVulnerable,
          proofCommand: command,
          statusReason: 'Header is present in the captured response.',
        ),
        [log(command, 'HTTP/2 200\nx-frame-options: DENY\n')],
      );

      expect(result.disposition, CandidateDisposition.verifiedNegative);
      expect(result.reasonCode, ClosureReasonCode.rejectingEvidenceVerified);
      expect(result.attemptedMethods, contains('http-response-headers'));
    });

    test(
      'keeps explicit prerequisite blockers from the conservative mapper',
      () {
        final result = CandidateClosureFinalizer.finalize(
          candidate(
            status: VulnerabilityStatus.undetermined,
            statusReason:
                'Authentication required before validation can continue.',
          ),
          const [],
        );

        expect(
          result.disposition,
          CandidateDisposition.blockedMissingCredentials,
        );
      },
    );
  });

  test('human work item factory creates sanitized stable blocker metadata', () {
    final closure = CandidateClosureFinalizer.finalize(
      candidate(
        status: VulnerabilityStatus.undetermined,
        statusReason: 'MFA required; token=super-secret-value',
      ),
      const [],
    );

    final item = HumanValidationWorkItemFactory.fromClosure(
      candidate(),
      closure,
    );

    expect(item, isNotNull);
    expect(item!.id, 'candidate-42-manualMfaRequired');
    expect(item.authorizationRequired, isNot(contains('super-secret-value')));
    expect(item.safetyNotes.toLowerCase(), contains('manual'));
  });
}

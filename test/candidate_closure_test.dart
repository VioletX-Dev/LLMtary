import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/candidate_closure.dart';
import 'package:llmtary/models/human_validation_work_item.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/candidate_admission_service.dart';
import 'package:llmtary/services/candidate_closeout_service.dart';
import 'package:llmtary/services/candidate_closure_planner.dart';
import 'package:llmtary/services/evidence_contract_registry.dart';

Vulnerability candidate(String problem, {String type = ''}) => Vulnerability(
  id: 7,
  projectId: 1,
  targetId: 2,
  targetAddress: '192.0.2.10',
  problem: problem,
  description: problem,
  severity: 'MEDIUM',
  confidence: 'LOW',
  evidence: 'port reachable',
  recommendation: 'Review',
  vulnerabilityType: type,
);

void main() {
  group('candidate closure lifecycle', () {
    test(
      'all required dispositions are terminal except active workflow states',
      () {
        expect(CandidateDisposition.verifiedFinding.isTerminal, isTrue);
        expect(CandidateDisposition.verifiedNegative.isTerminal, isTrue);
        expect(
          CandidateDisposition.pendingCustomerClarification.isTerminal,
          isTrue,
        );
        expect(CandidateDisposition.investigating.isTerminal, isFalse);
        expect(CandidateDisposition.planned.isTerminal, isFalse);
      },
    );

    test('closure serialization redacts likely secrets and round trips', () {
      final closure = CandidateClosure(
        vulnerabilityId: 7,
        projectId: 1,
        disposition: CandidateDisposition.blockedMissingCredentials,
        reasonCode: ClosureReasonCode.authenticationRequired,
        explanation: 'Authorization: Bearer abcdef123456 password=hunter2',
        attemptedMethods: const ['GET /login'],
        remainingPrerequisites: const ['approved test account'],
        nextAction: 'Provide approved account reference',
        owner: WorkOwner.customer,
        startedAt: DateTime.utc(2026, 1, 1),
        updatedAt: DateTime.utc(2026, 1, 2),
      );
      final encoded = closure.toMap();
      expect(encoded.values.join(' '), isNot(contains('abcdef123456')));
      expect(encoded.values.join(' '), isNot(contains('hunter2')));
      expect(
        CandidateClosure.fromMap(encoded).disposition,
        CandidateDisposition.blockedMissingCredentials,
      );
    });
  });

  group('candidate admission', () {
    test('rejects unknown vulnerability as invalid hypothesis', () {
      final result = CandidateAdmissionService.classify(
        candidate('Unknown Vulnerability'),
      );
      expect(result.accepted, isFalse);
      expect(result.recordKind, CandidateRecordKind.invalidHypothesis);
    });

    test('classifies service detection as an observation', () {
      final result = CandidateAdmissionService.classify(
        candidate(
          'Industrial Control System Protocol Detected — Safety Advisory',
        ),
      );
      expect(result.recordKind, CandidateRecordKind.observation);
      expect(result.accepted, isFalse);
    });
  });

  group('evidence contracts', () {
    test('generic reachability never satisfies an HTTP header contract', () {
      final contract = EvidenceContractRegistry.forCandidate(
        candidate('Missing X-Frame-Options Header'),
      );
      expect(contract.family, ClaimFamily.httpHeaders);
      expect(
        contract.evaluate(
          const EvidenceObservation(
            methodId: 'nmap-service-discovery',
            output: '80/tcp open http',
            exitCode: 0,
          ),
        ),
        EvidenceOutcome.insufficient,
      );
    });

    test('a direct HTTP response can support a missing header claim', () {
      final contract = EvidenceContractRegistry.forCandidate(
        candidate('Missing X-Frame-Options Header'),
      );
      expect(
        contract.evaluate(
          const EvidenceObservation(
            methodId: 'http-response-headers',
            output: 'HTTP/1.1 200 OK\nServer: example\nContent-Type: text/html',
            exitCode: 0,
          ),
        ),
        EvidenceOutcome.supportsClaim,
      );
    });
  });

  group('bounded adaptive planner', () {
    test('blocks authenticated work when no approved session exists', () {
      final plan = CandidateClosurePlanner.plan(
        candidate('Missing Account Lockout Protection'),
        const CandidatePrerequisites(),
      );
      expect(plan.shouldExecute, isFalse);
      expect(plan.disposition, CandidateDisposition.blockedMissingCredentials);
    });

    test('does not repeat the same method and stops at the request budget', () {
      final vuln = candidate('Missing X-Frame-Options Header');
      final first = CandidateClosurePlanner.plan(
        vuln,
        const CandidatePrerequisites(
          targetReachable: true,
          inScope: true,
          requestBudget: 1,
        ),
      );
      expect(first.shouldExecute, isTrue);
      final exhausted = CandidateClosurePlanner.plan(
        vuln,
        const CandidatePrerequisites(
          targetReachable: true,
          inScope: true,
          requestBudget: 1,
          requestsUsed: 1,
          attemptedMethodIds: ['http-response-headers'],
        ),
      );
      expect(exhausted.shouldExecute, isFalse);
      expect(
        exhausted.disposition,
        CandidateDisposition.safeTestingLimitReached,
      );
    });
  });

  group('closeout', () {
    test('blocks completion when a candidate has no defensible closure', () {
      final result = CandidateCloseoutService.validate(
        vulnerabilities: [candidate('TLS Weakness')],
        closuresByVulnerabilityId: const {},
      );
      expect(result.ready, isFalse);
      expect(result.unresolvedVulnerabilityIds, [7]);
    });

    test('accepts a blocked terminal state with owner and next action', () {
      final closure = CandidateClosure(
        vulnerabilityId: 7,
        projectId: 1,
        disposition: CandidateDisposition.blockedMfaOperatorAction,
        reasonCode: ClosureReasonCode.manualMfaRequired,
        explanation: 'Manual MFA completion is required.',
        remainingPrerequisites: const ['operator-completed MFA'],
        nextAction: 'Complete MFA on the appliance',
        owner: WorkOwner.operator,
        startedAt: DateTime.utc(2026),
        updatedAt: DateTime.utc(2026),
      );
      final result = CandidateCloseoutService.validate(
        vulnerabilities: [candidate('Authenticated M365 Review')],
        closuresByVulnerabilityId: {7: closure},
      );
      expect(result.ready, isTrue);
      expect(result.coveragePercent, 100);
    });
  });

  test('human validation cards persist references but redact secrets', () {
    final item = HumanValidationWorkItem(
      id: 'hv-1',
      projectId: 1,
      vulnerabilityId: 7,
      title: 'Controlled relay validation',
      authorizationRequired: 'Written authorization',
      evidenceRequested: const ['protocol transcript'],
      safetyNotes: 'Do not capture credentials. cookie=session-secret',
      owner: WorkOwner.operator,
      status: HumanValidationStatus.waitingAuthorization,
      evidenceReferences: const ['/evidence/review-1.txt'],
      createdAt: DateTime.utc(2026),
      updatedAt: DateTime.utc(2026),
    );
    final map = item.toMap();
    expect(map.values.join(' '), isNot(contains('session-secret')));
    expect(HumanValidationWorkItem.fromMap(map).evidenceReferences, [
      '/evidence/review-1.txt',
    ]);
  });
}

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/validation_run.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/assessment_validation_lifecycle.dart';

void main() {
  test('builds an assessment validation record before execution', () {
    final candidate = Vulnerability(
      id: 12,
      projectId: 3,
      targetId: 7,
      targetAddress: '192.0.2.10',
      problem: 'TLS weakness',
      description: 'Validate TLS protocol support.',
      severity: 'HIGH',
      confidence: 'LOW',
      evidence: '',
      recommendation: 'Harden TLS.',
    );
    final run = AssessmentValidationLifecycle.begin(
      candidate: candidate,
      projectId: 3,
      targetId: 7,
      methodId: 'tls-protocol-negotiation',
      deepSupervised: true,
      now: DateTime.utc(2026, 10, 31),
    );

    expect(run.mode, ValidationRunMode.assessment);
    expect(run.vulnerabilityId, 12);
    expect(run.parameters, contains('tls-protocol-negotiation'));
    expect(run.constraints, contains('exact-command approval'));
    expect(run.constraints, contains('session-local'));
    expect(run.statusBefore, VulnerabilityStatus.pending.name);
  });

  test(
    'maps terminal assessment statuses without claiming failed negatives',
    () {
      final pending = ValidationRun(
        id: 1,
        projectId: 3,
        targetId: 7,
        vulnerabilityId: 12,
        mode: ValidationRunMode.assessment,
        title: 'Validation',
        objective: 'Validate',
        startedAt: DateTime.utc(2026, 10, 31),
      );

      expect(
        AssessmentValidationLifecycle.complete(
          pending,
          status: VulnerabilityStatus.confirmed,
          summary: 'Direct proof.',
        ).outcome,
        ValidationRunOutcome.conditionObserved,
      );
      expect(
        AssessmentValidationLifecycle.complete(
          pending,
          status: VulnerabilityStatus.notVulnerable,
          summary: 'Direct rejecting proof.',
        ).outcome,
        ValidationRunOutcome.conditionNotObserved,
      );
      expect(
        AssessmentValidationLifecycle.complete(
          pending,
          status: VulnerabilityStatus.undetermined,
          summary: 'Tool failed.',
        ).outcome,
        ValidationRunOutcome.inconclusive,
      );
    },
  );

  test('error records never persist raw exception text', () {
    final pending = ValidationRun(
      id: 1,
      projectId: 3,
      targetId: 7,
      vulnerabilityId: 12,
      mode: ValidationRunMode.assessment,
      title: 'Validation',
      objective: 'Validate',
      startedAt: DateTime.utc(2026, 10, 31),
    );

    final failed = AssessmentValidationLifecycle.error(
      pending,
      error: StateError('opaque-session-material'),
    );
    expect(failed.outcome, ValidationRunOutcome.error);
    expect(failed.summary, contains('StateError'));
    expect(failed.summary, isNot(contains('opaque-session-material')));
  });
}

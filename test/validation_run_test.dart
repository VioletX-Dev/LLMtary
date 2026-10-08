import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/validation_run.dart';

void main() {
  test('validation run round-trips retest audit metadata', () {
    final started = DateTime.utc(2026, 10, 8, 12);
    final completed = DateTime.utc(2026, 10, 8, 12, 5);
    final run = ValidationRun(
      id: 9,
      projectId: 3,
      targetId: 7,
      vulnerabilityId: 12,
      mode: ValidationRunMode.retest,
      title: 'Retest authentication bypass',
      objective: 'Verify the original bypass no longer succeeds.',
      parameters: '{"path":"/login"}',
      expectedResult: 'Unauthorized request is rejected.',
      constraints: 'Read-only requests only.',
      statusBefore: 'confirmed',
      baselineStatusReason: 'Original finding was confirmed.',
      baselineProofCommand: 'curl https://target/proof',
      baselineProofOutput: 'original proof output',
      statusAfter: 'notVulnerable',
      outcome: ValidationRunOutcome.fixed,
      summary: 'Original proof could not be reproduced.',
      startedAt: started,
      completedAt: completed,
    );

    final restored = ValidationRun.fromMap(run.toMap());

    expect(restored.id, 9);
    expect(restored.mode, ValidationRunMode.retest);
    expect(restored.outcome, ValidationRunOutcome.fixed);
    expect(restored.vulnerabilityId, 12);
    expect(restored.statusBefore, 'confirmed');
    expect(restored.baselineStatusReason, 'Original finding was confirmed.');
    expect(restored.baselineProofCommand, 'curl https://target/proof');
    expect(restored.baselineProofOutput, 'original proof output');
    expect(restored.statusAfter, 'notVulnerable');
    expect(restored.startedAt, started);
    expect(restored.completedAt, completed);
  });
}

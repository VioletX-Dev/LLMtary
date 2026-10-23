import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/assessment_session_checkpoint.dart';

void main() {
  test('assessment checkpoint round-trips resumable execution work', () {
    final checkpoint = AssessmentSessionCheckpoint(
      projectId: 42,
      phase: AssessmentSessionPhase.execution,
      status: AssessmentSessionStatus.paused,
      pendingVulnerabilityIds: const [7, 9, 11],
      updatedAt: DateTime.utc(2026, 10, 23, 15, 0),
    );

    final restored = AssessmentSessionCheckpoint.decode(checkpoint.encode());

    expect(restored.projectId, 42);
    expect(restored.phase, AssessmentSessionPhase.execution);
    expect(restored.status, AssessmentSessionStatus.paused);
    expect(restored.pendingVulnerabilityIds, [7, 9, 11]);
    expect(restored.canResume, isTrue);
    expect(jsonDecode(checkpoint.encode()), isNot(contains('credential')));
  });

  test('running checkpoint is recoverable after an app restart', () {
    final checkpoint = AssessmentSessionCheckpoint(
      projectId: 5,
      phase: AssessmentSessionPhase.analysis,
      status: AssessmentSessionStatus.running,
      updatedAt: DateTime.utc(2026, 10, 23),
    );

    expect(checkpoint.canResume, isTrue);
    expect(checkpoint.asPaused().status, AssessmentSessionStatus.paused);
    expect(checkpoint.asPaused().phase, AssessmentSessionPhase.analysis);
  });

  test('checkpoint setting key is isolated per project', () {
    expect(AssessmentSessionCheckpoint.settingKey(3), 'assessment_session_3');
    expect(
      AssessmentSessionCheckpoint.settingKey(3),
      isNot(AssessmentSessionCheckpoint.settingKey(4)),
    );
  });

  test('pause gate pauses only at safe orchestration boundaries', () {
    final gate = AssessmentPauseGate();
    expect(gate.isPauseRequested, isFalse);

    gate.requestPause();
    expect(gate.isPauseRequested, isTrue);

    gate.reset();
    expect(gate.isPauseRequested, isFalse);
  });
}

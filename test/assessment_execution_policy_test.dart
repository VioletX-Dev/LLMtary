import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/assessment_execution_policy.dart';

void main() {
  test(
    'approval-gated execution serializes targets to avoid orphaned approvals',
    () {
      expect(
        AssessmentExecutionPolicy.targetParallelism(requireApproval: true),
        1,
      );
    },
  );

  test('automatic execution retains bounded target parallelism', () {
    expect(
      AssessmentExecutionPolicy.targetParallelism(requireApproval: false),
      3,
    );
  });

  test('resume honors explicit pending findings on completed targets', () {
    expect(
      AssessmentExecutionPolicy.includeVulnerabilityForExecution(
        resuming: true,
        targetExecutionComplete: true,
        explicitlyRetesting: false,
      ),
      isTrue,
    );
  });

  test('new execution still skips completed targets unless re-testing', () {
    expect(
      AssessmentExecutionPolicy.includeVulnerabilityForExecution(
        resuming: false,
        targetExecutionComplete: true,
        explicitlyRetesting: false,
      ),
      isFalse,
    );
    expect(
      AssessmentExecutionPolicy.includeVulnerabilityForExecution(
        resuming: false,
        targetExecutionComplete: true,
        explicitlyRetesting: true,
      ),
      isTrue,
    );
  });
}

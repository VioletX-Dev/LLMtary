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

  group('deep human-supervised profile', () {
    test('fails closed without a connected observer', () {
      final profile = AssessmentExecutionPolicy.profileFor(
        requireApproval: true,
        observerConnected: false,
      );
      expect(profile.depth, AssessmentDepth.deepHumanSupervised);
      expect(profile.executionAllowed, isFalse);
      expect(profile.blockReason, contains('observer'));
    });

    test('requires approval and expands bounded budgets while observed', () {
      final profile = AssessmentExecutionPolicy.profileFor(
        requireApproval: true,
        observerConnected: true,
      );
      expect(profile.executionAllowed, isTrue);
      expect(profile.requireExactCommandApproval, isTrue);
      expect(profile.retryBudget, 5);
      expect(profile.toolBudget, 8);
      expect(profile.requestBudget, 30);
      expect(profile.minimumDistinctMethods, 2);
      expect(profile.targetParallelism, 1);
    });

    test('caps iterations at remaining request budget', () {
      expect(
        AssessmentExecutionPolicy.boundedIterations(
          configuredIterations: 30,
          requestBudget: 30,
          requestsUsed: 8,
        ),
        22,
      );
      expect(
        AssessmentExecutionPolicy.boundedIterations(
          configuredIterations: 15,
          requestBudget: 8,
          requestsUsed: 8,
        ),
        0,
      );
    });

    test(
      'requires direct proof plus two methods or authenticated confirmation for a deep negative',
      () {
        expect(
          AssessmentExecutionPolicy.canConcludeNegative(
            deepSupervised: true,
            hasDirectRejectingEvidence: true,
            distinctMethodCount: 1,
            authenticatedConfirmation: false,
          ),
          isFalse,
        );
        expect(
          AssessmentExecutionPolicy.canConcludeNegative(
            deepSupervised: true,
            hasDirectRejectingEvidence: true,
            distinctMethodCount: 2,
            authenticatedConfirmation: false,
          ),
          isTrue,
        );
        expect(
          AssessmentExecutionPolicy.canConcludeNegative(
            deepSupervised: true,
            hasDirectRejectingEvidence: true,
            distinctMethodCount: 1,
            authenticatedConfirmation: true,
          ),
          isTrue,
        );
        expect(
          AssessmentExecutionPolicy.canConcludeNegative(
            deepSupervised: true,
            hasDirectRejectingEvidence: false,
            distinctMethodCount: 3,
            authenticatedConfirmation: true,
          ),
          isFalse,
        );
      },
    );

    test('standard mode retains conservative limits', () {
      final profile = AssessmentExecutionPolicy.profileFor(
        requireApproval: false,
        observerConnected: false,
      );
      expect(profile.depth, AssessmentDepth.standard);
      expect(profile.executionAllowed, isTrue);
      expect(profile.retryBudget, 3);
      expect(profile.toolBudget, 3);
      expect(profile.requestBudget, 8);
      expect(profile.minimumDistinctMethods, 1);
      expect(profile.targetParallelism, 3);
    });
  });
}

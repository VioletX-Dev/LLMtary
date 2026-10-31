enum AssessmentDepth { standard, deepHumanSupervised }

class AssessmentProfile {
  final AssessmentDepth depth;
  final bool executionAllowed;
  final bool requireExactCommandApproval;
  final int retryBudget;
  final int toolBudget;
  final int requestBudget;
  final int minimumDistinctMethods;
  final int targetParallelism;
  final String blockReason;

  const AssessmentProfile({
    required this.depth,
    required this.executionAllowed,
    required this.requireExactCommandApproval,
    required this.retryBudget,
    required this.toolBudget,
    required this.requestBudget,
    required this.minimumDistinctMethods,
    required this.targetParallelism,
    this.blockReason = '',
  });
}

class AssessmentExecutionPolicy {
  const AssessmentExecutionPolicy._();

  /// Approval-gated execution is the Human-Supervised Deep profile. The
  /// command executor's active approval callback is the observer heartbeat:
  /// if it is absent/disconnected, execution fails closed before any command.
  static AssessmentProfile profileFor({
    required bool requireApproval,
    required bool observerConnected,
  }) {
    if (!requireApproval) {
      return const AssessmentProfile(
        depth: AssessmentDepth.standard,
        executionAllowed: true,
        requireExactCommandApproval: false,
        retryBudget: 3,
        toolBudget: 3,
        requestBudget: 8,
        minimumDistinctMethods: 1,
        targetParallelism: 3,
      );
    }
    return AssessmentProfile(
      depth: AssessmentDepth.deepHumanSupervised,
      executionAllowed: observerConnected,
      requireExactCommandApproval: true,
      retryBudget: 5,
      toolBudget: 8,
      requestBudget: 30,
      minimumDistinctMethods: 2,
      targetParallelism: 1,
      blockReason: observerConnected
          ? ''
          : 'A connected human observer and active approval channel are required.',
    );
  }

  /// Approval prompts share one operator-facing dialog. Serialize targets when
  /// approval is required so one concurrent request cannot orphan another
  /// request's completer and deadlock the assessment.
  static int targetParallelism({required bool requireApproval}) => profileFor(
    requireApproval: requireApproval,
    observerConnected: requireApproval,
  ).targetParallelism;

  static int boundedIterations({
    required int configuredIterations,
    required int requestBudget,
    required int requestsUsed,
  }) {
    final remaining = requestBudget - requestsUsed;
    if (remaining <= 0 || configuredIterations <= 0) return 0;
    return configuredIterations < remaining ? configuredIterations : remaining;
  }

  static bool canConcludeNegative({
    required bool deepSupervised,
    required bool hasDirectRejectingEvidence,
    required int distinctMethodCount,
    required bool authenticatedConfirmation,
  }) {
    if (!hasDirectRejectingEvidence) return false;
    if (!deepSupervised) return true;
    return distinctMethodCount >= 2 || authenticatedConfirmation;
  }

  /// A persisted finding checkpoint is authoritative during resume. A target
  /// may be marked executionComplete from an earlier pass while still having
  /// explicitly checkpointed pending findings.
  static bool includeVulnerabilityForExecution({
    required bool resuming,
    required bool targetExecutionComplete,
    required bool explicitlyRetesting,
  }) => resuming || !targetExecutionComplete || explicitlyRetesting;
}

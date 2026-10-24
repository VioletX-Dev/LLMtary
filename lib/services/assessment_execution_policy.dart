class AssessmentExecutionPolicy {
  const AssessmentExecutionPolicy._();

  /// Approval prompts share one operator-facing dialog. Serialize targets when
  /// approval is required so one concurrent request cannot orphan another
  /// request's completer and deadlock the assessment.
  static int targetParallelism({required bool requireApproval}) =>
      requireApproval ? 1 : 3;

  /// A persisted finding checkpoint is authoritative during resume. A target
  /// may be marked executionComplete from an earlier pass while still having
  /// explicitly checkpointed pending findings.
  static bool includeVulnerabilityForExecution({
    required bool resuming,
    required bool targetExecutionComplete,
    required bool explicitlyRetesting,
  }) =>
      resuming || !targetExecutionComplete || explicitlyRetesting;
}

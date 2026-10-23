class AssessmentExecutionPolicy {
  const AssessmentExecutionPolicy._();

  /// Approval prompts share one operator-facing dialog. Serialize targets when
  /// approval is required so one concurrent request cannot orphan another
  /// request's completer and deadlock the assessment.
  static int targetParallelism({required bool requireApproval}) =>
      requireApproval ? 1 : 3;
}

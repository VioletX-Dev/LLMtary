enum VulnerabilityClass {
  authorization,
  authentication,
  injection,
  configuration,
  informationDisclosure,
  transport,
  other,
}

enum ValidationControl {
  authenticatedBaseline,
  unauthorizedComparison,
  benignNegativeInput,
  protocolBaseline,
}

enum IndependentValidationDecision { confirmed, rejected, inconclusive }

enum IndependentValidationOutcome { confirmed, rejected, inconclusive }

class IndependentValidationInput {
  final VulnerabilityClass vulnerabilityClass;
  final String proposerContextId;
  final String validatorContextId;
  final IndependentValidationDecision proposerDecision;
  final IndependentValidationDecision validatorDecision;
  final List<bool> reproductionAttempts;
  final List<int> directEvidenceArtifactIds;
  final Set<ValidationControl> completedControls;

  const IndependentValidationInput({
    required this.vulnerabilityClass,
    required this.proposerContextId,
    required this.validatorContextId,
    required this.proposerDecision,
    required this.validatorDecision,
    this.reproductionAttempts = const [],
    this.directEvidenceArtifactIds = const [],
    this.completedControls = const {},
  });
}

class IndependentValidationResult {
  final IndependentValidationOutcome outcome;
  final double reproducibilityScore;
  final Set<ValidationControl> missingControls;
  final String reason;

  const IndependentValidationResult({
    required this.outcome,
    required this.reproducibilityScore,
    this.missingControls = const {},
    required this.reason,
  });
}

class IndependentValidationRecord {
  final int? id;
  final int validationRunId;
  final int projectId;
  final int? vulnerabilityId;
  final VulnerabilityClass vulnerabilityClass;
  final String proposerContextId;
  final String validatorContextId;
  final IndependentValidationDecision proposerDecision;
  final IndependentValidationDecision validatorDecision;
  final IndependentValidationOutcome outcome;
  final List<bool> reproductionAttempts;
  final double reproducibilityScore;
  final List<int> directEvidenceArtifactIds;
  final Set<ValidationControl> completedControls;
  final Set<ValidationControl> missingControls;
  final String reason;
  final DateTime createdAt;

  const IndependentValidationRecord({
    this.id,
    required this.validationRunId,
    required this.projectId,
    this.vulnerabilityId,
    required this.vulnerabilityClass,
    required this.proposerContextId,
    required this.validatorContextId,
    required this.proposerDecision,
    required this.validatorDecision,
    required this.outcome,
    this.reproductionAttempts = const [],
    required this.reproducibilityScore,
    this.directEvidenceArtifactIds = const [],
    this.completedControls = const {},
    this.missingControls = const {},
    required this.reason,
    required this.createdAt,
  });
}

enum ValidationRunMode { retest, spotTest }

enum ValidationRunOutcome {
  pending,
  stillVulnerable,
  fixed,
  conditionObserved,
  conditionNotObserved,
  inconclusive,
  error,
}

class ValidationRun {
  final int? id;
  final int projectId;
  final int targetId;
  final int? vulnerabilityId;
  final ValidationRunMode mode;
  final String title;
  final String objective;
  final String parameters;
  final String expectedResult;
  final String constraints;
  final String statusBefore;
  final String baselineStatusReason;
  final String baselineProofCommand;
  final String baselineProofOutput;
  final String statusAfter;
  final ValidationRunOutcome outcome;
  final String summary;
  final DateTime startedAt;
  final DateTime? completedAt;

  const ValidationRun({
    this.id,
    required this.projectId,
    required this.targetId,
    this.vulnerabilityId,
    required this.mode,
    required this.title,
    required this.objective,
    this.parameters = '',
    this.expectedResult = '',
    this.constraints = '',
    this.statusBefore = '',
    this.baselineStatusReason = '',
    this.baselineProofCommand = '',
    this.baselineProofOutput = '',
    this.statusAfter = '',
    this.outcome = ValidationRunOutcome.pending,
    this.summary = '',
    required this.startedAt,
    this.completedAt,
  });

  Map<String, dynamic> toMap() => {
    'id': id,
    'projectId': projectId,
    'targetId': targetId,
    'vulnerabilityId': vulnerabilityId,
    'mode': mode.name,
    'title': title,
    'objective': objective,
    'parameters': parameters,
    'expectedResult': expectedResult,
    'constraints': constraints,
    'statusBefore': statusBefore,
    'baselineStatusReason': baselineStatusReason,
    'baselineProofCommand': baselineProofCommand,
    'baselineProofOutput': baselineProofOutput,
    'statusAfter': statusAfter,
    'outcome': outcome.name,
    'summary': summary,
    'startedAt': startedAt.toIso8601String(),
    'completedAt': completedAt?.toIso8601String(),
  };

  factory ValidationRun.fromMap(Map<String, dynamic> map) => ValidationRun(
    id: map['id'] as int?,
    projectId: map['projectId'] as int,
    targetId: map['targetId'] as int,
    vulnerabilityId: map['vulnerabilityId'] as int?,
    mode: ValidationRunMode.values.firstWhere(
      (value) => value.name == map['mode'],
      orElse: () => ValidationRunMode.spotTest,
    ),
    title: map['title'] as String,
    objective: map['objective'] as String,
    parameters: map['parameters'] as String? ?? '',
    expectedResult: map['expectedResult'] as String? ?? '',
    constraints: map['constraints'] as String? ?? '',
    statusBefore: map['statusBefore'] as String? ?? '',
    baselineStatusReason: map['baselineStatusReason'] as String? ?? '',
    baselineProofCommand: map['baselineProofCommand'] as String? ?? '',
    baselineProofOutput: map['baselineProofOutput'] as String? ?? '',
    statusAfter: map['statusAfter'] as String? ?? '',
    outcome: ValidationRunOutcome.values.firstWhere(
      (value) => value.name == map['outcome'],
      orElse: () => ValidationRunOutcome.pending,
    ),
    summary: map['summary'] as String? ?? '',
    startedAt: DateTime.parse(map['startedAt'] as String),
    completedAt: map['completedAt'] == null
        ? null
        : DateTime.parse(map['completedAt'] as String),
  );

  ValidationRun copyWith({
    int? id,
    String? statusAfter,
    ValidationRunOutcome? outcome,
    String? summary,
    DateTime? completedAt,
  }) => ValidationRun(
    id: id ?? this.id,
    projectId: projectId,
    targetId: targetId,
    vulnerabilityId: vulnerabilityId,
    mode: mode,
    title: title,
    objective: objective,
    parameters: parameters,
    expectedResult: expectedResult,
    constraints: constraints,
    statusBefore: statusBefore,
    baselineStatusReason: baselineStatusReason,
    baselineProofCommand: baselineProofCommand,
    baselineProofOutput: baselineProofOutput,
    statusAfter: statusAfter ?? this.statusAfter,
    outcome: outcome ?? this.outcome,
    summary: summary ?? this.summary,
    startedAt: startedAt,
    completedAt: completedAt ?? this.completedAt,
  );
}

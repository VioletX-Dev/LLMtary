import 'dart:convert';

enum AttackTraceStatus { running, completed, blocked, inconclusive, error }

enum AttackTraceStepKind {
  hypothesis,
  tactic,
  browserAction,
  httpExchange,
  command,
  controlRequest,
  interpretation,
  adaptation,
  validatorResult,
  cleanup,
}

enum AttackTraceValidatorResult { notRun, confirmed, rejected, inconclusive }

class AttackTrace {
  final int? id;
  final int projectId;
  final int targetId;
  final int? vulnerabilityId;
  final String title;
  final AttackTraceStatus status;
  final String summary;
  final DateTime startedAt;
  final DateTime? completedAt;

  const AttackTrace({
    this.id,
    required this.projectId,
    required this.targetId,
    this.vulnerabilityId,
    required this.title,
    this.status = AttackTraceStatus.running,
    this.summary = '',
    required this.startedAt,
    this.completedAt,
  });

  Map<String, Object?> toMap() => {
    'id': id,
    'project_id': projectId,
    'target_id': targetId,
    'vulnerability_id': vulnerabilityId,
    'title': title,
    'status': status.name,
    'summary': summary,
    'started_at': startedAt.toUtc().toIso8601String(),
    'completed_at': completedAt?.toUtc().toIso8601String(),
  };

  factory AttackTrace.fromMap(Map<String, Object?> map) => AttackTrace(
    id: map['id'] as int?,
    projectId: map['project_id'] as int,
    targetId: map['target_id'] as int,
    vulnerabilityId: map['vulnerability_id'] as int?,
    title: map['title'] as String,
    status: AttackTraceStatus.values.firstWhere(
      (value) => value.name == map['status'],
      orElse: () => AttackTraceStatus.error,
    ),
    summary: map['summary'] as String? ?? '',
    startedAt: DateTime.parse(map['started_at'] as String).toUtc(),
    completedAt: map['completed_at'] == null
        ? null
        : DateTime.parse(map['completed_at'] as String).toUtc(),
  );
}

class AttackTraceStep {
  final int? id;
  final int traceId;
  final int? sequence;
  final String stepKey;
  final List<String> parentStepKeys;
  final AttackTraceStepKind kind;
  final String hypothesis;
  final String tactic;
  final String action;
  final String output;
  final String interpretation;
  final String adaptation;
  final List<int> evidenceArtifactIds;
  final int? validationRunId;
  final AttackTraceValidatorResult validatorResult;
  final String cleanupStatus;
  final Map<String, String> metadata;
  final DateTime createdAt;

  const AttackTraceStep({
    this.id,
    required this.traceId,
    this.sequence,
    required this.stepKey,
    this.parentStepKeys = const [],
    required this.kind,
    this.hypothesis = '',
    this.tactic = '',
    this.action = '',
    this.output = '',
    this.interpretation = '',
    this.adaptation = '',
    this.evidenceArtifactIds = const [],
    this.validationRunId,
    this.validatorResult = AttackTraceValidatorResult.notRun,
    this.cleanupStatus = '',
    this.metadata = const {},
    required this.createdAt,
  });

  Map<String, Object?> toMap() => {
    'id': id,
    'trace_id': traceId,
    'sequence_no': sequence,
    'step_key': stepKey,
    'kind': kind.name,
    'hypothesis': hypothesis,
    'tactic': tactic,
    'action': action,
    'output': output,
    'interpretation': interpretation,
    'adaptation': adaptation,
    'evidence_artifact_ids': jsonEncode(evidenceArtifactIds),
    'validation_run_id': validationRunId,
    'validator_result': validatorResult.name,
    'cleanup_status': cleanupStatus,
    'metadata': jsonEncode(metadata),
    'created_at': createdAt.toUtc().toIso8601String(),
  };

  factory AttackTraceStep.fromMap(
    Map<String, Object?> map, {
    List<String> parentStepKeys = const [],
  }) => AttackTraceStep(
    id: map['id'] as int?,
    traceId: map['trace_id'] as int,
    sequence: map['sequence_no'] as int?,
    stepKey: map['step_key'] as String,
    parentStepKeys: parentStepKeys,
    kind: AttackTraceStepKind.values.firstWhere(
      (value) => value.name == map['kind'],
      orElse: () => AttackTraceStepKind.interpretation,
    ),
    hypothesis: map['hypothesis'] as String? ?? '',
    tactic: map['tactic'] as String? ?? '',
    action: map['action'] as String? ?? '',
    output: map['output'] as String? ?? '',
    interpretation: map['interpretation'] as String? ?? '',
    adaptation: map['adaptation'] as String? ?? '',
    evidenceArtifactIds: (jsonDecode(
      map['evidence_artifact_ids'] as String? ?? '[]',
    ) as List).map((value) => value as int).toList(growable: false),
    validationRunId: map['validation_run_id'] as int?,
    validatorResult: AttackTraceValidatorResult.values.firstWhere(
      (value) => value.name == map['validator_result'],
      orElse: () => AttackTraceValidatorResult.notRun,
    ),
    cleanupStatus: map['cleanup_status'] as String? ?? '',
    metadata: (jsonDecode(map['metadata'] as String? ?? '{}') as Map)
        .map((key, value) => MapEntry(key.toString(), value.toString())),
    createdAt: DateTime.parse(map['created_at'] as String).toUtc(),
  );
}

class AttackTraceGraph {
  final AttackTrace trace;
  final List<AttackTraceStep> steps;

  const AttackTraceGraph({required this.trace, required this.steps});

  Set<String> parentsOf(String stepKey) => steps
      .firstWhere((step) => step.stepKey == stepKey)
      .parentStepKeys
      .toSet();

  Set<String> childrenOf(String stepKey) => steps
      .where((step) => step.parentStepKeys.contains(stepKey))
      .map((step) => step.stepKey)
      .toSet();
}

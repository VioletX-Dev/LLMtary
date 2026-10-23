enum CloudAssistPhase { findingConfirmation, reportReview }

enum CloudAssistStatus {
  localOnly,
  cloudAssisted,
  skippedBudget,
  skippedUnavailable,
}

class CloudAssistReview {
  final int? id;
  final int projectId;
  final int? targetId;
  final CloudAssistPhase phase;
  final CloudAssistStatus status;
  final String provider;
  final String modelName;
  final String note;
  final DateTime createdAt;

  const CloudAssistReview({
    this.id,
    required this.projectId,
    this.targetId,
    required this.phase,
    required this.status,
    required this.provider,
    required this.modelName,
    required this.note,
    required this.createdAt,
  });

  Map<String, dynamic> toMap() => {
    'id': id,
    'project_id': projectId,
    'target_id': targetId,
    'phase': phase.name,
    'status': status.name,
    'provider': provider,
    'model_name': modelName,
    'note': note,
    'created_at': createdAt.toIso8601String(),
  };

  factory CloudAssistReview.fromMap(Map<String, dynamic> map) =>
      CloudAssistReview(
        id: map['id'] as int?,
        projectId: map['project_id'] as int,
        targetId: map['target_id'] as int?,
        phase: CloudAssistPhase.values.firstWhere(
          (value) => value.name == map['phase'],
          orElse: () => CloudAssistPhase.findingConfirmation,
        ),
        status: CloudAssistStatus.values.firstWhere(
          (value) => value.name == map['status'],
          orElse: () => CloudAssistStatus.localOnly,
        ),
        provider: map['provider'] as String? ?? '',
        modelName: map['model_name'] as String? ?? '',
        note: map['note'] as String? ?? '',
        createdAt: DateTime.parse(map['created_at'] as String),
      );
}

class CloudAssistResult {
  final CloudAssistPhase phase;
  final CloudAssistStatus status;
  final String note;

  const CloudAssistResult({
    required this.phase,
    required this.status,
    this.note = '',
  });

  /// Cloud assistance is supplemental; every outcome preserves the completed
  /// local workflow.
  bool get completedLocally => true;
}

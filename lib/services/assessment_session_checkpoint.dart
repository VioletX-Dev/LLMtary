import 'dart:convert';

enum AssessmentSessionPhase { analysis, execution }

enum AssessmentSessionStatus { running, pauseRequested, paused, completed }

/// Persisted, non-secret orchestration state for resumable assessment work.
///
/// Work is checkpointed at safe target/finding boundaries. An in-flight model
/// request or approved command is allowed to finish before the pause becomes
/// effective, so pausing never kills a command halfway through.
class AssessmentSessionCheckpoint {
  final int projectId;
  final AssessmentSessionPhase phase;
  final AssessmentSessionStatus status;
  final List<int> pendingVulnerabilityIds;
  final DateTime updatedAt;

  const AssessmentSessionCheckpoint({
    required this.projectId,
    required this.phase,
    required this.status,
    this.pendingVulnerabilityIds = const [],
    required this.updatedAt,
  });

  bool get canResume =>
      status == AssessmentSessionStatus.running ||
      status == AssessmentSessionStatus.pauseRequested ||
      status == AssessmentSessionStatus.paused;

  static String settingKey(int projectId) => 'assessment_session_$projectId';

  AssessmentSessionCheckpoint copyWith({
    AssessmentSessionStatus? status,
    List<int>? pendingVulnerabilityIds,
    DateTime? updatedAt,
  }) => AssessmentSessionCheckpoint(
    projectId: projectId,
    phase: phase,
    status: status ?? this.status,
    pendingVulnerabilityIds:
        pendingVulnerabilityIds ?? this.pendingVulnerabilityIds,
    updatedAt: updatedAt ?? this.updatedAt,
  );

  AssessmentSessionCheckpoint asPaused() => copyWith(
    status: AssessmentSessionStatus.paused,
    updatedAt: DateTime.now().toUtc(),
  );

  Map<String, dynamic> toJson() => {
    'projectId': projectId,
    'phase': phase.name,
    'status': status.name,
    'pendingVulnerabilityIds': pendingVulnerabilityIds,
    'updatedAt': updatedAt.toUtc().toIso8601String(),
  };

  String encode() => jsonEncode(toJson());

  factory AssessmentSessionCheckpoint.fromJson(Map<String, dynamic> json) {
    final phaseName = json['phase'] as String? ?? '';
    final statusName = json['status'] as String? ?? '';
    return AssessmentSessionCheckpoint(
      projectId: (json['projectId'] as num?)?.toInt() ?? 0,
      phase: AssessmentSessionPhase.values.firstWhere(
        (value) => value.name == phaseName,
        orElse: () => AssessmentSessionPhase.analysis,
      ),
      status: AssessmentSessionStatus.values.firstWhere(
        (value) => value.name == statusName,
        orElse: () => AssessmentSessionStatus.paused,
      ),
      pendingVulnerabilityIds:
          (json['pendingVulnerabilityIds'] as List<dynamic>? ?? const [])
              .whereType<num>()
              .map((value) => value.toInt())
              .toList(growable: false),
      updatedAt:
          DateTime.tryParse(json['updatedAt'] as String? ?? '')?.toUtc() ??
          DateTime.now().toUtc(),
    );
  }

  factory AssessmentSessionCheckpoint.decode(String value) =>
      AssessmentSessionCheckpoint.fromJson(
        jsonDecode(value) as Map<String, dynamic>,
      );
}

class AssessmentPauseGate {
  bool _pauseRequested = false;

  bool get isPauseRequested => _pauseRequested;

  void requestPause() => _pauseRequested = true;

  void reset() => _pauseRequested = false;
}

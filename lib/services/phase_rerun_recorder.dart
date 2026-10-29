import '../database/database_helper.dart';

class PhaseRerunRecorder {
  const PhaseRerunRecorder._();

  static String createRunId(String phase) {
    final slug = phase
        .toLowerCase()
        .replaceAll(RegExp(r'[^a-z0-9]+'), '-')
        .replaceAll(RegExp(r'^-+|-+$'), '');
    return '$slug-${DateTime.now().toUtc().microsecondsSinceEpoch}';
  }

  static Future<void> started({
    required int projectId,
    required String phase,
    required String runId,
    required int itemCount,
  }) => DatabaseHelper.insertSessionEvent(
    projectId: projectId,
    targetId: 0,
    eventType: 'phase_rerun_started',
    phase: phase,
    metadata: {
      'run_id': runId,
      'reason': 'User requested phase rerun',
      'item_count': itemCount,
    },
  );

  static Future<void> completed({
    required int projectId,
    required String phase,
    required String runId,
    required int itemCount,
    required String verification,
  }) => DatabaseHelper.insertSessionEvent(
    projectId: projectId,
    targetId: 0,
    eventType: 'phase_rerun_completed',
    phase: phase,
    metadata: {
      'run_id': runId,
      'item_count': itemCount,
      'result': 'completed',
      'verification': verification,
    },
  );

  static Future<void> failed({
    required int projectId,
    required String phase,
    required String runId,
    required int itemCount,
  }) => DatabaseHelper.insertSessionEvent(
    projectId: projectId,
    targetId: 0,
    eventType: 'phase_rerun_failed',
    phase: phase,
    metadata: {
      'run_id': runId,
      'item_count': itemCount,
      'result': 'failed',
      'verification': 'Phase executor did not complete successfully.',
    },
  );
}

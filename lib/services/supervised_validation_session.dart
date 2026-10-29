import 'dart:async';

import '../models/candidate_closure.dart';
import 'supervised_validation_policy.dart';

enum SupervisedSessionState {
  created,
  active,
  paused,
  closing,
  closed,
  terminated,
}

enum SupervisedActionStatus { completed, failed, rejected, blocked }

enum SupervisedEventType {
  sessionStarted,
  sessionPaused,
  sessionResumed,
  actionProposed,
  actionApproved,
  actionRejected,
  actionBlocked,
  actionCompleted,
  actionFailed,
  cleanupVerified,
  sessionClosed,
  sessionTerminated,
}

class SupervisedValidationEvent {
  final SupervisedEventType type;
  final DateTime timestamp;
  final String engagementReference;
  final String observingOperator;
  final String sourceAddress;
  final String destinationAddress;
  final String actionId;
  final String rationale;
  final String expectedEvidence;
  final String detail;
  final List<String> evidenceReferences;

  SupervisedValidationEvent({
    required this.type,
    required this.timestamp,
    required String engagementReference,
    required String observingOperator,
    required String sourceAddress,
    required String destinationAddress,
    String actionId = '',
    String rationale = '',
    String expectedEvidence = '',
    String detail = '',
    List<String> evidenceReferences = const [],
  }) : engagementReference = ClosureSanitizer.text(
         engagementReference,
         maxLength: 300,
       ),
       observingOperator = ClosureSanitizer.text(
         observingOperator,
         maxLength: 300,
       ),
       sourceAddress = ClosureSanitizer.text(sourceAddress, maxLength: 128),
       destinationAddress = ClosureSanitizer.text(
         destinationAddress,
         maxLength: 128,
       ),
       actionId = ClosureSanitizer.text(actionId, maxLength: 300),
       rationale = ClosureSanitizer.text(rationale, maxLength: 1000),
       expectedEvidence = ClosureSanitizer.text(
         expectedEvidence,
         maxLength: 1000,
       ),
       detail = ClosureSanitizer.text(detail, maxLength: 2000),
       evidenceReferences = ClosureSanitizer.list(evidenceReferences);
}

class SupervisedActionOutput {
  final int exitCode;
  final String sanitizedOutput;
  final List<String> evidenceReferences;

  const SupervisedActionOutput({
    required this.exitCode,
    required this.sanitizedOutput,
    this.evidenceReferences = const [],
  });
}

class SupervisedActionResult {
  final SupervisedActionStatus status;
  final String reason;
  final int? exitCode;
  final List<String> evidenceReferences;

  const SupervisedActionResult({
    required this.status,
    required this.reason,
    this.exitCode,
    this.evidenceReferences = const [],
  });
}

typedef SupervisedEventWriter =
    Future<void> Function(SupervisedValidationEvent event);
typedef SupervisedActionApproval =
    Future<bool> Function(SupervisedValidationAction action);
typedef SupervisedActionRunner =
    Future<SupervisedActionOutput> Function(SupervisedValidationAction action);

class SupervisedValidationSession {
  final SupervisedValidationAuthorization authorization;
  final DateTime Function() now;
  final Duration inactivityTimeout;
  final Duration maximumDuration;
  final SupervisedEventWriter persistEvent;
  final SupervisedValidationPolicy policy;

  SupervisedSessionState state = SupervisedSessionState.created;
  DateTime? _startedAt;
  DateTime? _lastActivityAt;
  Future<void> _queue = Future<void>.value();
  final Map<String, List<String>> _cleanupPending = <String, List<String>>{};
  final Map<String, List<String>> _cleanupExecutionEvidence =
      <String, List<String>>{};

  SupervisedValidationSession({
    required this.authorization,
    required this.now,
    required this.persistEvent,
    this.inactivityTimeout = const Duration(minutes: 10),
    this.maximumDuration = const Duration(hours: 2),
    this.policy = const SupervisedValidationPolicy(),
  });

  Future<void> start({required bool observerPresent}) async {
    if (state != SupervisedSessionState.created) {
      throw StateError('The supervised session has already started.');
    }
    if (!observerPresent) {
      throw StateError(
        'A human observer must be present to start the session.',
      );
    }
    final timestamp = now().toUtc();
    final expiry = authorization.expiry;
    if (expiry == null || !timestamp.isBefore(expiry)) {
      throw StateError('The supervised authorization is invalid or expired.');
    }
    _startedAt = timestamp;
    _lastActivityAt = timestamp;
    state = SupervisedSessionState.active;
    await _record(SupervisedEventType.sessionStarted);
  }

  Future<SupervisedActionResult> execute({
    required SupervisedValidationAction action,
    required String rationale,
    required String expectedEvidence,
    required bool observerPresent,
    required SupervisedActionApproval requestApproval,
    required SupervisedActionRunner runner,
  }) {
    final completer = Completer<SupervisedActionResult>();
    _queue = _queue.then((_) async {
      try {
        completer.complete(
          await _executeSerial(
            action: action,
            rationale: rationale,
            expectedEvidence: expectedEvidence,
            observerPresent: observerPresent,
            requestApproval: requestApproval,
            runner: runner,
          ),
        );
      } catch (error, stackTrace) {
        completer.completeError(error, stackTrace);
      }
    });
    return completer.future;
  }

  Future<SupervisedActionResult> _executeSerial({
    required SupervisedValidationAction action,
    required String rationale,
    required String expectedEvidence,
    required bool observerPresent,
    required SupervisedActionApproval requestApproval,
    required SupervisedActionRunner runner,
  }) async {
    final boundary = await _validateSessionBoundary(observerPresent);
    if (boundary != null) return boundary;

    await _record(
      SupervisedEventType.actionProposed,
      action: action,
      rationale: rationale,
      expectedEvidence: expectedEvidence,
    );
    final approved = await requestApproval(action);
    if (!approved) {
      await _record(
        SupervisedEventType.actionRejected,
        action: action,
        rationale: rationale,
        expectedEvidence: expectedEvidence,
        detail: 'The observing operator rejected the exact action.',
      );
      return const SupervisedActionResult(
        status: SupervisedActionStatus.rejected,
        reason: 'The observing operator rejected the exact action.',
      );
    }

    final decision = policy.evaluate(
      authorization: authorization,
      action: action,
      now: now(),
      observerPresent: observerPresent,
      exactActionApproved: true,
    );
    if (!decision.allowed) {
      await _record(
        SupervisedEventType.actionBlocked,
        action: action,
        rationale: rationale,
        expectedEvidence: expectedEvidence,
        detail: decision.reason,
      );
      return SupervisedActionResult(
        status: SupervisedActionStatus.blocked,
        reason: decision.reason,
      );
    }

    await _record(
      SupervisedEventType.actionApproved,
      action: action,
      rationale: rationale,
      expectedEvidence: expectedEvidence,
    );
    _lastActivityAt = now().toUtc();
    try {
      final output = await runner(action);
      _lastActivityAt = now().toUtc();
      if (output.exitCode != 0) {
        await _record(
          SupervisedEventType.actionFailed,
          action: action,
          rationale: rationale,
          expectedEvidence: expectedEvidence,
          detail: output.sanitizedOutput,
          evidenceReferences: output.evidenceReferences,
        );
        return SupervisedActionResult(
          status: SupervisedActionStatus.failed,
          reason: output.sanitizedOutput,
          exitCode: output.exitCode,
          evidenceReferences: output.evidenceReferences,
        );
      }
      if (action.changesState) {
        _cleanupPending[action.actionId] = List.unmodifiable(
          action.cleanupActions,
        );
      } else if (action.exactAction.isNotEmpty &&
          output.evidenceReferences.isNotEmpty) {
        for (final pending in _cleanupPending.entries) {
          if (pending.value.contains(action.exactAction)) {
            _cleanupExecutionEvidence[pending.key] = List.unmodifiable(
              output.evidenceReferences,
            );
          }
        }
      }
      await _record(
        SupervisedEventType.actionCompleted,
        action: action,
        rationale: rationale,
        expectedEvidence: expectedEvidence,
        detail: output.sanitizedOutput,
        evidenceReferences: output.evidenceReferences,
      );
      return SupervisedActionResult(
        status: SupervisedActionStatus.completed,
        reason: 'The approved action completed.',
        exitCode: output.exitCode,
        evidenceReferences: output.evidenceReferences,
      );
    } catch (error) {
      final detail = ClosureSanitizer.text(error.toString(), maxLength: 1000);
      await _record(
        SupervisedEventType.actionFailed,
        action: action,
        rationale: rationale,
        expectedEvidence: expectedEvidence,
        detail: detail,
      );
      return SupervisedActionResult(
        status: SupervisedActionStatus.failed,
        reason: detail,
      );
    }
  }

  Future<SupervisedActionResult?> _validateSessionBoundary(
    bool observerPresent,
  ) async {
    if (state != SupervisedSessionState.active) {
      return const SupervisedActionResult(
        status: SupervisedActionStatus.blocked,
        reason: 'The supervised session is not active.',
      );
    }
    final timestamp = now().toUtc();
    final startedAt = _startedAt!;
    final lastActivityAt = _lastActivityAt!;
    if (!observerPresent ||
        timestamp.difference(lastActivityAt) > inactivityTimeout ||
        timestamp.difference(startedAt) > maximumDuration) {
      state = SupervisedSessionState.terminated;
      await _record(
        SupervisedEventType.sessionTerminated,
        detail: !observerPresent
            ? 'The observing operator is no longer present.'
            : 'The supervised session timed out.',
      );
      return const SupervisedActionResult(
        status: SupervisedActionStatus.blocked,
        reason:
            'Observer presence and active timeout boundaries failed closed.',
      );
    }
    return null;
  }

  Future<void> pause({required String reason}) async {
    if (state != SupervisedSessionState.active) return;
    state = SupervisedSessionState.paused;
    await _record(SupervisedEventType.sessionPaused, detail: reason);
  }

  /// Called by the supervised console timer so observer departure and timeout
  /// boundaries terminate the session even when no new action is submitted.
  Future<bool> enforceTimeouts({required bool observerPresent}) async {
    if (state != SupervisedSessionState.active &&
        state != SupervisedSessionState.paused) {
      return state == SupervisedSessionState.terminated;
    }
    final timestamp = now().toUtc();
    final startedAt = _startedAt!;
    final lastActivityAt = _lastActivityAt!;
    if (observerPresent &&
        timestamp.difference(lastActivityAt) <= inactivityTimeout &&
        timestamp.difference(startedAt) <= maximumDuration) {
      return false;
    }
    state = SupervisedSessionState.terminated;
    await _record(
      SupervisedEventType.sessionTerminated,
      detail: !observerPresent
          ? 'The observing operator is no longer present.'
          : 'The supervised session timed out.',
    );
    return true;
  }

  Future<void> resume({required bool observerPresent}) async {
    if (state != SupervisedSessionState.paused || !observerPresent) {
      throw StateError('Paused session and observer presence are required.');
    }
    _lastActivityAt = now().toUtc();
    state = SupervisedSessionState.active;
    await _record(SupervisedEventType.sessionResumed);
  }

  Future<void> verifyCleanup({required String actionId}) async {
    final evidenceReferences = _cleanupExecutionEvidence[actionId];
    if (!_cleanupPending.containsKey(actionId) ||
        evidenceReferences == null ||
        evidenceReferences.isEmpty) {
      throw StateError(
        'The exact predefined cleanup action must complete with evidence before verification.',
      );
    }
    _cleanupPending.remove(actionId);
    _cleanupExecutionEvidence.remove(actionId);
    await _record(
      SupervisedEventType.cleanupVerified,
      actionId: actionId,
      evidenceReferences: evidenceReferences,
    );
  }

  Future<void> close({bool evidenceReviewed = false}) async {
    await _queue;
    if (_cleanupPending.isNotEmpty) {
      throw StateError('Cleanup verification is still pending.');
    }
    if (!evidenceReviewed) {
      throw StateError(
        'The observing human must review the sanitized evidence before closure.',
      );
    }
    if (state != SupervisedSessionState.active &&
        state != SupervisedSessionState.paused) {
      throw StateError('Only an active or paused session may close.');
    }
    state = SupervisedSessionState.closing;
    await _record(
      SupervisedEventType.sessionClosed,
      detail:
          'Session closed after cleanup verification and human evidence review.',
    );
    state = SupervisedSessionState.closed;
  }

  Future<void> terminate({required String reason}) async {
    state = SupervisedSessionState.terminated;
    await _record(SupervisedEventType.sessionTerminated, detail: reason);
  }

  Future<void> _record(
    SupervisedEventType type, {
    SupervisedValidationAction? action,
    String actionId = '',
    String rationale = '',
    String expectedEvidence = '',
    String detail = '',
    List<String> evidenceReferences = const [],
  }) => persistEvent(
    SupervisedValidationEvent(
      type: type,
      timestamp: now().toUtc(),
      engagementReference: authorization.engagementReference,
      observingOperator: authorization.observingOperator,
      sourceAddress: authorization.sourceAddress,
      destinationAddress: authorization.destinationAddress,
      actionId: action?.actionId ?? actionId,
      rationale: rationale,
      expectedEvidence: expectedEvidence,
      detail: detail,
      evidenceReferences: evidenceReferences,
    ),
  );
}

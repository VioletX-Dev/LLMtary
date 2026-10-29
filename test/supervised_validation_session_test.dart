import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/supervised_validation_policy.dart';
import 'package:llmtary/services/supervised_validation_session.dart';

void main() {
  const authorization = SupervisedValidationAuthorization(
    engagementReference: 'ENG-2026-001',
    observingOperator: 'operator-1',
    sourceAddress: '172.16.2.5',
    destinationAddress: '172.17.2.8',
    expiresAt: '2026-10-29T20:00:00Z',
    maximumHopCount: 1,
  );

  test(
    'AI action executes only after exact approval and records evidence',
    () async {
      final persisted = <SupervisedValidationEvent>[];
      final session = SupervisedValidationSession(
        authorization: authorization,
        now: () => DateTime.utc(2026, 10, 29, 19),
        persistEvent: (event) async => persisted.add(event),
      );
      await session.start(observerPresent: true);

      final result = await session.execute(
        action: const SupervisedValidationAction(
          actionId: 'action-1',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
          opensRemoteSession: true,
        ),
        rationale: 'Validate authorized remote access.',
        expectedEvidence: 'Remote identity and hostname.',
        observerPresent: true,
        requestApproval: (_) async => true,
        runner: (_) async => const SupervisedActionOutput(
          exitCode: 0,
          sanitizedOutput: 'identity=[REDACTED] host=TARGET',
          evidenceReferences: [
            'evidence/action-1.txt',
            'evidence/action-1.png',
          ],
        ),
      );

      expect(result.status, SupervisedActionStatus.completed);
      expect(result.evidenceReferences, contains('evidence/action-1.png'));
      expect(
        persisted.map((event) => event.type),
        containsAll([
          SupervisedEventType.sessionStarted,
          SupervisedEventType.actionProposed,
          SupervisedEventType.actionApproved,
          SupervisedEventType.actionCompleted,
        ]),
      );
    },
  );

  test(
    'actions are serialized and a rejected action never reaches runner',
    () async {
      final firstGate = Completer<void>();
      var active = 0;
      var peak = 0;
      var rejectedRuns = 0;
      final session = SupervisedValidationSession(
        authorization: authorization,
        now: () => DateTime.utc(2026, 10, 29, 19),
        persistEvent: (_) async {},
      );
      await session.start(observerPresent: true);

      Future<SupervisedActionOutput> trackedRunner(
        SupervisedValidationAction _,
      ) async {
        active++;
        if (active > peak) peak = active;
        await firstGate.future;
        active--;
        return const SupervisedActionOutput(exitCode: 0, sanitizedOutput: 'ok');
      }

      final first = session.execute(
        action: const SupervisedValidationAction(
          actionId: 'first',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
        ),
        rationale: 'first',
        expectedEvidence: 'first evidence',
        observerPresent: true,
        requestApproval: (_) async => true,
        runner: trackedRunner,
      );
      final rejected = session.execute(
        action: const SupervisedValidationAction(
          actionId: 'rejected',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
        ),
        rationale: 'rejected',
        expectedEvidence: 'none',
        observerPresent: true,
        requestApproval: (_) async => false,
        runner: (_) async {
          rejectedRuns++;
          return const SupervisedActionOutput(
            exitCode: 0,
            sanitizedOutput: 'bad',
          );
        },
      );

      await Future<void>.delayed(Duration.zero);
      expect(active, 1);
      firstGate.complete();
      await first;
      final rejectedResult = await rejected;
      expect(peak, 1);
      expect(rejectedRuns, 0);
      expect(rejectedResult.status, SupervisedActionStatus.rejected);
    },
  );

  test('pause, observer departure and timeout fail closed', () async {
    var current = DateTime.utc(2026, 10, 29, 19);
    final session = SupervisedValidationSession(
      authorization: authorization,
      now: () => current,
      inactivityTimeout: const Duration(minutes: 5),
      maximumDuration: const Duration(minutes: 30),
      persistEvent: (_) async {},
    );
    await session.start(observerPresent: true);
    await session.pause(reason: 'operator requested');

    final paused = await session.execute(
      action: const SupervisedValidationAction(
        actionId: 'paused',
        sourceAddress: '172.16.2.5',
        destinationAddress: '172.17.2.8',
        hopCount: 1,
      ),
      rationale: 'must not run',
      expectedEvidence: 'none',
      observerPresent: true,
      requestApproval: (_) async => true,
      runner: (_) async =>
          const SupervisedActionOutput(exitCode: 0, sanitizedOutput: 'bad'),
    );
    expect(paused.status, SupervisedActionStatus.blocked);

    await session.resume(observerPresent: true);
    current = current.add(const Duration(minutes: 6));
    final expired = await session.execute(
      action: const SupervisedValidationAction(
        actionId: 'expired',
        sourceAddress: '172.16.2.5',
        destinationAddress: '172.17.2.8',
        hopCount: 1,
      ),
      rationale: 'must not run',
      expectedEvidence: 'none',
      observerPresent: false,
      requestApproval: (_) async => true,
      runner: (_) async =>
          const SupervisedActionOutput(exitCode: 0, sanitizedOutput: 'bad'),
    );
    expect(expired.status, SupervisedActionStatus.blocked);
    expect(session.state, SupervisedSessionState.terminated);
  });

  test('periodic timeout enforcement terminates an idle session', () async {
    var current = DateTime.utc(2026, 10, 29, 19);
    final events = <SupervisedValidationEvent>[];
    final session = SupervisedValidationSession(
      authorization: authorization,
      now: () => current,
      inactivityTimeout: const Duration(minutes: 5),
      persistEvent: (event) async => events.add(event),
    );
    await session.start(observerPresent: true);
    current = current.add(const Duration(minutes: 6));

    final terminated = await session.enforceTimeouts(observerPresent: true);

    expect(terminated, isTrue);
    expect(session.state, SupervisedSessionState.terminated);
    expect(events.last.type, SupervisedEventType.sessionTerminated);
  });

  test('event persistence sanitizes every human and AI supplied field', () {
    final event = SupervisedValidationEvent(
      type: SupervisedEventType.actionCompleted,
      timestamp: DateTime.utc(2026),
      engagementReference: 'password=engagement-secret',
      observingOperator: 'token=operator-secret',
      sourceAddress: '172.16.2.5',
      destinationAddress: '172.17.2.8',
      actionId: 'secret=action-secret',
      rationale: 'password=rationale-secret',
      expectedEvidence: 'token=evidence-secret',
      detail: 'cookie=output-secret',
      evidenceReferences: const ['secret=path-secret'],
    );
    final persisted = [
      event.engagementReference,
      event.observingOperator,
      event.actionId,
      event.rationale,
      event.expectedEvidence,
      event.detail,
      ...event.evidenceReferences,
    ].join(' ');
    expect(persisted, isNot(contains('engagement-secret')));
    expect(persisted, isNot(contains('operator-secret')));
    expect(persisted, isNot(contains('action-secret')));
    expect(persisted, isNot(contains('rationale-secret')));
    expect(persisted, isNot(contains('evidence-secret')));
    expect(persisted, isNot(contains('output-secret')));
    expect(persisted, isNot(contains('path-secret')));
  });

  test(
    'close requires cleanup verification for state-changing actions',
    () async {
      final session = SupervisedValidationSession(
        authorization: authorization,
        now: () => DateTime.utc(2026, 10, 29, 19),
        persistEvent: (_) async {},
      );
      await session.start(observerPresent: true);
      await session.execute(
        action: const SupervisedValidationAction(
          actionId: 'state-change',
          exactAction: 'touch /tmp/llmtary-safe-state-change',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
          changesState: true,
          reversible: true,
          cleanupActions: ['rm -f /tmp/llmtary-safe-state-change'],
          cleanupVerification: 'marker absent',
        ),
        rationale: 'bounded marker',
        expectedEvidence: 'marker created',
        observerPresent: true,
        requestApproval: (_) async => true,
        runner: (_) async => const SupervisedActionOutput(
          exitCode: 0,
          sanitizedOutput: 'created',
          evidenceReferences: ['evidence/create.txt'],
        ),
      );

      await expectLater(session.close(), throwsStateError);
      await expectLater(
        session.verifyCleanup(actionId: 'state-change'),
        throwsStateError,
      );
      await session.execute(
        action: const SupervisedValidationAction(
          actionId: 'state-change-cleanup',
          exactAction: 'rm -f /tmp/llmtary-safe-state-change',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
        ),
        rationale: 'execute predefined cleanup',
        expectedEvidence: 'marker removed',
        observerPresent: true,
        requestApproval: (_) async => true,
        runner: (_) async => const SupervisedActionOutput(
          exitCode: 0,
          sanitizedOutput: 'removed',
          evidenceReferences: ['evidence/cleanup.txt'],
        ),
      );
      await session.verifyCleanup(actionId: 'state-change');
      await expectLater(session.close(), throwsStateError);
      await session.close(evidenceReviewed: true);
      expect(session.state, SupervisedSessionState.closed);
    },
  );
}

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/supervised_validation_policy.dart';

void main() {
  const policy = SupervisedValidationPolicy();
  const authorization = SupervisedValidationAuthorization(
    engagementReference: 'ENG-2026-001',
    observingOperator: 'authorized-operator',
    sourceAddress: '172.16.2.5',
    destinationAddress: '172.17.2.8',
    expiresAt: '2026-10-29T20:00:00Z',
    maximumHopCount: 1,
  );

  test(
    'AI-operated remote access requires live observer and exact approval',
    () {
      final decision = policy.evaluate(
        authorization: authorization,
        action: const SupervisedValidationAction(
          actionId: 'action-1',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
          opensRemoteSession: true,
          changesState: false,
        ),
        now: DateTime.utc(2026, 10, 29, 19),
        observerPresent: true,
        exactActionApproved: true,
      );

      expect(decision.allowed, isTrue);
      expect(decision.requiresPerActionApproval, isTrue);
      expect(decision.aiOperated, isTrue);
    },
  );

  test('persistent consent cannot approve supervised actions', () {
    final decision = policy.evaluate(
      authorization: authorization,
      action: const SupervisedValidationAction(
        actionId: 'action-2',
        sourceAddress: '172.16.2.5',
        destinationAddress: '172.17.2.8',
        hopCount: 1,
        opensRemoteSession: true,
        changesState: false,
      ),
      now: DateTime.utc(2026, 10, 29, 19),
      observerPresent: true,
      exactActionApproved: false,
      persistentConsentPresent: true,
    );

    expect(decision.allowed, isFalse);
    expect(decision.reason, contains('exact action'));
  });

  test(
    'scope, one-hop, expiry, destructive and secret actions fail closed',
    () {
      const unsafeActions = [
        SupervisedValidationAction(
          actionId: 'wrong-target',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.11',
          hopCount: 1,
        ),
        SupervisedValidationAction(
          actionId: 'two-hops',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 2,
        ),
        SupervisedValidationAction(
          actionId: 'destructive',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
          destructive: true,
        ),
        SupervisedValidationAction(
          actionId: 'secret-read',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
          readsSecrets: true,
        ),
      ];

      for (final action in unsafeActions) {
        expect(
          policy
              .evaluate(
                authorization: authorization,
                action: action,
                now: DateTime.utc(2026, 10, 29, 19),
                observerPresent: true,
                exactActionApproved: true,
              )
              .allowed,
          isFalse,
        );
      }

      expect(
        policy
            .evaluate(
              authorization: authorization,
              action: const SupervisedValidationAction(
                actionId: 'expired',
                sourceAddress: '172.16.2.5',
                destinationAddress: '172.17.2.8',
                hopCount: 1,
              ),
              now: DateTime.utc(2026, 10, 29, 21),
              observerPresent: true,
              exactActionApproved: true,
            )
            .allowed,
        isFalse,
      );
    },
  );

  test('authorization rejects malformed or option-like host addresses', () {
    const invalidAuthorization = SupervisedValidationAuthorization(
      engagementReference: 'ENG-1',
      observingOperator: 'operator',
      sourceAddress: '-oProxyCommand=bad',
      destinationAddress: '172.17.2.8',
      expiresAt: '2026-10-29T20:00:00Z',
      maximumHopCount: 1,
    );
    final decision = policy.evaluate(
      authorization: invalidAuthorization,
      action: const SupervisedValidationAction(
        actionId: 'action',
        sourceAddress: '-oProxyCommand=bad',
        destinationAddress: '172.17.2.8',
        hopCount: 1,
      ),
      now: DateTime.utc(2026, 10, 29, 19),
      observerPresent: true,
      exactActionApproved: true,
    );
    expect(decision.allowed, isFalse);
    expect(decision.reason, contains('address'));
  });

  test(
    'state changes require approval, reversibility and cleanup contract',
    () {
      final decision = policy.evaluate(
        authorization: authorization,
        action: const SupervisedValidationAction(
          actionId: 'reversible-change',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          hopCount: 1,
          changesState: true,
          reversible: true,
          cleanupActions: ['remove temporary marker'],
          cleanupVerification: 'verify marker is absent',
        ),
        now: DateTime.utc(2026, 10, 29, 19),
        observerPresent: true,
        exactActionApproved: true,
      );

      expect(decision.allowed, isTrue);
      expect(decision.cleanupRequired, isTrue);
    },
  );
}

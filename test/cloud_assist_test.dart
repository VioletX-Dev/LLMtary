import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/cloud_assist.dart';
import 'package:llmtary/models/llm_provider.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/cloud_assist_service.dart';
import 'package:llmtary/services/test_budget.dart';

Project _project({bool enabled = false, double limit = 5, double spent = 0}) =>
    Project(
      id: 11,
      name: 'local-first',
      folderPath: '/tmp/local-first',
      createdAt: DateTime.utc(2026, 1, 1),
      lastOpenedAt: DateTime.utc(2026, 1, 1),
      budgetMode: TestBudgetMode.localRuntime,
      budgetLimit: 60,
      cloudAssistEnabled: enabled,
      cloudAssistProvider: LLMProvider.chatGPT.name,
      cloudAssistFindingReview: true,
      cloudAssistReportReview: true,
      cloudAssistBudgetUsd: limit,
      cloudAssistSpentUsd: spent,
    );

void main() {
  test(
    'cloud assist is disabled by default and legacy projects stay local-only',
    () {
      final restored = Project.fromMap({
        'id': 1,
        'name': 'legacy',
        'folderPath': '/tmp/legacy',
        'createdAt': DateTime.utc(2026, 1, 1).toIso8601String(),
        'lastOpenedAt': DateTime.utc(2026, 1, 1).toIso8601String(),
      });

      expect(restored.cloudAssistEnabled, isFalse);
      expect(restored.cloudAssistFindingReview, isFalse);
      expect(restored.cloudAssistReportReview, isFalse);
      expect(restored.cloudAssistBudgetUsd, 0);
      expect(restored.cloudAssistSpentUsd, 0);
    },
  );

  test(
    'cloud assist configuration and spend survive project map round-trip',
    () {
      final restored = Project.fromMap(
        _project(enabled: true, spent: 1.25).toMap(),
      );

      expect(restored.cloudAssistEnabled, isTrue);
      expect(restored.cloudAssistProvider, LLMProvider.chatGPT.name);
      expect(restored.cloudAssistFindingReview, isTrue);
      expect(restored.cloudAssistReportReview, isTrue);
      expect(restored.cloudAssistBudgetUsd, 5);
      expect(restored.cloudAssistSpentUsd, 1.25);
      expect(restored.hasCloudAssistBudget, isTrue);
    },
  );

  test('cloud review audit records round-trip with provider provenance', () {
    final at = DateTime.utc(2026, 1, 2, 3, 4);
    final review = CloudAssistReview(
      id: 9,
      projectId: 11,
      targetId: 4,
      phase: CloudAssistPhase.findingConfirmation,
      status: CloudAssistStatus.cloudAssisted,
      provider: LLMProvider.claude.name,
      modelName: 'claude-sonnet',
      note: 'One evidence gap requires operator review.',
      createdAt: at,
    );

    final restored = CloudAssistReview.fromMap(review.toMap());

    expect(restored.id, 9);
    expect(restored.projectId, 11);
    expect(restored.targetId, 4);
    expect(restored.phase, CloudAssistPhase.findingConfirmation);
    expect(restored.status, CloudAssistStatus.cloudAssisted);
    expect(restored.provider, LLMProvider.claude.name);
    expect(restored.modelName, 'claude-sonnet');
    expect(restored.note, contains('evidence gap'));
    expect(restored.createdAt, at);
  });

  test(
    'finding review prompt explicitly checks local negative conclusions',
    () {
      final prompt = CloudAssistService.buildFindingReviewPrompt(
        targetAddress: '192.0.2.10',
        deviceEvidence: '{"ports":[80]}',
        localFindings: 'No findings reported by the local model.',
      );

      expect(prompt, contains('false negatives'));
      expect(prompt, contains('Do not silently approve a negative conclusion'));
      expect(prompt, contains('Do not execute commands'));
      expect(prompt, contains('192.0.2.10'));
    },
  );

  test('cloud payload redaction removes appliance-bound credential values', () {
    final redacted = CloudAssistService.redactSecrets(
      'password=hunter2 token=abc.def.ghi',
      const ['hunter2', 'abc.def.ghi'],
    );

    expect(redacted, isNot(contains('hunter2')));
    expect(redacted, isNot(contains('abc.def.ghi')));
    expect(redacted, contains('[REDACTED]'));
  });

  test(
    'cloud payload redaction masks common secret fields without known values',
    () {
      final redacted = CloudAssistService.redactSecrets(
        '{"password":"not-listed","authorization":"Bearer xyz"}',
        const [],
      );

      expect(redacted, isNot(contains('not-listed')));
      expect(redacted, isNot(contains('Bearer xyz')));
    },
  );

  test('prompt redaction masks labeled secrets and private keys', () {
    final redacted = CloudAssistService.redactSecrets(
      'password: unknown-secret\nAuthorization: Bearer abc123\n'
      '-----BEGIN PRIVATE KEY-----\nkey-material\n-----END PRIVATE KEY-----',
      const [],
    );

    expect(redacted, isNot(contains('unknown-secret')));
    expect(redacted, isNot(contains('abc123')));
    expect(redacted, isNot(contains('key-material')));
    expect(redacted, contains('[REDACTED]'));
  });

  test(
    'disabled cloud assist completes locally without invoking cloud',
    () async {
      var calls = 0;
      final result = await CloudAssistService.runOptional(
        project: _project(),
        phase: CloudAssistPhase.findingConfirmation,
        callCloud: () async {
          calls++;
          return 'should not run';
        },
      );

      expect(calls, 0);
      expect(result.status, CloudAssistStatus.localOnly);
      expect(result.completedLocally, isTrue);
    },
  );

  test(
    'budget exhaustion skips cloud and preserves local completion',
    () async {
      final result = await CloudAssistService.runOptional(
        project: _project(enabled: true, spent: 5),
        phase: CloudAssistPhase.findingConfirmation,
        callCloud: () async =>
            throw const BudgetExceededException('cap reached'),
      );

      expect(result.status, CloudAssistStatus.skippedBudget);
      expect(result.completedLocally, isTrue);
      expect(result.note, contains('cap reached'));
    },
  );

  test('cloud outage never blocks local completion', () async {
    final result = await CloudAssistService.runOptional(
      project: _project(enabled: true),
      phase: CloudAssistPhase.reportReview,
      callCloud: () async => throw Exception('provider unavailable'),
    );

    expect(result.status, CloudAssistStatus.skippedUnavailable);
    expect(result.completedLocally, isTrue);
  });

  test('successful cloud review is marked cloud assisted', () async {
    final result = await CloudAssistService.runOptional(
      project: _project(enabled: true),
      phase: CloudAssistPhase.reportReview,
      callCloud: () async => 'No material inconsistencies found.',
    );

    expect(result.status, CloudAssistStatus.cloudAssisted);
    expect(result.note, 'No material inconsistencies found.');
    expect(result.completedLocally, isTrue);
  });
}

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/llm_provider.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/test_budget.dart';

void main() {
  group('TestBudgetPolicy', () {
    test('classifies hosted providers as API and local runtimes as local', () {
      expect(
        TestBudgetPolicy.defaultModeFor(LLMProvider.chatGPT),
        TestBudgetMode.apiCost,
      );
      expect(
        TestBudgetPolicy.defaultModeFor(LLMProvider.claude),
        TestBudgetMode.apiCost,
      );
      expect(
        TestBudgetPolicy.defaultModeFor(LLMProvider.gemini),
        TestBudgetMode.apiCost,
      );
      expect(
        TestBudgetPolicy.defaultModeFor(LLMProvider.openRouter),
        TestBudgetMode.apiCost,
      );
      expect(
        TestBudgetPolicy.defaultModeFor(LLMProvider.ollama),
        TestBudgetMode.localRuntime,
      );
      expect(
        TestBudgetPolicy.defaultModeFor(LLMProvider.lmStudio),
        TestBudgetMode.localRuntime,
      );
    });

    test('prices known models and uses conservative API fallback', () {
      final known = TestBudgetPolicy.pricingFor(LLMProvider.chatGPT, 'gpt-5');
      final fallback = TestBudgetPolicy.pricingFor(
        LLMProvider.custom,
        'unknown',
      );

      expect(known.inputPerMillionUsd, greaterThan(0));
      expect(known.outputPerMillionUsd, greaterThan(known.inputPerMillionUsd));
      expect(
        fallback.inputPerMillionUsd,
        greaterThanOrEqualTo(known.inputPerMillionUsd),
      );
      expect(
        fallback.outputPerMillionUsd,
        greaterThanOrEqualTo(known.outputPerMillionUsd),
      );
      expect(fallback.isFallback, isTrue);
    });

    test('computes actual API cost from provider token usage', () {
      const pricing = ModelPricing(
        inputPerMillionUsd: 2,
        outputPerMillionUsd: 10,
      );
      expect(
        pricing.costFor(inputTokens: 500000, outputTokens: 100000),
        closeTo(2.0, 0.000001),
      );
    });

    test('caps output tokens to the remaining dollar budget', () {
      const pricing = ModelPricing(
        inputPerMillionUsd: 2,
        outputPerMillionUsd: 10,
      );
      final tokens = TestBudgetPolicy.maxAffordableOutputTokens(
        limitUsd: 1,
        spentUsd: 0.2,
        estimatedInputTokens: 100000,
        configuredMaxOutputTokens: 100000,
        pricing: pricing,
      );
      expect(tokens, 60000);
    });

    test('rejects a request when estimated input consumes the remainder', () {
      const pricing = ModelPricing(
        inputPerMillionUsd: 2,
        outputPerMillionUsd: 10,
      );
      expect(
        () => TestBudgetPolicy.maxAffordableOutputTokens(
          limitUsd: 0.2,
          spentUsd: 0.1,
          estimatedInputTokens: 100000,
          configuredMaxOutputTokens: 1000,
          pricing: pricing,
        ),
        throwsA(isA<BudgetExceededException>()),
      );
    });

    test('returns only the remaining local runtime', () {
      final started = DateTime.utc(2026, 1, 1, 12);
      final now = started.add(const Duration(minutes: 7));
      expect(
        TestBudgetPolicy.remainingRuntime(
          limit: const Duration(minutes: 10),
          startedAt: started,
          now: now,
        ),
        const Duration(minutes: 3),
      );
    });

    test('rejects local work when runtime is exhausted', () {
      final started = DateTime.utc(2026, 1, 1, 12);
      expect(
        () => TestBudgetPolicy.remainingRuntime(
          limit: const Duration(minutes: 10),
          startedAt: started,
          now: started.add(const Duration(minutes: 10)),
        ),
        throwsA(isA<BudgetExceededException>()),
      );
    });
  });

  group('ProjectBudgetSession', () {
    Project project({
      TestBudgetMode? mode,
      double? limit,
      double spent = 0,
      DateTime? startedAt,
    }) => Project(
      id: 4,
      name: 'test',
      folderPath: '/tmp/test',
      createdAt: DateTime.utc(2026),
      lastOpenedAt: DateTime.utc(2026),
      budgetMode: mode,
      budgetLimit: limit,
      budgetSpentUsd: spent,
      budgetStartedAt: startedAt,
    );

    test('blocks legacy project until a budget is configured', () async {
      final session = ProjectBudgetSession(project: project());
      expect(
        () => session.beforeRequest(
          provider: LLMProvider.chatGPT,
          modelName: 'gpt-5',
          estimatedInputTokens: 10,
          configuredMaxOutputTokens: 100,
          configuredTimeout: const Duration(seconds: 30),
          now: DateTime.utc(2026),
        ),
        throwsA(isA<BudgetExceededException>()),
      );
    });

    test('records API usage once and persists estimated spend', () async {
      double persisted = 0;
      final session = ProjectBudgetSession(
        project: project(mode: TestBudgetMode.apiCost, limit: 10),
        onSpend: (amount) async => persisted += amount,
      );

      final allowance = await session.beforeRequest(
        provider: LLMProvider.chatGPT,
        modelName: 'gpt-5',
        estimatedInputTokens: 100,
        configuredMaxOutputTokens: 1000,
        configuredTimeout: const Duration(seconds: 30),
        now: DateTime.utc(2026),
      );
      await session.recordUsage(inputTokens: 1000, outputTokens: 500);

      expect(allowance.maxOutputTokens, 1000);
      expect(persisted, greaterThan(0));
      expect(session.spentUsd, persisted);
    });

    test('concurrent API requests reserve budget before either completes', () async {
      final session = ProjectBudgetSession(
        project: project(mode: TestBudgetMode.apiCost, limit: 0.02),
      );

      final first = await session.beforeRequest(
        provider: LLMProvider.chatGPT,
        modelName: 'gpt-5',
        estimatedInputTokens: 100,
        configuredMaxOutputTokens: 1000,
        configuredTimeout: const Duration(seconds: 30),
        now: DateTime.utc(2026),
      );
      final second = await session.beforeRequest(
        provider: LLMProvider.chatGPT,
        modelName: 'gpt-5',
        estimatedInputTokens: 100,
        configuredMaxOutputTokens: 1000,
        configuredTimeout: const Duration(seconds: 30),
        now: DateTime.utc(2026),
      );

      expect(second.maxOutputTokens, lessThan(first.maxOutputTokens));
      session.cancel(first);
      session.cancel(second);
    });

    test('starts local runtime once and clamps timeout to remainder', () async {
      DateTime? persistedStart;
      final now = DateTime.utc(2026, 1, 1, 12);
      final session = ProjectBudgetSession(
        project: project(mode: TestBudgetMode.localRuntime, limit: 10),
        onStart: (value) async => persistedStart = value,
      );

      final first = await session.beforeRequest(
        provider: LLMProvider.ollama,
        modelName: 'local',
        estimatedInputTokens: 100,
        configuredMaxOutputTokens: 1000,
        configuredTimeout: const Duration(minutes: 30),
        now: now,
      );
      final second = await session.beforeRequest(
        provider: LLMProvider.ollama,
        modelName: 'local',
        estimatedInputTokens: 100,
        configuredMaxOutputTokens: 1000,
        configuredTimeout: const Duration(minutes: 30),
        now: now.add(const Duration(minutes: 7)),
      );

      expect(persistedStart, now);
      expect(first.timeout, const Duration(minutes: 10));
      expect(second.timeout, const Duration(minutes: 3));
      expect(
        session.operationTimeout(
          const Duration(minutes: 30),
          now.add(const Duration(minutes: 7)),
        ),
        const Duration(minutes: 3),
      );
    });
  });
}

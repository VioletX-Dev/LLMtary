import '../models/llm_provider.dart';
import '../models/project.dart';
import '../models/test_budget_mode.dart';

export '../models/test_budget_mode.dart';

class BudgetExceededException implements Exception {
  final String message;
  const BudgetExceededException(this.message);

  @override
  String toString() => message;
}

class ModelPricing {
  final double inputPerMillionUsd;
  final double outputPerMillionUsd;
  final bool isFallback;

  const ModelPricing({
    required this.inputPerMillionUsd,
    required this.outputPerMillionUsd,
    this.isFallback = false,
  });

  double costFor({required int inputTokens, required int outputTokens}) {
    return (inputTokens * inputPerMillionUsd +
            outputTokens * outputPerMillionUsd) /
        1000000;
  }
}

class TestBudgetPolicy {
  const TestBudgetPolicy._();

  static TestBudgetMode defaultModeFor(LLMProvider provider) {
    return provider == LLMProvider.ollama || provider == LLMProvider.lmStudio
        ? TestBudgetMode.localRuntime
        : TestBudgetMode.apiCost;
  }

  /// Estimated public standard rates in USD per million tokens.
  /// Unknown and custom models intentionally use a conservative fallback.
  static ModelPricing pricingFor(LLMProvider provider, String modelName) {
    final model = modelName.toLowerCase();
    if (provider == LLMProvider.chatGPT) {
      if (model.contains('gpt-6')) {
        return const ModelPricing(
          inputPerMillionUsd: 10,
          outputPerMillionUsd: 50,
        );
      }
      if (model.contains('gpt-5')) {
        return const ModelPricing(
          inputPerMillionUsd: 1.25,
          outputPerMillionUsd: 10,
        );
      }
      if (model.contains('gpt-4o-mini')) {
        return const ModelPricing(
          inputPerMillionUsd: 0.15,
          outputPerMillionUsd: 0.6,
        );
      }
      if (model.contains('gpt-4o')) {
        return const ModelPricing(
          inputPerMillionUsd: 2.5,
          outputPerMillionUsd: 10,
        );
      }
    }
    if (provider == LLMProvider.claude) {
      if (model.contains('opus')) {
        return const ModelPricing(
          inputPerMillionUsd: 15,
          outputPerMillionUsd: 75,
        );
      }
      if (model.contains('haiku')) {
        return const ModelPricing(
          inputPerMillionUsd: 1,
          outputPerMillionUsd: 5,
        );
      }
      if (model.contains('sonnet')) {
        return const ModelPricing(
          inputPerMillionUsd: 3,
          outputPerMillionUsd: 15,
        );
      }
    }
    if (provider == LLMProvider.gemini) {
      if (model.contains('flash-lite')) {
        return const ModelPricing(
          inputPerMillionUsd: 0.1,
          outputPerMillionUsd: 0.4,
        );
      }
      if (model.contains('flash')) {
        return const ModelPricing(
          inputPerMillionUsd: 0.5,
          outputPerMillionUsd: 3,
        );
      }
      if (model.contains('pro')) {
        return const ModelPricing(
          inputPerMillionUsd: 2,
          outputPerMillionUsd: 12,
        );
      }
    }
    return const ModelPricing(
      inputPerMillionUsd: 15,
      outputPerMillionUsd: 75,
      isFallback: true,
    );
  }

  static int maxAffordableOutputTokens({
    required double limitUsd,
    required double spentUsd,
    required int estimatedInputTokens,
    required int configuredMaxOutputTokens,
    required ModelPricing pricing,
  }) {
    final remaining = limitUsd - spentUsd;
    final inputCost = pricing.costFor(
      inputTokens: estimatedInputTokens,
      outputTokens: 0,
    );
    final outputBudget = remaining - inputCost;
    if (outputBudget <= 0) {
      throw const BudgetExceededException(
        'API budget exhausted. Increase the dollar cap to resume this test.',
      );
    }
    final affordable = (outputBudget * 1000000 / pricing.outputPerMillionUsd)
        .floor();
    if (affordable < 1) {
      throw const BudgetExceededException(
        'API budget exhausted. Increase the dollar cap to resume this test.',
      );
    }
    return affordable < configuredMaxOutputTokens
        ? affordable
        : configuredMaxOutputTokens;
  }

  static Duration remainingRuntime({
    required Duration limit,
    required DateTime startedAt,
    required DateTime now,
  }) {
    final remaining = limit - now.difference(startedAt);
    if (remaining <= Duration.zero) {
      throw const BudgetExceededException(
        'Local-model runtime limit reached. Increase the limit to resume this test.',
      );
    }
    return remaining;
  }
}

class BudgetAllowance {
  final int maxOutputTokens;
  final Duration timeout;
  final double reservedUsd;

  const BudgetAllowance({
    required this.maxOutputTokens,
    required this.timeout,
    this.reservedUsd = 0,
  });
}

typedef BudgetSpendWriter = Future<void> Function(double amountUsd);
typedef BudgetStartWriter = Future<void> Function(DateTime startedAt);

class ProjectBudgetSession {
  final Project project;
  final BudgetSpendWriter? onSpend;
  final BudgetStartWriter? onStart;
  double _spentUsd;
  double _reservedUsd = 0;
  DateTime? _startedAt;
  ModelPricing? _activePricing;

  ProjectBudgetSession({required this.project, this.onSpend, this.onStart})
    : _spentUsd = project.budgetSpentUsd,
      _startedAt = project.budgetStartedAt;

  double get spentUsd => _spentUsd;
  DateTime? get startedAt => _startedAt;

  Future<BudgetAllowance> beforeRequest({
    required LLMProvider provider,
    required String modelName,
    required int estimatedInputTokens,
    required int configuredMaxOutputTokens,
    required Duration configuredTimeout,
    required DateTime now,
  }) async {
    if (!project.hasBudget) {
      throw const BudgetExceededException(
        'Set a budget for this test before using the model.',
      );
    }
    final mode = project.budgetMode!;
    final providerMode = TestBudgetPolicy.defaultModeFor(provider);
    if (provider != LLMProvider.custom && mode != providerMode) {
      throw BudgetExceededException(
        'The test budget type does not match ${provider.displayName}. Update the budget to continue.',
      );
    }

    if (mode == TestBudgetMode.apiCost) {
      final pricing = TestBudgetPolicy.pricingFor(provider, modelName);
      _activePricing = pricing;
      final maxOutputTokens = TestBudgetPolicy.maxAffordableOutputTokens(
        limitUsd: project.budgetLimit!,
        spentUsd: _spentUsd + _reservedUsd,
        estimatedInputTokens: estimatedInputTokens,
        configuredMaxOutputTokens: configuredMaxOutputTokens,
        pricing: pricing,
      );
      final reservation = pricing.costFor(
        inputTokens: estimatedInputTokens,
        outputTokens: maxOutputTokens,
      );
      _reservedUsd += reservation;
      return BudgetAllowance(
        maxOutputTokens: maxOutputTokens,
        timeout: configuredTimeout,
        reservedUsd: reservation,
      );
    }

    if (_startedAt == null) {
      _startedAt = now;
      await onStart?.call(now);
    }
    final remaining = TestBudgetPolicy.remainingRuntime(
      limit: Duration(milliseconds: (project.budgetLimit! * 60000).round()),
      startedAt: _startedAt!,
      now: now,
    );
    return BudgetAllowance(
      maxOutputTokens: configuredMaxOutputTokens,
      timeout: remaining < configuredTimeout ? remaining : configuredTimeout,
    );
  }

  Duration operationTimeout(Duration configured, DateTime now) {
    if (project.budgetMode != TestBudgetMode.localRuntime || _startedAt == null) {
      return configured;
    }
    final remaining = TestBudgetPolicy.remainingRuntime(
      limit: Duration(milliseconds: (project.budgetLimit! * 60000).round()),
      startedAt: _startedAt!,
      now: now,
    );
    return remaining < configured ? remaining : configured;
  }

  Future<void> recordUsage({
    required int inputTokens,
    required int outputTokens,
    BudgetAllowance? allowance,
  }) async {
    final pricing = _activePricing;
    if (project.budgetMode != TestBudgetMode.apiCost || pricing == null) return;
    _reservedUsd = (_reservedUsd - (allowance?.reservedUsd ?? 0)).clamp(
      0,
      double.infinity,
    );
    final amount = pricing.costFor(
      inputTokens: inputTokens,
      outputTokens: outputTokens,
    );
    _spentUsd += amount;
    await onSpend?.call(amount);
  }

  void cancel(BudgetAllowance allowance) {
    _reservedUsd = (_reservedUsd - allowance.reservedUsd).clamp(
      0,
      double.infinity,
    );
  }
}

class TestBudgetRuntime {
  static ProjectBudgetSession? activeSession;

  static void configure(ProjectBudgetSession session) {
    activeSession = session;
  }

  static void clear() {
    activeSession = null;
  }
}

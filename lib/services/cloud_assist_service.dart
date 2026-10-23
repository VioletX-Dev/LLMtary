import '../models/cloud_assist.dart';
import '../models/llm_provider.dart';
import '../models/llm_settings.dart';
import '../models/project.dart';
import '../database/database_helper.dart';
import 'llm_service.dart';
import 'test_budget.dart';

class CloudAssistService {
  const CloudAssistService._();

  static String redactSecrets(String input, Iterable<String> secrets) {
    var redacted = input;
    for (final secret in secrets) {
      if (secret.isNotEmpty) redacted = redacted.replaceAll(secret, '[REDACTED]');
    }
    final jsonSecret = RegExp(
      r'("(?:password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie|set-cookie)"\s*:\s*")[^"]*(")',
      caseSensitive: false,
    );
    redacted = redacted.replaceAllMapped(
      jsonSecret,
      (match) => '${match.group(1)}[REDACTED]${match.group(2)}',
    );
    final assignmentSecret = RegExp(
      r'\b(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|cookie)\s*=\s*[^\s,;]+',
      caseSensitive: false,
    );
    redacted = redacted.replaceAllMapped(
      assignmentSecret,
      (match) => '${match.group(1)}=[REDACTED]',
    );
    return redacted;
  }

  static Future<CloudAssistResult> runOptional({
    required Project project,
    required CloudAssistPhase phase,
    required Future<String> Function() callCloud,
  }) async {
    final phaseEnabled = switch (phase) {
      CloudAssistPhase.findingConfirmation => project.cloudAssistFindingReview,
      CloudAssistPhase.reportReview => project.cloudAssistReportReview,
    };
    if (!project.cloudAssistEnabled || !phaseEnabled) {
      return CloudAssistResult(
        phase: phase,
        status: CloudAssistStatus.localOnly,
        note: 'Completed using the local model.',
      );
    }

    try {
      final note = await callCloud();
      return CloudAssistResult(
        phase: phase,
        status: CloudAssistStatus.cloudAssisted,
        note: note.trim(),
      );
    } on BudgetExceededException catch (error) {
      return CloudAssistResult(
        phase: phase,
        status: CloudAssistStatus.skippedBudget,
        note: error.toString(),
      );
    } catch (error) {
      return CloudAssistResult(
        phase: phase,
        status: CloudAssistStatus.skippedUnavailable,
        note: 'Cloud review unavailable: $error',
      );
    }
  }

  static Future<CloudAssistResult> review({
    required Project project,
    required CloudAssistPhase phase,
    required String prompt,
    int? targetId,
    Future<void> Function(double amountUsd)? onSpend,
    void Function(int sent, int received)? onTokensUsed,
  }) async {
    var providerName = project.cloudAssistProvider ?? '';
    var modelName = '';
    final result = await runOptional(
      project: project,
      phase: phase,
      callCloud: () async {
        final provider = LLMProvider.values.firstWhere(
          (value) => value.name == providerName,
          orElse: () => LLMProvider.none,
        );
        if (!LLMSemaphore.isCloudProvider(provider)) {
          throw const FormatException('Select a configured cloud provider.');
        }
        final saved = await DatabaseHelper.getProviderSettings(provider.name);
        if (saved == null) {
          throw StateError('${provider.displayName} is not configured.');
        }
        final settings = LLMSettings(
          provider: provider,
          baseUrl: saved['baseUrl'] as String?,
          apiKey: saved['apiKey'] as String?,
          modelName: saved['modelName'] as String? ?? '',
          temperature: 0.1,
          maxTokens: 2048,
          timeoutSeconds: saved['timeoutSeconds'] as int? ?? 180,
        );
        modelName = settings.modelName;
        if (settings.modelName.trim().isEmpty ||
            (provider.requiresApiKey &&
                (settings.apiKey == null || settings.apiKey!.isEmpty))) {
          throw StateError(
            '${provider.displayName} configuration is incomplete.',
          );
        }
        final budgetProject = project.copyWith(
          budgetMode: TestBudgetMode.apiCost,
          budgetLimit: project.cloudAssistBudgetUsd,
          budgetSpentUsd: project.cloudAssistSpentUsd,
        );
        final budget = ProjectBudgetSession(
          project: budgetProject,
          onSpend: (amount) async {
            await onSpend?.call(amount);
          },
        );
        return LLMService(budgetSession: budget).sendMessage(
          settings,
          prompt,
          useSystemPrompt: false,
          onTokensUsed: onTokensUsed,
        );
      },
    );
    if (project.id != null && project.cloudAssistEnabled) {
      await DatabaseHelper.insertCloudAssistReview(
        CloudAssistReview(
          projectId: project.id!,
          targetId: targetId,
          phase: phase,
          status: result.status,
          provider: providerName,
          modelName: modelName,
          note: result.note,
          createdAt: DateTime.now(),
        ),
      );
    }
    return result;
  }

  static String buildFindingReviewPrompt({
    required String targetAddress,
    required String deviceEvidence,
    required String localFindings,
  }) =>
      '''You are performing an optional second-pass quality review of a locally completed penetration-test analysis.

TARGET: $targetAddress

LOCAL FINDINGS:
$localFindings

RECONNAISSANCE EVIDENCE:
$deviceEvidence

Review both positive findings and the possibility of false negatives. Identify unsupported conclusions, material vulnerabilities potentially omitted by the local analysis, and evidence gaps. Do not execute commands, propose destructive or denial-of-service testing, or expand scope. Do not silently approve a negative conclusion. Return a concise operator review memo; this review does not automatically add, remove, confirm, or suppress findings.''';

  static String buildReportReviewPrompt(String report) =>
      '''Review this locally generated penetration-test report for internal contradictions, unsupported claims, omitted confirmed findings, severity inconsistencies, and statements that imply cloud validation when none occurred. Do not invent findings or evidence. Return a concise operator review memo; do not rewrite the report.\n\nREPORT:\n$report''';
}

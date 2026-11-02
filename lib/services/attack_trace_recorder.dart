import 'dart:convert';

import '../models/attack_trace.dart';
import '../models/browser_test.dart';
import '../models/independent_validation.dart';
import 'attack_trace_repository.dart';
import 'sensitive_text_redactor.dart';

class AttackTraceRecorder {
  final AttackTraceRepository repository;

  const AttackTraceRecorder(this.repository);

  Future<int> recordBrowserAction({
    required int traceId,
    required String stepKey,
    List<String> parentStepKeys = const [],
    required BrowserActionRecord record,
    required DateTime createdAt,
  }) => repository.append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.browserAction,
      action: SensitiveTextRedactor.redact(record.action, maxLength: 2000),
      output: SensitiveTextRedactor.redact(
        jsonEncode({
          'url': record.finalUrl,
          'statusCode': record.statusCode,
          'domSha256': record.domSha256,
          'networkExchangeCount': record.networkExchanges.length,
        }),
        maxLength: 8000,
      ),
      evidenceArtifactIds: record.evidenceArtifactIds,
      metadata: {
        'roleId': record.roleId,
        'browserActionKind': record.kind.name,
      },
      createdAt: createdAt,
    ),
  );

  Future<int> recordCommand({
    required int traceId,
    required String stepKey,
    List<String> parentStepKeys = const [],
    required String command,
    required String output,
    List<int> evidenceArtifactIds = const [],
    required DateTime createdAt,
  }) => repository.append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.command,
      action: SensitiveTextRedactor.redact(command, maxLength: 2000),
      output: SensitiveTextRedactor.redact(output, maxLength: 8000),
      evidenceArtifactIds: evidenceArtifactIds,
      createdAt: createdAt,
    ),
  );

  Future<int> recordValidation({
    required int traceId,
    required String stepKey,
    List<String> parentStepKeys = const [],
    required int validationRunId,
    required IndependentValidationRecord record,
  }) => repository.append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.validatorResult,
      interpretation: SensitiveTextRedactor.redact(
        record.reason,
        maxLength: 4000,
      ),
      evidenceArtifactIds: record.directEvidenceArtifactIds,
      validationRunId: validationRunId,
      validatorResult: switch (record.outcome) {
        IndependentValidationOutcome.confirmed =>
          AttackTraceValidatorResult.confirmed,
        IndependentValidationOutcome.rejected =>
          AttackTraceValidatorResult.rejected,
        IndependentValidationOutcome.inconclusive =>
          AttackTraceValidatorResult.inconclusive,
      },
      metadata: {
        'proposerContextId': record.proposerContextId,
        'validatorContextId': record.validatorContextId,
        'reproducibilityScore': record.reproducibilityScore.toString(),
      },
      createdAt: record.createdAt,
    ),
  );

  Future<int> recordCleanup({
    required int traceId,
    required String stepKey,
    List<String> parentStepKeys = const [],
    required String action,
    required bool verified,
    required DateTime createdAt,
  }) => repository.append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.cleanup,
      action: SensitiveTextRedactor.redact(action, maxLength: 2000),
      cleanupStatus: verified ? 'verified' : 'notVerified',
      createdAt: createdAt,
    ),
  );
}

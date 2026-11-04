import 'dart:async';
import 'dart:convert';
import 'dart:math';

import '../models/candidate_closure.dart';
import '../models/independent_validation.dart';
import 'attack_trace_recorder.dart';
import 'candidate_closure_repository.dart';
import 'independent_validation_policy.dart';
import 'independent_validation_repository.dart';
import 'sensitive_text_redactor.dart';

abstract interface class LLMCaller {
  Future<String> sendMessage(String message, {bool useSystemPrompt = true});
}

abstract interface class AdvisoryValidationReviewer {
  Future<void> review(IndependentValidationRecord record);
}

class IndependentValidationOrchestrator {
  final LLMCaller proposerCaller;
  final LLMCaller validatorCaller;
  final IndependentValidationRepository repository;
  final IndependentValidationPolicy policy;
  final AttackTraceRecorder traceRecorder;
  final CandidateClosureRepository closureRepository;
  final AdvisoryValidationReviewer? advisoryReviewer;
  final Duration requestTimeout;
  final int maxResponseCharacters;
  final DateTime Function() now;
  final String lockOwnerId;
  final Duration lockTtl;

  IndependentValidationOrchestrator({
    required this.proposerCaller,
    required this.validatorCaller,
    required this.repository,
    required this.policy,
    required this.traceRecorder,
    required this.closureRepository,
    this.advisoryReviewer,
    this.requestTimeout = const Duration(minutes: 5),
    this.maxResponseCharacters = 128 * 1024,
    DateTime Function()? now,
    String? lockOwnerId,
    this.lockTtl = const Duration(minutes: 10),
  }) : now = now ?? (() => DateTime.now().toUtc()),
       lockOwnerId = lockOwnerId ?? _randomOwnerId();

  Future<IndependentValidationRecord> run({
    required int validationRunId,
    required int projectId,
    int? vulnerabilityId,
    required VulnerabilityClass vulnerabilityClass,
    required String proposerContextId,
    required String validatorContextId,
    required String proposerPrompt,
    required String validatorPromptTemplate,
    required int traceId,
  }) async {
    if (validationRunId <= 0 || projectId <= 0 || traceId <= 0) {
      throw ArgumentError(
        'Persisted validation, project, and trace ids are required.',
      );
    }
    if (proposerContextId.trim().isEmpty ||
        validatorContextId.trim().isEmpty ||
        proposerContextId == validatorContextId) {
      throw ArgumentError('Proposer and validator contexts must be separate.');
    }
    final existing = await repository.tryForValidationRun(validationRunId);
    if (existing != null) return existing;
    final acquired = await repository.acquireLock(
      validationRunId: validationRunId,
      ownerId: lockOwnerId,
      acquiredAt: now().toUtc(),
      ttl: lockTtl,
    );
    if (!acquired) {
      final completed = await repository.tryForValidationRun(validationRunId);
      if (completed != null) return completed;
      throw StateError('Independent validation is already in progress.');
    }

    try {
      IndependentValidationDecision proposerDecision =
          IndependentValidationDecision.inconclusive;
      IndependentValidationDecision validatorDecision =
          IndependentValidationDecision.inconclusive;
      final evidenceIds = <int>{};
      final completedControls = <ValidationControl>{};
      final attempts = <bool>[];
      String? sanitizedFailureType;

      try {
        final proposerResponse = await proposerCaller
            .sendMessage(_boundedPrompt(proposerPrompt))
            .timeout(requestTimeout);
        final boundedProposer = _boundedResponse(proposerResponse);
        proposerDecision = _parseDecision(boundedProposer);
        evidenceIds.addAll(_parseEvidenceIds(boundedProposer));
        completedControls.addAll(_parseControls(boundedProposer));

        final requiredControls = _requiredControls(vulnerabilityClass);
        final claimEnvelope = jsonEncode({
          'decision': proposerDecision.name,
          'directEvidenceArtifactIds': evidenceIds.toList()..sort(),
          'requiredControls':
              requiredControls.map((value) => value.name).toList()..sort(),
        });
        for (var attempt = 1; attempt <= 2; attempt++) {
          final validatorPrompt = validatorPromptTemplate
              .replaceAll('{{claim}}', claimEnvelope)
              .replaceAll('{{attempt}}', '$attempt');
          final response = await validatorCaller
              .sendMessage(_boundedPrompt(validatorPrompt))
              .timeout(requestTimeout);
          final bounded = _boundedResponse(response);
          attempts.add(_parseAttemptSuccess(bounded));
          evidenceIds.addAll(_parseEvidenceIds(bounded));
          completedControls.addAll(_parseControls(bounded));
          final decision = _parseDecision(bounded);
          if (decision != IndependentValidationDecision.inconclusive) {
            validatorDecision = decision;
          }
        }
      } catch (error) {
        sanitizedFailureType = error.runtimeType.toString();
      }

      final validatedEvidenceIds = await repository.validEvidenceIds(
        projectId: projectId,
        vulnerabilityId: vulnerabilityId,
        evidenceIds: evidenceIds,
      );
      final policyResult = policy.evaluate(
        IndependentValidationInput(
          vulnerabilityClass: vulnerabilityClass,
          proposerContextId: proposerContextId,
          validatorContextId: validatorContextId,
          proposerDecision: proposerDecision,
          validatorDecision: validatorDecision,
          reproductionAttempts: attempts,
          directEvidenceArtifactIds: validatedEvidenceIds,
          completedControls: completedControls,
        ),
      );
      final createdAt = now().toUtc();
      final finalRecord = IndependentValidationRecord(
        validationRunId: validationRunId,
        projectId: projectId,
        vulnerabilityId: vulnerabilityId,
        vulnerabilityClass: vulnerabilityClass,
        proposerContextId: _boundedIdentifier(proposerContextId),
        validatorContextId: _boundedIdentifier(validatorContextId),
        proposerDecision: proposerDecision,
        validatorDecision: validatorDecision,
        outcome: sanitizedFailureType == null
            ? policyResult.outcome
            : IndependentValidationOutcome.inconclusive,
        reproductionAttempts: List.unmodifiable(attempts),
        reproducibilityScore: policyResult.reproducibilityScore,
        directEvidenceArtifactIds: List.unmodifiable(validatedEvidenceIds),
        completedControls: Set.unmodifiable(completedControls),
        missingControls: policyResult.missingControls,
        reason: sanitizedFailureType == null
            ? policyResult.reason
            : 'Validation request failed: $sanitizedFailureType',
        createdAt: createdAt,
      );

      await repository.persist(finalRecord);
      await traceRecorder.recordValidation(
        traceId: traceId,
        stepKey: 'independent-validation-$validationRunId',
        validationRunId: validationRunId,
        record: finalRecord,
      );

      if (finalRecord.outcome == IndependentValidationOutcome.confirmed &&
          vulnerabilityId != null) {
        await closureRepository.upsertClosure(
          CandidateClosure(
            vulnerabilityId: vulnerabilityId,
            projectId: projectId,
            disposition: CandidateDisposition.verifiedFinding,
            reasonCode: ClosureReasonCode.directEvidenceVerified,
            explanation:
                'Independent proposer and validator confirmed the finding with direct evidence and repeatable controls.',
            attemptedMethods: const ['independent validation'],
            successfulObservations: finalRecord.directEvidenceArtifactIds
                .map((id) => 'Direct evidence artifact $id')
                .toList(growable: false),
            startedAt: createdAt,
            updatedAt: createdAt,
          ),
        );
      }

      if (advisoryReviewer != null) {
        try {
          await advisoryReviewer!.review(finalRecord).timeout(requestTimeout);
        } catch (_) {
          // Optional advisory review never changes or blocks the local result.
        }
      }
      return finalRecord;
    } finally {
      await repository.releaseLock(
        validationRunId: validationRunId,
        ownerId: lockOwnerId,
      );
    }
  }

  static String _randomOwnerId() {
    final random = Random.secure();
    return List<int>.generate(
      16,
      (_) => random.nextInt(256),
    ).map((value) => value.toRadixString(16).padLeft(2, '0')).join();
  }

  Set<ValidationControl> _requiredControls(VulnerabilityClass value) =>
      switch (value) {
        VulnerabilityClass.authorization => const {
          ValidationControl.authenticatedBaseline,
          ValidationControl.unauthorizedComparison,
        },
        VulnerabilityClass.injection => const {
          ValidationControl.benignNegativeInput,
        },
        VulnerabilityClass.transport => const {
          ValidationControl.protocolBaseline,
        },
        _ => const <ValidationControl>{},
      };

  IndependentValidationDecision _parseDecision(String text) {
    final match = RegExp(
      r'\bdecision\s*:\s*(confirmed|rejected|inconclusive)\b',
      caseSensitive: false,
    ).firstMatch(text);
    return switch (match?.group(1)?.toLowerCase()) {
      'confirmed' => IndependentValidationDecision.confirmed,
      'rejected' => IndependentValidationDecision.rejected,
      _ => IndependentValidationDecision.inconclusive,
    };
  }

  List<int> _parseEvidenceIds(String text) {
    final match = RegExp(
      r'evidence\s*:\s*\[(.*?)\]',
      caseSensitive: false,
    ).firstMatch(text);
    if (match == null) return const [];
    return (match.group(1) ?? '')
        .split(',')
        .map((value) => int.tryParse(value.trim()))
        .whereType<int>()
        .where((value) => value > 0)
        .toSet()
        .toList(growable: false);
  }

  Set<ValidationControl> _parseControls(String text) {
    final match = RegExp(
      r'controls\s*:\s*\[(.*?)\]',
      caseSensitive: false,
    ).firstMatch(text);
    if (match == null) return const {};
    final names = (match.group(1) ?? '')
        .split(',')
        .map((value) => value.trim());
    return ValidationControl.values
        .where((control) => names.contains(control.name))
        .toSet();
  }

  bool _parseAttemptSuccess(String text) =>
      RegExp(r'\battempt\s*:\s*true\b', caseSensitive: false).hasMatch(text);

  String _boundedPrompt(String value) =>
      SensitiveTextRedactor.redact(value, maxLength: 64 * 1024);

  String _boundedResponse(String value) =>
      SensitiveTextRedactor.redact(value, maxLength: maxResponseCharacters);

  String _boundedIdentifier(String value) =>
      SensitiveTextRedactor.redact(value.trim(), maxLength: 256);
}

import 'dart:convert';
import 'dart:math';

import 'package:sqflite_common_ffi/sqflite_ffi.dart';

import '../models/attack_trace.dart';
import 'attack_trace_repository.dart';
import 'sensitive_text_redactor.dart';

enum TraceActionClass { reasoning, command, browser, stateChanging, supervised }

enum TracePlannerDecisionStatus {
  planned,
  approvalRequired,
  blocked,
  budgetExhausted,
}

enum TracePlannerCheckpointStatus { running, paused, completed, blocked }

class TraceActionProposal {
  final TraceActionClass actionClass;
  final String action;
  final String hypothesisStepKey;
  final String cleanupAction;
  final bool approved;
  final bool isRetry;

  const TraceActionProposal({
    required this.actionClass,
    required this.action,
    required this.hypothesisStepKey,
    this.cleanupAction = '',
    this.approved = false,
    this.isRetry = false,
  });
}

class TracePlannerDecision {
  final TracePlannerDecisionStatus status;
  final String reason;
  final String stepKey;
  final bool requiresApproval;

  const TracePlannerDecision({
    required this.status,
    required this.reason,
    this.stepKey = '',
    this.requiresApproval = false,
  });
}

class TracePlannerCheckpoint {
  final TracePlannerCheckpointStatus status;
  final int requestsUsed;
  final int toolsUsed;
  final int retriesUsed;
  final String pendingStepKey;
  final DateTime updatedAt;

  const TracePlannerCheckpoint({
    required this.status,
    required this.requestsUsed,
    required this.toolsUsed,
    required this.retriesUsed,
    required this.pendingStepKey,
    required this.updatedAt,
  });

  Map<String, Object?> toJson() => {
    'status': status.name,
    'requestsUsed': requestsUsed,
    'toolsUsed': toolsUsed,
    'retriesUsed': retriesUsed,
    'pendingStepKey': pendingStepKey,
    'updatedAt': updatedAt.toUtc().toIso8601String(),
  };

  factory TracePlannerCheckpoint.fromJson(Map<String, Object?> value) =>
      TracePlannerCheckpoint(
        status: TracePlannerCheckpointStatus.values.firstWhere(
          (item) => item.name == value['status'],
          orElse: () => TracePlannerCheckpointStatus.blocked,
        ),
        requestsUsed: (value['requestsUsed'] as num?)?.toInt() ?? 0,
        toolsUsed: (value['toolsUsed'] as num?)?.toInt() ?? 0,
        retriesUsed: (value['retriesUsed'] as num?)?.toInt() ?? 0,
        pendingStepKey: value['pendingStepKey']?.toString() ?? '',
        updatedAt:
            DateTime.tryParse(value['updatedAt']?.toString() ?? '')?.toUtc() ??
            DateTime.fromMillisecondsSinceEpoch(0, isUtc: true),
      );
}

class TracePlannerConfig {
  final int maxActionsPerTrace;
  final int maxRequests;
  final int maxTools;
  final int maxRetries;
  final Duration maxRuntime;

  const TracePlannerConfig({
    this.maxActionsPerTrace = 20,
    this.maxRequests = 20,
    this.maxTools = 12,
    this.maxRetries = 3,
    this.maxRuntime = const Duration(hours: 2),
  });
}

class TracePlannerFacade {
  final AttackTraceRepository repository;
  final TracePlannerConfig config;
  final DateTime Function() now;
  final String lockOwnerId;
  final Duration proofLockTtl;

  TracePlannerFacade(
    this.repository, {
    this.config = const TracePlannerConfig(),
    DateTime Function()? now,
    String? lockOwnerId,
    this.proofLockTtl = const Duration(minutes: 10),
  }) : now = now ?? (() => DateTime.now().toUtc()),
       lockOwnerId = lockOwnerId ?? _randomOwnerId();

  Future<TracePlannerDecision> evaluateProposal({
    required int traceId,
    required TraceActionProposal proposal,
  }) async {
    final graph = await repository.graph(traceId);
    final current = await _loadCheckpoint(traceId);
    final usesTool = proposal.actionClass != TraceActionClass.reasoning;
    if (current.status == TracePlannerCheckpointStatus.paused) {
      return const TracePlannerDecision(
        status: TracePlannerDecisionStatus.blocked,
        reason: 'Trace is paused at a safe boundary.',
      );
    }
    if (now().toUtc().difference(graph.trace.startedAt) > config.maxRuntime ||
        current.requestsUsed >= config.maxRequests ||
        (usesTool && current.toolsUsed >= config.maxTools) ||
        (proposal.isRetry && current.retriesUsed >= config.maxRetries)) {
      return const TracePlannerDecision(
        status: TracePlannerDecisionStatus.budgetExhausted,
        reason: 'Trace request, tool, retry, or runtime budget exhausted.',
      );
    }
    final action = proposal.action.trim();
    if (action.isEmpty || _isProhibited(action)) {
      return const TracePlannerDecision(
        status: TracePlannerDecisionStatus.blocked,
        reason: 'Action is empty or prohibited by deterministic safety policy.',
      );
    }
    final stateful =
        proposal.actionClass == TraceActionClass.stateChanging ||
        proposal.actionClass == TraceActionClass.supervised;
    if (stateful && proposal.cleanupAction.trim().isEmpty) {
      return const TracePlannerDecision(
        status: TracePlannerDecisionStatus.blocked,
        reason: 'Reversible state changes require predefined cleanup.',
      );
    }
    if (stateful && !proposal.approved) {
      return const TracePlannerDecision(
        status: TracePlannerDecisionStatus.approvalRequired,
        reason: 'Explicit per-action operator approval is required.',
        requiresApproval: true,
      );
    }

    final stepKey = 'planned-${current.requestsUsed + 1}';
    await _saveCheckpoint(
      traceId,
      TracePlannerCheckpoint(
        status: TracePlannerCheckpointStatus.running,
        requestsUsed: current.requestsUsed + 1,
        toolsUsed: current.toolsUsed + (usesTool ? 1 : 0),
        retriesUsed: current.retriesUsed + (proposal.isRetry ? 1 : 0),
        pendingStepKey: stepKey,
        updatedAt: now().toUtc(),
      ),
    );
    return TracePlannerDecision(
      status: TracePlannerDecisionStatus.planned,
      reason: 'Bounded action planned under deterministic policy.',
      stepKey: stepKey,
    );
  }

  Future<void> pause(int traceId) async {
    final current = await _loadCheckpoint(traceId);
    await _saveCheckpoint(
      traceId,
      TracePlannerCheckpoint(
        status: TracePlannerCheckpointStatus.paused,
        requestsUsed: current.requestsUsed,
        toolsUsed: current.toolsUsed,
        retriesUsed: current.retriesUsed,
        pendingStepKey: current.pendingStepKey,
        updatedAt: now().toUtc(),
      ),
    );
  }

  Future<TracePlannerCheckpoint> resume(int traceId) async {
    final current = await _loadCheckpoint(traceId);
    final resumed = TracePlannerCheckpoint(
      status: TracePlannerCheckpointStatus.running,
      requestsUsed: current.requestsUsed,
      toolsUsed: current.toolsUsed,
      retriesUsed: current.retriesUsed,
      pendingStepKey: current.pendingStepKey,
      updatedAt: now().toUtc(),
    );
    await _saveCheckpoint(traceId, resumed);
    return resumed;
  }

  Future<bool> acquireProof(int traceId) async {
    final acquiredAt = now().toUtc();
    return repository.db.transaction((txn) async {
      await txn.delete(
        'attack_trace_locks',
        where: 'trace_id = ? AND lock_kind = ? AND expires_at <= ?',
        whereArgs: [traceId, 'proof', acquiredAt.toIso8601String()],
      );
      final id = await txn.insert('attack_trace_locks', {
        'trace_id': traceId,
        'lock_kind': 'proof',
        'owner_id': lockOwnerId,
        'acquired_at': acquiredAt.toIso8601String(),
        'expires_at': acquiredAt.add(proofLockTtl).toIso8601String(),
      }, conflictAlgorithm: ConflictAlgorithm.ignore);
      return id != 0;
    });
  }

  Future<void> releaseProof(int traceId) async {
    await repository.db.delete(
      'attack_trace_locks',
      where: 'trace_id = ? AND lock_kind = ? AND owner_id = ?',
      whereArgs: [traceId, 'proof', lockOwnerId],
    );
  }

  Future<void> completeStateChange({
    required int traceId,
    required String actionStepKey,
    required bool cleanupVerified,
  }) async {
    if (!cleanupVerified) {
      throw StateError(
        'State-changing action cannot complete before verified cleanup.',
      );
    }
    final current = await _loadCheckpoint(traceId);
    await _saveCheckpoint(
      traceId,
      TracePlannerCheckpoint(
        status: TracePlannerCheckpointStatus.completed,
        requestsUsed: current.requestsUsed,
        toolsUsed: current.toolsUsed,
        retriesUsed: current.retriesUsed,
        pendingStepKey: '',
        updatedAt: now().toUtc(),
      ),
    );
  }

  /// Backward-compatible selection of the oldest pending deduplicated hypothesis.
  Future<Map<String, Object?>?> nextPlannedAction(int traceId) async {
    if (config.maxActionsPerTrace <= 0) return null;
    final graph = await repository.graph(traceId);
    final statefulKinds = {
      AttackTraceStepKind.command,
      AttackTraceStepKind.browserAction,
      AttackTraceStepKind.controlRequest,
    };
    if (graph.steps.where((step) => statefulKinds.contains(step.kind)).length >=
        config.maxActionsPerTrace) {
      return null;
    }
    final unique = <String, AttackTraceStep>{};
    for (final hypothesis in graph.steps.where(
      (step) => step.kind == AttackTraceStepKind.hypothesis,
    )) {
      final key = hypothesis.hypothesis.trim();
      if (key.isEmpty) continue;
      final previous = unique[key];
      if (previous == null ||
          previous.createdAt.isBefore(hypothesis.createdAt)) {
        unique[key] = hypothesis;
      }
    }
    final pending =
        unique.values
            .where((step) => graph.childrenOf(step.stepKey).isEmpty)
            .toList()
          ..sort((a, b) => a.createdAt.compareTo(b.createdAt));
    if (pending.isEmpty) return null;
    final selected = pending.first;
    final payload = jsonEncode({
      'planned_from_step': selected.stepKey,
      'hypothesis': selected.hypothesis,
      'tactic': selected.tactic,
      'created_at': now().toUtc().toIso8601String(),
    });
    await repository.db.insert('attack_trace_checkpoints', {
      'trace_id': traceId,
      'checkpoint_key': 'next_action',
      'payload': payload,
      'created_at': now().toUtc().toIso8601String(),
    }, conflictAlgorithm: ConflictAlgorithm.replace);
    return {
      'traceId': traceId,
      'checkpointKey': 'next_action',
      'payload': payload,
      'requiresApproval': false,
    };
  }

  Future<TracePlannerCheckpoint> _loadCheckpoint(int traceId) async {
    final rows = await repository.db.query(
      'attack_trace_checkpoints',
      where: 'trace_id = ? AND checkpoint_key = ?',
      whereArgs: [traceId, 'planner_state'],
      limit: 1,
    );
    if (rows.isEmpty) {
      return TracePlannerCheckpoint(
        status: TracePlannerCheckpointStatus.running,
        requestsUsed: 0,
        toolsUsed: 0,
        retriesUsed: 0,
        pendingStepKey: '',
        updatedAt: now().toUtc(),
      );
    }
    return TracePlannerCheckpoint.fromJson(
      Map<String, Object?>.from(
        jsonDecode(rows.single['payload'] as String) as Map,
      ),
    );
  }

  Future<void> _saveCheckpoint(int traceId, TracePlannerCheckpoint value) =>
      repository.db.insert('attack_trace_checkpoints', {
        'trace_id': traceId,
        'checkpoint_key': 'planner_state',
        'payload': jsonEncode(value.toJson()),
        'created_at': value.updatedAt.toUtc().toIso8601String(),
      }, conflictAlgorithm: ConflictAlgorithm.replace);

  bool _isProhibited(String action) {
    final normalized = action.toLowerCase();
    const prohibited = <String>[
      'mimikatz',
      'sekurlsa',
      'credential dump',
      'dump password',
      'disable mfa',
      'bypass mfa',
      'reverse shell',
      'bind shell',
      'create backdoor',
      'persistence',
      'scheduled task',
      'startup folder',
      'external callback',
      'interactsh',
      'ngrok',
      'unbounded tunnel',
      'pivot all',
      'delete database',
      'format disk',
      'rm -rf',
    ];
    return prohibited.any(normalized.contains);
  }

  static String _randomOwnerId() {
    final random = Random.secure();
    return List<int>.generate(
      16,
      (_) => random.nextInt(256),
    ).map((value) => value.toRadixString(16).padLeft(2, '0')).join();
  }
}

class AttackTraceInstrumentation {
  final AttackTraceRepository repository;

  const AttackTraceInstrumentation(this.repository);

  Future<int> recordHypothesis({
    required int traceId,
    required String stepKey,
    required String hypothesis,
    required String tactic,
    required DateTime createdAt,
    List<String> parentStepKeys = const [],
  }) => _append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.hypothesis,
      hypothesis: _redact(hypothesis, 4000),
      tactic: _redact(tactic, 1000),
      createdAt: createdAt,
    ),
  );

  Future<int> recordCommand({
    required int traceId,
    required String stepKey,
    required String command,
    required String output,
    required String interpretation,
    required String adaptation,
    required DateTime createdAt,
    List<String> parentStepKeys = const [],
    List<int> evidenceArtifactIds = const [],
  }) => _append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.command,
      action: _redact(command, 2000),
      output: _redact(output, 8000),
      interpretation: _redact(interpretation, 4000),
      adaptation: _redact(adaptation, 4000),
      evidenceArtifactIds: evidenceArtifactIds,
      createdAt: createdAt,
    ),
  );

  Future<int> recordBrowserAction({
    required int traceId,
    required String stepKey,
    required String action,
    required String output,
    required DateTime createdAt,
    List<String> parentStepKeys = const [],
    List<int> evidenceArtifactIds = const [],
  }) => _append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.browserAction,
      action: _redact(action, 2000),
      output: _redact(output, 8000),
      evidenceArtifactIds: evidenceArtifactIds,
      createdAt: createdAt,
    ),
  );

  Future<int> recordControlRequest({
    required int traceId,
    required String stepKey,
    required String action,
    required DateTime createdAt,
    List<String> parentStepKeys = const [],
  }) => _append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.controlRequest,
      action: _redact(action, 2000),
      createdAt: createdAt,
    ),
  );

  Future<int> recordValidation({
    required int traceId,
    required String stepKey,
    required int validationRunId,
    required AttackTraceValidatorResult result,
    required String interpretation,
    required DateTime createdAt,
    List<String> parentStepKeys = const [],
  }) => _append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.validatorResult,
      validationRunId: validationRunId,
      validatorResult: result,
      interpretation: _redact(interpretation, 4000),
      createdAt: createdAt,
    ),
  );

  Future<int> recordCleanup({
    required int traceId,
    required String stepKey,
    required String action,
    required bool verified,
    required DateTime createdAt,
    List<String> parentStepKeys = const [],
  }) => _append(
    AttackTraceStep(
      traceId: traceId,
      stepKey: stepKey,
      parentStepKeys: parentStepKeys,
      kind: AttackTraceStepKind.cleanup,
      action: _redact(action, 2000),
      cleanupStatus: verified ? 'verified' : 'failed',
      createdAt: createdAt,
    ),
  );

  Future<int> _append(AttackTraceStep step) => repository.append(step);

  static String _redact(String value, int maxLength) =>
      SensitiveTextRedactor.redact(value, maxLength: maxLength);
}

typedef ValidatedCommandRunner =
    Future<Map<String, dynamic>> Function(String command);

class TracedCommandRunner {
  final TracePlannerFacade planner;
  final AttackTraceInstrumentation instrumentation;
  final ValidatedCommandRunner commandRunner;

  const TracedCommandRunner({
    required this.planner,
    required this.instrumentation,
    required this.commandRunner,
  });

  Future<Map<String, dynamic>> execute({
    required int traceId,
    required TraceActionProposal proposal,
    required String interpretation,
    required String adaptation,
    required DateTime createdAt,
    List<int> evidenceArtifactIds = const [],
  }) async {
    final decision = await planner.evaluateProposal(
      traceId: traceId,
      proposal: proposal,
    );
    if (decision.status != TracePlannerDecisionStatus.planned) {
      return {
        'exitCode': -1,
        'output': 'BLOCKED: ${decision.reason}',
        'error': decision.status.name,
      };
    }
    final result = await commandRunner(proposal.action);
    await instrumentation.recordCommand(
      traceId: traceId,
      stepKey: decision.stepKey,
      parentStepKeys: [proposal.hypothesisStepKey],
      command: proposal.action,
      output: result['output']?.toString() ?? '',
      interpretation: interpretation,
      adaptation: adaptation,
      evidenceArtifactIds: evidenceArtifactIds,
      createdAt: createdAt,
    );
    return result;
  }
}

class AttackTraceSummaryBuilder {
  const AttackTraceSummaryBuilder();

  Future<String> build(AttackTraceRepository repository, int traceId) async {
    final graph = await repository.graph(traceId);
    final buffer = StringBuffer()
      ..writeln('Trace: ${graph.trace.title}')
      ..writeln('Status: ${graph.trace.status.name}');
    for (final step in graph.steps) {
      final details = <String>[
        if (step.hypothesis.isNotEmpty) 'hypothesis=${step.hypothesis}',
        if (step.tactic.isNotEmpty) 'tactic=${step.tactic}',
        if (step.action.isNotEmpty) 'action=${step.action}',
        if (step.output.isNotEmpty) 'output=${step.output}',
        if (step.interpretation.isNotEmpty)
          'interpretation=${step.interpretation}',
        if (step.adaptation.isNotEmpty) 'adaptation=${step.adaptation}',
        if (step.evidenceArtifactIds.isNotEmpty)
          'evidence=${step.evidenceArtifactIds.join(',')}',
        if (step.validatorResult != AttackTraceValidatorResult.notRun)
          'validator=${step.validatorResult.name}',
        if (step.cleanupStatus.isNotEmpty) 'cleanup=${step.cleanupStatus}',
      ];
      buffer.writeln(
        '${step.sequence}. ${step.kind.name}: ${details.join(' | ')}',
      );
    }
    return SensitiveTextRedactor.redact(buffer.toString(), maxLength: 64000);
  }
}

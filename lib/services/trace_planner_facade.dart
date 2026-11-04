import 'dart:convert';

import 'attack_trace_repository.dart';
import '../models/attack_trace.dart';

class TracePlannerConfig {
  final int maxActionsPerTrace;

  const TracePlannerConfig({this.maxActionsPerTrace = 5});
}

class TracePlannerFacade {
  final AttackTraceRepository repository;
  final TracePlannerConfig config;

  const TracePlannerFacade(this.repository, {this.config = const TracePlannerConfig()});

  /// Returns a planned next-step checkpoint payload or null when none available
  /// or when the planner's budgets are exhausted.
  Future<Map<String, Object?>?> nextPlannedAction(int traceId) async {
    final graph = await repository.graph(traceId);

    // Count stateful actions already taken as a simple budget heuristic.
    final statefulKinds = {
      AttackTraceStepKind.command,
      AttackTraceStepKind.browserAction,
      AttackTraceStepKind.controlRequest,
    };
    final existingStatefulCount = graph.steps.where((s) => statefulKinds.contains(s.kind)).length;
    if (existingStatefulCount >= config.maxActionsPerTrace) {
      return null; // budget exhausted
    }

    // Deduplicate hypotheses by hypothesis text and choose the earliest createdAt
    final hypotheses = graph.steps.where((s) => s.kind == AttackTraceStepKind.hypothesis);
    final Map<String, AttackTraceStep> unique = {};
    for (final h in hypotheses) {
      final key = h.hypothesis.trim();
      if (key.isEmpty) continue;
      if (!unique.containsKey(key) || unique[key]!.createdAt.isAfter(h.createdAt)) {
        unique[key] = h;
      }
    }

    if (unique.isEmpty) return null;

    // Find hypotheses that have no children (i.e., pending exploration)
    final pending = unique.values.where((h) => graph.childrenOf(h.stepKey).isEmpty).toList();
    if (pending.isEmpty) return null;

    // Choose the oldest pending hypothesis
    pending.sort((a, b) => a.createdAt.compareTo(b.createdAt));
    final chosen = pending.first;

    // Persist a checkpoint for the planned action
    final payload = jsonEncode({
      'planned_from_step': chosen.stepKey,
      'hypothesis': chosen.hypothesis,
      'tactic': chosen.tactic,
      'created_at': DateTime.now().toUtc().toIso8601String(),
    });
    final checkpointKey = 'next_action';
    await repository.db.insert('attack_trace_checkpoints', {
      'trace_id': traceId,
      'checkpoint_key': checkpointKey,
      'payload': payload,
      'created_at': DateTime.now().toUtc().toIso8601String(),
    });

    return {
      'traceId': traceId,
      'checkpointKey': checkpointKey,
      'payload': payload,
      'requiresApproval': false,
    };
  }
}

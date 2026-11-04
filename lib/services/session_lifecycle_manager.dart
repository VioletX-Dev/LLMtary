import 'dart:convert';
import 'dart:math';

import '../models/browser_session.dart';
import 'browser_process_manager.dart';
import 'browser_session_repository.dart';

class SessionLifecycleManager {
  final BrowserSessionRepository repository;
  final BrowserProcessLauncher launcher;
  final String chromiumExecutable;
  final Duration maxIdle;
  final DateTime Function() now;
  final Map<String, BrowserProcess> _processes = {};

  SessionLifecycleManager({
    required this.repository,
    required this.launcher,
    required this.chromiumExecutable,
    this.maxIdle = const Duration(minutes: 15),
    DateTime Function()? now,
  }) : now = now ?? (() => DateTime.now().toUtc()) {
    if (!chromiumExecutable.startsWith('/')) {
      throw ArgumentError.value(
        chromiumExecutable,
        'chromiumExecutable',
        'A trusted absolute executable path is required',
      );
    }
  }

  Future<BrowserSessionSnapshot> createSession({
    required int projectId,
    required String roleId,
  }) async {
    if (projectId <= 0 || roleId.trim().isEmpty) {
      throw ArgumentError('Persisted project id and non-empty role id required');
    }
    final sessionId = _randomId();
    final process = await launcher.startChromium(executable: chromiumExecutable);
    final createdAt = now().toUtc();
    final snapshot = BrowserSessionSnapshot(
      sessionId: sessionId,
      projectId: projectId,
      roleId: roleId.trim(),
      status: BrowserSessionStatus.active,
      createdAt: createdAt,
      lastActiveAt: createdAt,
      currentUrl: 'about:blank',
      domSha256: '',
    );
    try {
      await repository.upsert(snapshot);
      _processes[sessionId] = process;
      return snapshot;
    } catch (_) {
      await process.kill();
      rethrow;
    }
  }

  Future<void> updateState(
    String sessionId, {
    required String currentUrl,
    required String domSha256,
    required List<BrowserFormState> forms,
    required List<BrowserSessionNetworkExchange> networkExchanges,
    required List<int> evidenceArtifactIds,
  }) async {
    final existing = await _requireActive(sessionId);
    await repository.upsert(BrowserSessionSnapshot(
      sessionId: existing.sessionId,
      projectId: existing.projectId,
      roleId: existing.roleId,
      status: BrowserSessionStatus.active,
      createdAt: existing.createdAt,
      lastActiveAt: now().toUtc(),
      currentUrl: currentUrl,
      domSha256: domSha256,
      forms: forms,
      networkExchanges: networkExchanges,
      evidenceArtifactIds: evidenceArtifactIds,
    ));
  }

  BrowserProcess? processFor(String sessionId) => _processes[sessionId];

  Future<void> closeSession(String sessionId) async {
    final process = _processes.remove(sessionId);
    if (process != null) await process.kill();
    await repository.markClosed(sessionId, now().toUtc());
  }

  Future<List<String>> recoverAbandonedSessions() async {
    final abandoned = await repository.activeBefore(
      now().toUtc().subtract(maxIdle),
    );
    final recovered = <String>[];
    for (final session in abandoned) {
      await closeSession(session.sessionId);
      recovered.add(session.sessionId);
    }
    return List.unmodifiable(recovered);
  }

  Future<BrowserSessionSnapshot> _requireActive(String sessionId) async {
    final existing = await repository.get(sessionId);
    if (existing == null || existing.status != BrowserSessionStatus.active) {
      throw StateError('Browser session is not active');
    }
    return existing;
  }

  String _randomId() {
    final random = Random.secure();
    final bytes = List<int>.generate(18, (_) => random.nextInt(256));
    return base64UrlEncode(bytes).replaceAll('=', '');
  }
}

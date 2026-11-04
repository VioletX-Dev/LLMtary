import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/browser_session.dart';
import 'package:llmtary/services/browser_process_manager.dart';
import 'package:llmtary/services/browser_session_repository.dart';
import 'package:llmtary/services/session_lifecycle_manager.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

class _FakeProcess implements Process {
  bool killed = false;
  @override
  final int pid;
  _FakeProcess(this.pid);
  @override
  Future<int> get exitCode async => 0;
  @override
  bool kill([ProcessSignal signal = ProcessSignal.sigterm]) {
    killed = true;
    return true;
  }
  @override
  Stream<List<int>> get stdout => const Stream.empty();
  @override
  Stream<List<int>> get stderr => const Stream.empty();
  @override
  IOSink get stdin => _FakeSink();
  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeSink implements IOSink {
  @override Encoding encoding = utf8;
  @override Future<void> close() async {}
  @override Future<void> get done async {}
  @override void add(List<int> data) {}
  @override void addError(Object error, [StackTrace? stackTrace]) {}
  @override Future<void> addStream(Stream<List<int>> stream) async {}
  @override void write(Object? object) {}
  @override void writeAll(Iterable<Object?> objects, [String separator = '']) {}
  @override void writeCharCode(int charCode) {}
  @override void writeln([Object? object = '']) {}
  @override noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeLauncher implements BrowserProcessLauncher {
  final List<BrowserProcess> launched = [];
  final List<String> executables = [];
  int nextPid = 1;
  @override
  Future<BrowserProcess> startChromium({
    required String executable,
    List<String> extraArgs = const [],
    Map<String, String>? environment,
  }) async {
    executables.add(executable);
    final profile = await Directory.systemTemp.createTemp('browser-role-');
    final process = BrowserProcess(
      process: _FakeProcess(nextPid++),
      debugPort: 9222 + nextPid,
      websocketUri: Uri.parse('ws://127.0.0.1:9222/devtools/browser'),
      profileDirectory: profile,
    );
    launched.add(process);
    return process;
  }
}

void main() {
  test('isolates role sessions, persists state, and closes abandoned sessions', () async {
    sqfliteFfiInit();
    final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
    addTearDown(db.close);
    await BrowserSessionRepository.createTables(db);
    final repository = BrowserSessionRepository(db);
    final launcher = _FakeLauncher();
    expect(
      () => SessionLifecycleManager(
        repository: repository,
        launcher: launcher,
        chromiumExecutable: '/tmp/untrusted-chromium',
        executableProbe: (_) => true,
      ),
      throwsArgumentError,
    );
    final unavailable = SessionLifecycleManager(
      repository: repository,
      launcher: launcher,
      executableProbe: (_) => false,
    );
    await expectLater(
      unavailable.createSession(projectId: 4, roleId: 'unavailable'),
      throwsStateError,
    );
    var now = DateTime.utc(2026, 11, 4, 12);
    final manager = SessionLifecycleManager(
      repository: repository,
      launcher: launcher,
      executableProbe: (_) => true,
      maxIdle: const Duration(minutes: 30),
      now: () => now,
    );

    final admin = await manager.createSession(projectId: 4, roleId: 'admin');
    final user = await manager.createSession(projectId: 4, roleId: 'user');

    expect(admin.sessionId, isNot(user.sessionId));
    expect(launcher.launched, hasLength(2));
    expect(launcher.executables, everyElement('/usr/bin/chromium'));
    expect(
      launcher.launched[0].profileDirectory.path,
      isNot(launcher.launched[1].profileDirectory.path),
    );
    await manager.updateState(
      admin.sessionId,
      currentUrl: 'https://target.local/admin?token=secret',
      domSha256: 'digest',
      forms: const [],
      networkExchanges: const [],
      evidenceArtifactIds: const [7],
    );
    final persisted = await repository.get(admin.sessionId);
    expect(persisted!.roleId, 'admin');
    expect(persisted.evidenceArtifactIds, [7]);
    expect(persisted.currentUrl, isNot(contains('secret')));

    now = now.add(const Duration(hours: 1));
    final recovered = await manager.recoverAbandonedSessions();
    expect(recovered, containsAll([admin.sessionId, user.sessionId]));
    expect((launcher.launched[0].process as _FakeProcess).killed, isTrue);
    expect((await repository.get(admin.sessionId))!.status, BrowserSessionStatus.closed);
  });
}

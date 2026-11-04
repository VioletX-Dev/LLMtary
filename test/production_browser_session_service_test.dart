import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/browser_test.dart';
import 'package:llmtary/services/attack_trace_recorder.dart';
import 'package:llmtary/services/browser_process_manager.dart';
import 'package:llmtary/services/browser_session_repository.dart';
import 'package:llmtary/services/production_browser_session_service.dart';
import 'package:llmtary/services/session_lifecycle_manager.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

class _Process implements Process {
  @override
  final int pid = 1;
  @override
  Future<int> get exitCode async => 0;
  @override
  bool kill([ProcessSignal signal = ProcessSignal.sigterm]) => true;
  @override
  Stream<List<int>> get stdout => const Stream.empty();
  @override
  Stream<List<int>> get stderr => const Stream.empty();
  @override
  IOSink get stdin => _Sink();
  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Sink implements IOSink {
  @override
  Encoding encoding = utf8;
  @override
  Future<void> close() async {}
  @override
  Future<void> get done async {}
  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _Launcher implements BrowserProcessLauncher {
  @override
  Future<BrowserProcess> startChromium({
    required String executable,
    List<String> extraArgs = const [],
    Map<String, String>? environment,
  }) async {
    return BrowserProcess(
      process: _Process(),
      debugPort: 9222,
      websocketUri: Uri.parse('ws://127.0.0.1:9222/devtools/page/test'),
      profileDirectory: await Directory.systemTemp.createTemp('prod-browser-'),
    );
  }
}

class _Driver implements BrowserDriver {
  @override
  Future<BrowserDriverObservation> perform(
    BrowserActionRequest request,
  ) async => const BrowserDriverObservation(
    url: 'https://target.local/login?token=secret',
    statusCode: 200,
    domSnapshot:
        '<form id="login"><input name="password" type="password" value="secret"></form>',
    networkExchanges: [
      BrowserNetworkExchange(
        method: 'GET',
        url: 'https://target.local/login?token=secret',
        statusCode: 200,
      ),
    ],
    screenshotEvidenceArtifactId: 17,
  );
}

class _Recorder implements AttackTraceRecorder {
  int calls = 0;
  @override
  Future<int> recordBrowserAction({
    required int traceId,
    required String stepKey,
    List<String> parentStepKeys = const [],
    required BrowserActionRecord record,
    required DateTime createdAt,
  }) async {
    calls++;
    return 1;
  }

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test(
    'runs a production browser action and persists sanitized modeled state',
    () async {
      sqfliteFfiInit();
      final db = await databaseFactoryFfi.openDatabase(inMemoryDatabasePath);
      addTearDown(db.close);
      await BrowserSessionRepository.createTables(db);
      final repository = BrowserSessionRepository(db);
      final lifecycle = SessionLifecycleManager(
        repository: repository,
        launcher: _Launcher(),
        chromiumExecutable: '/usr/bin/chromium',
      );
      final recorder = _Recorder();
      var closed = false;
      final service = ProductionBrowserSessionService(
        lifecycle: lifecycle,
        repository: repository,
        traceRecorder: recorder,
        runtimeFactory: (process, screenshotSink) async => BrowserDriverRuntime(
          driver: _Driver(),
          close: () async => closed = true,
        ),
      );

      final session = await service.start(
        projectId: 4,
        roleId: 'admin',
        traceId: 9,
        screenshotSink: (bytes) async => 17,
      );
      final record = await service.execute(
        session.sessionId,
        const BrowserActionRequest(
          kind: BrowserActionKind.navigate,
          url: 'https://target.local/login',
          roleId: 'admin',
        ),
      );

      expect(record.evidenceArtifactIds, [17]);
      expect(recorder.calls, 1);
      final persisted = await repository.get(session.sessionId);
      expect(persisted!.forms.single.fields.single.type, 'password');
      expect(persisted.currentUrl, isNot(contains('secret')));
      await service.close(session.sessionId);
      expect(closed, isTrue);
    },
  );
}

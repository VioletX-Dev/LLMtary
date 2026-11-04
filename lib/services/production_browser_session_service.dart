import '../models/browser_session.dart';
import '../models/browser_test.dart';
import 'attack_trace_recorder.dart';
import 'browser_form_state_modeler.dart';
import 'browser_process_manager.dart';
import 'browser_session_repository.dart';
import 'browser_testing_service.dart';
import 'cdp_browser_driver.dart';
import 'session_lifecycle_manager.dart';

class BrowserDriverRuntime {
  final BrowserDriver driver;
  final Future<void> Function() close;

  const BrowserDriverRuntime({required this.driver, required this.close});
}

typedef BrowserDriverRuntimeFactory =
    Future<BrowserDriverRuntime> Function(
      BrowserProcess process,
      BrowserScreenshotSink? screenshotSink,
    );

class ProductionBrowserSessionService {
  final SessionLifecycleManager lifecycle;
  final BrowserSessionRepository repository;
  final AttackTraceRecorder traceRecorder;
  final BrowserDriverRuntimeFactory runtimeFactory;
  final BrowserFormStateModeler formModeler;
  final Map<String, BrowserDriverRuntime> _runtimes = {};
  final Map<String, BrowserTestingService> _testingServices = {};

  ProductionBrowserSessionService({
    required this.lifecycle,
    required this.repository,
    required this.traceRecorder,
    BrowserDriverRuntimeFactory? runtimeFactory,
    this.formModeler = const BrowserFormStateModeler(),
  }) : runtimeFactory = runtimeFactory ?? _defaultRuntimeFactory;

  Future<BrowserSessionSnapshot> start({
    required int projectId,
    required String roleId,
    required int traceId,
    BrowserScreenshotSink? screenshotSink,
  }) async {
    if (traceId <= 0) throw ArgumentError.value(traceId, 'traceId');
    final session = await lifecycle.createSession(
      projectId: projectId,
      roleId: roleId,
    );
    final process = lifecycle.processFor(session.sessionId);
    if (process == null) {
      await lifecycle.closeSession(session.sessionId);
      throw StateError('Browser process was not registered');
    }
    try {
      final runtime = await runtimeFactory(process, screenshotSink);
      _runtimes[session.sessionId] = runtime;
      _testingServices[session.sessionId] = BrowserTestingService(
        runtime.driver,
        attackTraceRecorder: traceRecorder,
        attackTraceId: traceId,
      );
      return session;
    } catch (_) {
      await lifecycle.closeSession(session.sessionId);
      rethrow;
    }
  }

  Future<BrowserActionRecord> execute(
    String sessionId,
    BrowserActionRequest request,
  ) async {
    final persisted = await repository.get(sessionId);
    if (persisted == null || persisted.status != BrowserSessionStatus.active) {
      throw StateError('Browser session is not active');
    }
    if (request.roleId.trim().isNotEmpty &&
        request.roleId != persisted.roleId) {
      throw StateError('Browser role does not match the isolated session');
    }
    final service = _testingServices[sessionId];
    if (service == null) throw StateError('Browser runtime is unavailable');
    final result = await service.executeDetailed(request);
    final record = result.record;
    await lifecycle.updateState(
      sessionId,
      currentUrl: record.finalUrl,
      domSha256: record.domSha256,
      forms: formModeler.fromDom(result.observation.domSnapshot),
      networkExchanges: record.networkExchanges
          .map(
            (exchange) => BrowserSessionNetworkExchange(
              method: exchange.method,
              url: exchange.url,
              statusCode: exchange.statusCode,
            ),
          )
          .toList(growable: false),
      evidenceArtifactIds: record.evidenceArtifactIds,
    );
    return record;
  }

  Future<void> close(String sessionId) async {
    final runtime = _runtimes.remove(sessionId);
    _testingServices.remove(sessionId);
    try {
      if (runtime != null) await runtime.close();
    } finally {
      await lifecycle.closeSession(sessionId);
    }
  }

  static Future<BrowserDriverRuntime> _defaultRuntimeFactory(
    BrowserProcess process,
    BrowserScreenshotSink? screenshotSink,
  ) async {
    final transport = await WebSocketCdpTransport.connect(process.websocketUri);
    return BrowserDriverRuntime(
      driver: CdpBrowserDriver(transport, screenshotSink: screenshotSink),
      close: transport.close,
    );
  }
}

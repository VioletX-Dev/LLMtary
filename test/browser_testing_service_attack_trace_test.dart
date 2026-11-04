
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/browser_test.dart';
import 'package:llmtary/services/browser_testing_service.dart';
import 'package:llmtary/services/attack_trace_recorder.dart';

class _FakeDriver implements BrowserDriver {
  final BrowserDriverObservation observation;
  _FakeDriver(this.observation);

  @override
  Future<BrowserDriverObservation> perform(BrowserActionRequest request) async => observation;
}

class _FakeRecorder implements AttackTraceRecorder {
  int calls = 0;
  int? receivedTraceId;
  @override
  Future<int> recordBrowserAction({
    required int traceId,
    required String stepKey,
    List<String> parentStepKeys = const [],
    required BrowserActionRecord record,
    required DateTime createdAt,
  }) async {
    calls += 1;
    receivedTraceId = traceId;
    return 1;
  }

  // The other methods are unused in this test; forward to noSuchMethod
  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test('BrowserTestingService calls AttackTraceRecorder.recordBrowserAction', () async {
    final observation = BrowserDriverObservation(
      url: 'http://example.local',
      statusCode: 200,
      domSnapshot: '<html></html>',
    );
    final driver = _FakeDriver(observation);
    final recorder = _FakeRecorder();
    final service = BrowserTestingService(
      driver,
      attackTraceRecorder: recorder,
      attackTraceId: 42,
    );

    final request = BrowserActionRequest(kind: BrowserActionKind.navigate, url: 'http://example.local');

    final record = await service.execute(request);

    expect(record.finalUrl, contains('http'));
    expect(recorder.calls, 1);
    expect(recorder.receivedTraceId, 42);
  });

  test('requires a persisted trace id when trace recording is enabled', () {
    final driver = _FakeDriver(const BrowserDriverObservation(
      url: 'about:blank',
      statusCode: 0,
      domSnapshot: '',
    ));
    final recorder = _FakeRecorder();

    expect(
      () => BrowserTestingService(driver, attackTraceRecorder: recorder),
      throwsArgumentError,
    );
  });
}

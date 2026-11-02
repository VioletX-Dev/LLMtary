import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/browser_test.dart';
import 'package:llmtary/services/browser_testing_service.dart';

class _FakeBrowserDriver implements BrowserDriver {
  BrowserActionRequest? received;

  @override
  Future<BrowserDriverObservation> perform(BrowserActionRequest request) async {
    received = request;
    return const BrowserDriverObservation(
      url: 'https://app.example.test/account',
      statusCode: 200,
      domSnapshot: '<main><h1>Account</h1></main>',
      networkExchanges: [
        BrowserNetworkExchange(
          method: 'POST',
          url: 'https://app.example.test/session',
          statusCode: 200,
          requestHeaders: {
            'authorization': 'Bearer secret-value',
            'content-type': 'application/json',
          },
          responseHeaders: {'set-cookie': 'session=secret-value'},
        ),
      ],
      screenshotEvidenceArtifactId: 77,
    );
  }
}

void main() {
  test('steers browser and captures sanitized evidence-linked state', () async {
    final driver = _FakeBrowserDriver();
    final record = await BrowserTestingService(driver).execute(
      const BrowserActionRequest(
        kind: BrowserActionKind.fill,
        selector: '#password',
        value: 'never-persist-this',
        roleId: 'analyst',
      ),
    );

    expect(driver.received?.value, 'never-persist-this');
    expect(record.action, 'fill #password');
    expect(record.action, isNot(contains('never-persist-this')));
    expect(record.domSha256, hasLength(64));
    expect(record.networkExchanges.single.requestHeaders, {
      'content-type': 'application/json',
    });
    expect(record.networkExchanges.single.responseHeaders, isEmpty);
    expect(record.evidenceArtifactIds, [77]);
  });
}

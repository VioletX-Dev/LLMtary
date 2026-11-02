import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/browser_test.dart';
import 'package:llmtary/services/cdp_browser_driver.dart';

class _FakeCdpTransport implements CdpTransport {
  final controller = StreamController<Map<String, dynamic>>.broadcast();
  final commands = <String>[];

  @override
  Stream<Map<String, dynamic>> get events => controller.stream;

  @override
  Future<Map<String, dynamic>> send(
    String method, [
    Map<String, dynamic> params = const {},
  ]) async {
    commands.add(method);
    if (method == 'Page.navigate') {
      scheduleMicrotask(() {
        controller.add({
          'method': 'Network.requestWillBeSent',
          'params': {
            'requestId': 'request-1',
            'request': {
              'url': 'https://app.example.test/dashboard',
              'method': 'GET',
              'headers': {'accept': 'text/html'},
            },
          },
        });
        controller.add({
          'method': 'Network.responseReceived',
          'params': {
            'requestId': 'request-1',
            'type': 'Document',
            'response': {
              'url': 'https://app.example.test/dashboard',
              'status': 200,
              'headers': {'content-type': 'text/html'},
            },
          },
        });
        controller.add({'method': 'Page.loadEventFired', 'params': {}});
      });
      return {'frameId': 'frame-1'};
    }
    if (method == 'Runtime.evaluate') {
      final expression = params['expression'] as String;
      if (expression.contains('outerHTML')) {
        return {
          'result': {'value': '<html><main>Dashboard</main></html>'},
        };
      }
      if (expression.contains('location.href')) {
        return {
          'result': {'value': 'https://app.example.test/dashboard'},
        };
      }
    }
    return const {};
  }

  @override
  Future<void> close() => controller.close();
}

void main() {
  test(
    'CDP driver navigates and captures DOM plus network exchanges',
    () async {
      final transport = _FakeCdpTransport();
      addTearDown(transport.close);
      final driver = CdpBrowserDriver(
        transport,
        navigationTimeout: const Duration(seconds: 1),
      );

      final observation = await driver.perform(
        const BrowserActionRequest(
          kind: BrowserActionKind.navigate,
          url: 'https://app.example.test/dashboard',
          roleId: 'analyst',
        ),
      );

      expect(
        transport.commands,
        containsAll(['Page.enable', 'Network.enable', 'Page.navigate']),
      );
      expect(observation.url, 'https://app.example.test/dashboard');
      expect(observation.statusCode, 200);
      expect(observation.domSnapshot, contains('Dashboard'));
      expect(observation.networkExchanges.single.method, 'GET');
      expect(observation.networkExchanges.single.statusCode, 200);
    },
  );
}

import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/browser_runtime_configuration.dart';

void main() {
  test(
    'uses only an approved browser path from root-managed configuration',
    () {
      final directory = Directory.systemTemp.createTempSync('browser-config-');
      addTearDown(() => directory.deleteSync(recursive: true));
      final config = File('${directory.path}/browser-runtime.conf')
        ..writeAsStringSync('CHROMIUM_EXECUTABLE=/usr/bin/chromium-browser\n');
      expect(
        BrowserRuntimeConfiguration.resolve(configFile: config),
        '/usr/bin/chromium-browser',
      );

      Process.runSync('/bin/chmod', ['0666', config.path]);
      expect(
        BrowserRuntimeConfiguration.resolve(configFile: config),
        '/usr/bin/chromium',
      );
      Process.runSync('/bin/chmod', ['0600', config.path]);

      config.writeAsStringSync('CHROMIUM_EXECUTABLE=/tmp/untrusted\n');
      expect(
        BrowserRuntimeConfiguration.resolve(configFile: config),
        '/usr/bin/chromium',
      );
    },
  );

  test('falls back deterministically when configuration is absent', () {
    expect(
      BrowserRuntimeConfiguration.resolve(
        configFile: File('/definitely/missing/browser-runtime.conf'),
      ),
      '/usr/bin/chromium',
    );
  });
}

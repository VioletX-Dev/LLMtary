import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/branding.dart';

void main() {
  test('defines the VioletX Pentesting Agent display name', () {
    expect(appDisplayName, 'VioletX Pentesting Agent');
    expect(appShortName, 'VioletX Pentesting Agent');
  });

  test('uses the display name on user-visible desktop surfaces', () {
    for (final path in <String>[
      'lib/main.dart',
      'lib/screens/home_screen.dart',
      'lib/screens/main_screen.dart',
    ]) {
      expect(File(path).readAsStringSync(), contains('appDisplayName'), reason: path);
    }
    for (final path in <String>[
      'linux/LLMtary.desktop',
      'linux/runner/my_application.cc',
      'windows/runner/main.cpp',
      'windows/runner/Runner.rc',
      'macos/Runner/Configs/AppInfo.xcconfig',
    ]) {
      expect(File(path).readAsStringSync(), contains('VioletX Pentesting Agent'), reason: path);
    }
  });

  test('preserves technical identifiers for upgrade compatibility', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    final linuxCmake = File('linux/CMakeLists.txt').readAsStringSync();
    expect(pubspec, contains('name: llmtary'));
    expect(linuxCmake, contains('set(BINARY_NAME "llmtary")'));
  });
}

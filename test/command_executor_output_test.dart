import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/command_executor.dart';

void main() {
  test('executeCommand caps captured output without killing the process', () async {
    if (!Platform.isLinux && !Platform.isMacOS) {
      return;
    }

    final result = await CommandExecutor.executeCommand(
      "python3 -c \"print('A' * 300000); print('TAIL')\"",
      false,
      maxCapturedOutputChars: 4096,
    );

    expect(result['exitCode'], 0);
    expect(result['output'], contains('OUTPUT TRUNCATED'));
    expect((result['output'] as String).length, lessThan(5000));
  });
}

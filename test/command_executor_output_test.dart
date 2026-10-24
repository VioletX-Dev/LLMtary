import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/command_executor.dart';

void main() {
  test('approval-required command fails closed without a callback', () async {
    final result = await CommandExecutor.executeCommand(
      'printf SHOULD_NOT_RUN',
      true,
    );

    expect(result['exitCode'], -2);
    expect(result['output'], contains('Explicit operator approval is required'));
  });

  test('approval-required command prompts every time and ignores always allow', () async {
    if (!Platform.isLinux && !Platform.isMacOS) {
      return;
    }

    var approvalCalls = 0;
    final first = await CommandExecutor.executeCommand(
      'printf APPROVED_ONCE',
      true,
      onApprovalNeeded: (_) async {
        approvalCalls++;
        return 'always';
      },
    );
    final second = await CommandExecutor.executeCommand(
      'printf SHOULD_NOT_RUN',
      true,
      onApprovalNeeded: (_) async {
        approvalCalls++;
        return 'deny';
      },
    );

    expect(first['exitCode'], 0);
    expect(second['exitCode'], -2);
    expect(second['output'], contains('DENIED'));
    expect(approvalCalls, 2);
  });

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

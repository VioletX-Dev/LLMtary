import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test(
    'executor injects targeted directive into analysis and command prompts',
    () {
      final source = File(
        'lib/services/exploit_executor.dart',
      ).readAsStringSync();

      expect(source, contains('String executionDirective = \'\''));
      expect(source, contains('bool forceActiveTesting = false'));
      expect(source, contains('if (!forceActiveTesting &&'));
      expect(
        source,
        contains(
          "executionDirective.isNotEmpty ? '\\n\\n\$executionDirective' : ''",
        ),
      );
      expect(source, contains('executionDirective: executionDirective'));
    },
  );
}

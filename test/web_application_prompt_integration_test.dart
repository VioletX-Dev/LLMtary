import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/prompt_templates.dart';
import 'package:llmtary/utils/device_utils.dart';

void main() {
  test('core web prompt includes the web application testing skill', () {
    final prompt = PromptTemplates.webAppCorePrompt(
      '{"target":"https://staging.example.test","open_ports":[{"port":443,"service":"https"}]}',
      scope: TargetScope.external,
    );

    expect(prompt, contains('AUTHORIZED TARGETS ONLY'));
    expect(prompt, contains('AUTHENTICATED MULTI-ROLE TESTING'));
    expect(prompt, contains('EVIDENCE-DRIVEN VALIDATION'));
    expect(prompt, contains('Coverage ledger'));
  });
}

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/prompt_templates.dart';
import 'package:llmtary/utils/device_utils.dart';

void main() {
  test('project preserves customer testing requests in maps and copyWith', () {
    final project = Project(
      name: 'engagement',
      folderPath: '/tmp/engagement',
      createdAt: DateTime(2026, 1, 1),
      lastOpenedAt: DateTime(2026, 1, 1),
      customerTestingRequests: 'Test checkout and password reset.',
    );

    final restored = Project.fromMap(project.toMap());
    expect(restored.customerTestingRequests, 'Test checkout and password reset.');
    expect(
      project.copyWith(customerTestingRequests: 'Test API authorization.')
          .customerTestingRequests,
      'Test API authorization.',
    );
  });

  test('web prompt includes customer requests as bounded untrusted requirements', () {
    final prompt = PromptTemplates.webAppCorePrompt(
      '{"open_ports":[{"port":443,"service":"https"}]}',
      scope: TargetScope.external,
      customerTestingRequests: 'Focus on checkout authorization and coupon abuse.',
    );

    expect(prompt, contains('CUSTOMER TESTING REQUESTS'));
    expect(prompt, contains('Focus on checkout authorization and coupon abuse.'));
    expect(prompt, contains('UNTRUSTED TESTING REQUIREMENTS'));
    expect(prompt, contains('out-of-scope actions'));
  });
}

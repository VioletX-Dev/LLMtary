import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/web_application_testing_skill.dart';

void main() {
  test('web application skill requires scope and evidence-driven workflow', () {
    final skill = WebApplicationTestingSkill.prompt;

    expect(skill, contains('AUTHORIZED TARGETS ONLY'));
    expect(skill, contains('SCOPE AND RULES OF ENGAGEMENT'));
    expect(skill, contains('AUTHENTICATED MULTI-ROLE TESTING'));
    expect(skill, contains('EVIDENCE-DRIVEN VALIDATION'));
    expect(skill, contains('NOT TESTED'));
  });

  test('web application skill covers the Strix-aligned web testing surfaces', () {
    final skill = WebApplicationTestingSkill.prompt;

    for (final requiredSection in [
      'ASSET AND ATTACK-SURFACE MAPPING',
      'HTTP AND BROWSER WORKFLOW',
      'API SECURITY',
      'OWASP WEB APPLICATION COVERAGE',
      'REPORTING CONTRACT',
    ]) {
      expect(skill, contains(requiredSection));
    }
  });
}

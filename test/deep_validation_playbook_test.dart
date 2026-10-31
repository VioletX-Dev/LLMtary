import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/deep_validation_playbook.dart';

Vulnerability finding(String problem, {String type = ''}) => Vulnerability(
  id: 5,
  projectId: 1,
  targetId: 2,
  targetAddress: '192.0.2.20',
  problem: problem,
  description: problem,
  severity: 'HIGH',
  confidence: 'LOW',
  evidence: '',
  recommendation: 'Validate.',
  vulnerabilityType: type,
);

void main() {
  test(
    'web playbook requires native fallback after an Nmap script failure',
    () {
      final playbook = DeepValidationPlaybook.forCandidate(
        finding('Missing X-Frame-Options security header'),
        attemptedMethods: const ['http-response-headers'],
        deepSupervised: true,
        credentialsAvailable: false,
      );

      expect(playbook.family, DeepPlaybookFamily.web);
      expect(playbook.nextMethodId, 'http-response-headers-native');
      expect(playbook.directive, contains('Nmap NSE'));
      expect(playbook.directive, contains('not evidence of absence'));
      expect(playbook.directive, contains('192.0.2.20'));
      expect(playbook.directive, contains('exact-command approval'));
    },
  );

  test(
    'directory playbook exposes credentialed method without credential values',
    () {
      final playbook = DeepValidationPlaybook.forCandidate(
        finding('LDAP anonymous bind and directory policy'),
        attemptedMethods: const ['ldap-rootdse-read'],
        deepSupervised: true,
        credentialsAvailable: true,
      );

      expect(playbook.family, DeepPlaybookFamily.windowsDirectory);
      expect(playbook.nextMethodId, 'ldap-approved-bind-metadata');
      expect(playbook.directive, contains('session-local'));
      expect(playbook.directive, isNot(contains('password=')));
    },
  );

  test('repetition is rejected when no distinct safe method remains', () {
    final playbook = DeepValidationPlaybook.forCandidate(
      finding('Missing X-Frame-Options security header'),
      attemptedMethods: const [
        'http-response-headers',
        'http-response-headers-native',
      ],
      deepSupervised: true,
      credentialsAvailable: false,
    );

    expect(playbook.nextMethodId, isNull);
    expect(playbook.distinctMethodsExhausted, isTrue);
  });
}

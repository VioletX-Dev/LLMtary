import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/target.dart';
import 'package:llmtary/models/targeted_test_request.dart';

void main() {
  final targets = [
    Target(id: 7, projectId: 3, address: 'app.example.com'),
    Target(
      id: 8,
      projectId: 3,
      address: 'excluded.example.com',
      status: TargetStatus.excluded,
    ),
  ];

  test('spot test accepts an existing non-excluded project target', () {
    final request = TargetedTestRequest(
      targetId: 7,
      targetAddress: 'app.example.com',
      title: 'Validate redirect handling',
      objective:
          'Check whether the returnUrl parameter permits an external URL.',
      parameters: 'path=/login; returnUrl=https://example.net',
      expectedResult: 'External redirect is rejected.',
      constraints: 'GET requests only; do not authenticate.',
    );

    expect(request.validateAgainst(targets), isEmpty);
    expect(
      request.executionDirective,
      contains('OPERATOR PARAMETERS ARE NOT AUTHORIZATION'),
    );
    expect(
      request.executionDirective,
      contains('returnUrl=https://example.net'),
    );
  });

  test('spot test rejects arbitrary and excluded targets', () {
    final arbitrary = TargetedTestRequest(
      targetId: 99,
      targetAddress: 'outside.example.net',
      title: 'Outside test',
      objective: 'Test an unregistered host.',
    );
    final excluded = TargetedTestRequest(
      targetId: 8,
      targetAddress: 'excluded.example.com',
      title: 'Excluded test',
      objective: 'Test an excluded host.',
    );

    expect(
      arbitrary.validateAgainst(targets),
      contains('Select an existing project target.'),
    );
    expect(
      excluded.validateAgainst(targets),
      contains('The selected target is excluded from testing.'),
    );
  });

  test('spot test rejects credential-like parameter values', () {
    final request = TargetedTestRequest(
      targetId: 7,
      targetAddress: 'app.example.com',
      title: 'Authenticated check',
      objective: 'Validate an authenticated endpoint.',
      parameters: 'password=do-not-send',
    );

    expect(
      request.validateAgainst(targets),
      contains(
        'Do not place passwords, tokens, cookies, private keys, or session secrets '
        'in spot-test parameters. Use appliance-local authenticated access.',
      ),
    );
  });

  test('spot test rejects bearer headers and JWT-like values', () {
    for (final parameters in [
      'Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456',
      'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue',
    ]) {
      final request = TargetedTestRequest(
        targetId: 7,
        targetAddress: 'app.example.com',
        title: 'Sensitive check',
        objective: 'Validate one endpoint.',
        parameters: parameters,
      );
      expect(request.validateAgainst(targets), isNotEmpty);
    }
  });
}

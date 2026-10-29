import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/supervised_validation_planner.dart';
import 'package:llmtary/services/supervised_validation_policy.dart';

void main() {
  const authorization = SupervisedValidationAuthorization(
    engagementReference: 'ENG-PLAN-1',
    observingOperator: 'operator-1',
    sourceAddress: '172.16.2.5',
    destinationAddress: '172.17.2.8',
    expiresAt: '2026-10-29T20:00:00Z',
    maximumHopCount: 1,
  );

  test(
    'AI planner emits one bounded exact action for human approval',
    () async {
      String? capturedPrompt;
      final planner = SupervisedValidationPlanner(
        askModel: (prompt) async {
          capturedPrompt = prompt;
          return '''{
          "action_id":"action-1",
          "rationale":"Confirm the remote execution identity",
          "expected_evidence":"hostname output",
          "remote_command":"hostname",
          "use_authorized_hop":true,
          "changes_state":false,
          "reversible":false,
          "destructive":false,
          "reads_secrets":false,
          "bypasses_mfa":false,
          "creates_persistence":false,
          "starts_listener":false,
          "escalates_privileges":false,
          "cleanup_actions":[],
          "cleanup_verification":""
        }''';
        },
      );

      final proposal = await planner.proposeNext(
        authorization: authorization,
        priorSanitizedEvents: const ['session started'],
      );

      expect(proposal.remoteCommand, 'hostname');
      expect(proposal.action.hopCount, 1);
      expect(proposal.action.sourceAddress, '172.16.2.5');
      expect(proposal.action.destinationAddress, '172.17.2.8');
      expect(capturedPrompt, contains('human must approve the exact action'));
      expect(capturedPrompt, contains('Never request or emit credentials'));
      expect(capturedPrompt, contains('hostname, whoami, id, uname, pwd'));
    },
  );

  test(
    'planner sanitizes authorization labels before model dispatch',
    () async {
      String? capturedPrompt;
      final planner = SupervisedValidationPlanner(
        askModel: (prompt) async {
          capturedPrompt = prompt;
          return '''{
          "action_id":"action-1",
          "rationale":"Confirm hostname",
          "expected_evidence":"hostname output",
          "remote_command":"hostname",
          "use_authorized_hop":false,
          "changes_state":false,
          "reversible":false,
          "destructive":false,
          "reads_secrets":false,
          "bypasses_mfa":false,
          "creates_persistence":false,
          "starts_listener":false,
          "escalates_privileges":false,
          "cleanup_actions":[],
          "cleanup_verification":""
        }''';
        },
      );
      await planner.proposeNext(
        authorization: const SupervisedValidationAuthorization(
          engagementReference: 'password=should-not-leak',
          observingOperator: 'token=operator-secret',
          sourceAddress: '172.16.2.5',
          destinationAddress: '172.17.2.8',
          expiresAt: '2026-10-29T20:00:00Z',
        ),
        priorSanitizedEvents: const ['password=event-secret'],
      );
      expect(capturedPrompt, isNot(contains('should-not-leak')));
      expect(capturedPrompt, isNot(contains('operator-secret')));
      expect(capturedPrompt, isNot(contains('event-secret')));
    },
  );

  test('AI planner rejects secret-bearing or malformed proposals', () async {
    for (final response in [
      '{"action_id":"a","rationale":"x","expected_evidence":"x","remote_command":"echo password=Secret123!","use_authorized_hop":false}',
      '{"action_id":"a","rationale":"x","expected_evidence":"x","remote_command":"hostname; whoami","use_authorized_hop":false}',
      'not json',
    ]) {
      final planner = SupervisedValidationPlanner(
        askModel: (_) async => response,
      );
      await expectLater(
        planner.proposeNext(
          authorization: authorization,
          priorSanitizedEvents: const [],
        ),
        throwsFormatException,
      );
    }
  });
}

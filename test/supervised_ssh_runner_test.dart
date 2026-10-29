import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/supervised_ssh_runner.dart';
import 'package:llmtary/services/supervised_validation_policy.dart';

void main() {
  const authorization = SupervisedValidationAuthorization(
    engagementReference: 'ENG-SSH-1',
    observingOperator: 'operator-1',
    sourceAddress: '172.16.2.5',
    destinationAddress: '172.17.2.8',
    expiresAt: '2026-10-29T20:00:00Z',
    maximumHopCount: 1,
  );

  test('builds direct SSH as fixed arguments without a shell', () {
    final invocation = SupervisedSshRunner.buildInvocation(
      authorization: authorization,
      request: const SupervisedSshRequest(
        destinationUser: 'tester',
        destinationKeyPath: '/home/llmtary/.ssh/destination_key',
        knownHostsPath: '/home/llmtary/.ssh/known_hosts',
        remoteCommand: 'hostname',
      ),
    );

    expect(invocation.executable, 'ssh');
    expect(invocation.runInShell, isFalse);
    expect(
      invocation.arguments,
      containsAll([
        '-o',
        'BatchMode=yes',
        '-o',
        'StrictHostKeyChecking=yes',
        '-o',
        'UserKnownHostsFile=/home/llmtary/.ssh/known_hosts',
        '-i',
        '/home/llmtary/.ssh/destination_key',
        'tester@172.17.2.8',
        'hostname',
      ]),
    );
  });

  test('builds exactly one authorized ProxyJump hop', () {
    final invocation = SupervisedSshRunner.buildInvocation(
      authorization: authorization,
      request: const SupervisedSshRequest(
        destinationUser: 'tester',
        destinationKeyPath: '/home/llmtary/.ssh/destination_key',
        sourceUser: 'pivot-user',
        knownHostsPath: '/home/llmtary/.ssh/known_hosts',
        remoteCommand: 'id',
        useAuthorizedHop: true,
      ),
    );

    expect(invocation.arguments, contains('-J'));
    expect(invocation.arguments, contains('pivot-user@172.16.2.5'));
    expect(invocation.arguments.where((arg) => arg == '-J'), hasLength(1));
  });

  test('rejects shell composition, destructive commands and unsafe paths', () {
    for (final command in [
      'hostname; whoami',
      'cat /etc/shadow',
      'shutdown -h now',
      'env',
      'find / -name id_rsa',
    ]) {
      expect(
        () => SupervisedSshRunner.buildInvocation(
          authorization: authorization,
          request: SupervisedSshRequest(
            destinationUser: 'tester',
            destinationKeyPath: '/home/llmtary/.ssh/destination_key',
            knownHostsPath: '/home/llmtary/.ssh/known_hosts',
            remoteCommand: command,
          ),
        ),
        throwsArgumentError,
      );
    }
    expect(
      () => SupervisedSshRunner.buildInvocation(
        authorization: authorization,
        request: const SupervisedSshRequest(
          destinationUser: 'tester',
          destinationKeyPath: '../../secret',
          knownHostsPath: '/home/llmtary/.ssh/known_hosts',
          remoteCommand: 'hostname',
        ),
      ),
      throwsArgumentError,
    );
  });

  test('allows only a bounded temporary marker state change and cleanup', () {
    for (final command in [
      'touch /tmp/llmtary-safe-ENGSSH1-action1',
      'rm -f /tmp/llmtary-safe-ENGSSH1-action1',
    ]) {
      final invocation = SupervisedSshRunner.buildInvocation(
        authorization: authorization,
        request: SupervisedSshRequest(
          destinationUser: 'tester',
          destinationKeyPath: '/home/llmtary/.ssh/destination_key',
          knownHostsPath: '/home/llmtary/.ssh/known_hosts',
          remoteCommand: command,
        ),
      );
      expect(invocation.arguments.last, command);
    }
    expect(
      () => SupervisedSshRunner.buildInvocation(
        authorization: authorization,
        request: const SupervisedSshRequest(
          destinationUser: 'tester',
          destinationKeyPath: '/home/llmtary/.ssh/destination_key',
          knownHostsPath: '/home/llmtary/.ssh/known_hosts',
          remoteCommand: 'rm -f /tmp/other-file',
        ),
      ),
      throwsArgumentError,
    );
  });

  test('never accepts password or secret material in the request contract', () {
    final fields = SupervisedSshRequest(
      destinationUser: 'tester',
      destinationKeyPath: '/home/llmtary/.ssh/destination_key',
      knownHostsPath: '/home/llmtary/.ssh/known_hosts',
      remoteCommand: 'hostname',
    ).toString();
    expect(fields.toLowerCase(), isNot(contains('password')));
    expect(fields.toLowerCase(), isNot(contains('token')));
  });
}

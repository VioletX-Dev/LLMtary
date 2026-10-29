import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path/path.dart' as p;

import '../models/candidate_closure.dart';
import '../utils/command_validator.dart';
import 'supervised_validation_policy.dart';
import 'supervised_validation_session.dart';

class SupervisedSshRequest {
  final String destinationUser;
  final String destinationKeyPath;
  final String knownHostsPath;
  final String remoteCommand;
  final String sourceUser;
  final bool useAuthorizedHop;

  const SupervisedSshRequest({
    required this.destinationUser,
    required this.destinationKeyPath,
    required this.knownHostsPath,
    required this.remoteCommand,
    this.sourceUser = '',
    this.useAuthorizedHop = false,
  });

  @override
  String toString() =>
      'SupervisedSshRequest(user=$destinationUser, keyPath=$destinationKeyPath, knownHosts=$knownHostsPath, hop=$useAuthorizedHop)';
}

class SupervisedProcessInvocation {
  final String executable;
  final List<String> arguments;
  final bool runInShell;

  const SupervisedProcessInvocation({
    required this.executable,
    required this.arguments,
    this.runInShell = false,
  });
}

class SupervisedSshRunner {
  static final RegExp _safeIdentity = RegExp(
    r'^[A-Za-z_][A-Za-z0-9_.-]{0,63}$',
  );
  static final RegExp _shellComposition = RegExp(
    r'[;&|`\n\r]|\$\(|\$\{|<\(|>\(',
  );

  static SupervisedProcessInvocation buildInvocation({
    required SupervisedValidationAuthorization authorization,
    required SupervisedSshRequest request,
  }) {
    if (!_safeIdentity.hasMatch(request.destinationUser) ||
        (request.useAuthorizedHop &&
            !_safeIdentity.hasMatch(request.sourceUser))) {
      throw ArgumentError(
        'SSH usernames must use a bounded safe identity format.',
      );
    }
    _validatePrivatePath(request.destinationKeyPath, 'private key');
    _validatePrivatePath(request.knownHostsPath, 'known-hosts file');
    final remoteCommand = request.remoteCommand.trim();
    if (remoteCommand.isEmpty || _shellComposition.hasMatch(remoteCommand)) {
      throw ArgumentError('Remote shell composition is not permitted.');
    }
    if (!_isBoundedReadOnlyCommand(remoteCommand)) {
      throw ArgumentError(
        'Only bounded identity, hostname, network-context, and service-status commands are permitted.',
      );
    }
    final validation = CommandValidator.validateMandatoryPolicy(remoteCommand);
    if (!validation.isValid || validation.shouldHardBlock) {
      throw ArgumentError(
        validation.reason.isEmpty
            ? 'The remote command failed mandatory safety validation.'
            : validation.reason,
      );
    }
    if (request.useAuthorizedHop && authorization.maximumHopCount != 1) {
      throw ArgumentError('Exactly one authorized hop is required.');
    }

    final arguments = <String>[
      '-o',
      'BatchMode=yes',
      '-o',
      'StrictHostKeyChecking=yes',
      '-o',
      'PasswordAuthentication=no',
      '-o',
      'KbdInteractiveAuthentication=no',
      '-o',
      'ConnectTimeout=15',
      '-o',
      'ServerAliveInterval=10',
      '-o',
      'ServerAliveCountMax=2',
      '-o',
      'UserKnownHostsFile=${request.knownHostsPath}',
      '-i',
      request.destinationKeyPath,
    ];
    if (request.useAuthorizedHop) {
      arguments.addAll([
        '-J',
        '${request.sourceUser}@${authorization.sourceAddress}',
      ]);
    }
    arguments.addAll([
      '${request.destinationUser}@${authorization.destinationAddress}',
      remoteCommand,
    ]);
    return SupervisedProcessInvocation(
      executable: 'ssh',
      arguments: List.unmodifiable(arguments),
    );
  }

  static Future<SupervisedActionOutput> run({
    required SupervisedValidationAuthorization authorization,
    required SupervisedSshRequest request,
    Duration timeout = const Duration(seconds: 45),
  }) async {
    final invocation = buildInvocation(
      authorization: authorization,
      request: request,
    );
    final process = await Process.start(
      invocation.executable,
      invocation.arguments,
      runInShell: false,
    );
    final stdoutFuture = process.stdout.transform(utf8.decoder).join();
    final stderrFuture = process.stderr.transform(utf8.decoder).join();
    int exitCode;
    try {
      exitCode = await process.exitCode.timeout(timeout);
    } on TimeoutException {
      process.kill(ProcessSignal.sigterm);
      await Future<void>.delayed(const Duration(milliseconds: 250));
      process.kill(ProcessSignal.sigkill);
      return const SupervisedActionOutput(
        exitCode: 124,
        sanitizedOutput: 'The bounded SSH action timed out and was terminated.',
      );
    }
    final output = ClosureSanitizer.text(
      '${await stdoutFuture}\n${await stderrFuture}',
      maxLength: 12000,
    );
    return SupervisedActionOutput(exitCode: exitCode, sanitizedOutput: output);
  }

  static bool _isBoundedReadOnlyCommand(String command) {
    final value = command.trim();
    final patterns = <RegExp>[
      RegExp(r'^hostname(?:\s+-f)?$', caseSensitive: false),
      RegExp(r'^whoami(?:\s+/all)?$', caseSensitive: false),
      RegExp(r'^id(?:\s+-[a-z]+)?$', caseSensitive: false),
      RegExp(r'^uname(?:\s+-a)?$', caseSensitive: false),
      RegExp(r'^pwd$', caseSensitive: false),
      RegExp(r'^ip\s+(?:addr|address|route)\s+show$', caseSensitive: false),
      RegExp(r'^ipconfig(?:\s+/all)?$', caseSensitive: false),
      RegExp(r'^systeminfo$', caseSensitive: false),
      RegExp(r'^ss\s+-[lntup]+$', caseSensitive: false),
      RegExp(r'^netstat\s+-(?:ano|rn)$', caseSensitive: false),
      RegExp(
        r'^touch\s+/tmp/llmtary-safe-[A-Za-z0-9_-]{1,120}$',
        caseSensitive: false,
      ),
      RegExp(
        r'^rm\s+-f\s+/tmp/llmtary-safe-[A-Za-z0-9_-]{1,120}$',
        caseSensitive: false,
      ),
      RegExp(
        r'^systemctl\s+is-active\s+[A-Za-z0-9_.@-]{1,100}$',
        caseSensitive: false,
      ),
    ];
    return patterns.any((pattern) => pattern.hasMatch(value));
  }

  static void _validatePrivatePath(String value, String label) {
    if (!p.isAbsolute(value) || p.normalize(value) != value) {
      throw ArgumentError('The $label must be a normalized absolute path.');
    }
    final allowedRoot = p.normalize('/home/llmtary/.ssh');
    if (!p.isWithin(allowedRoot, value)) {
      throw ArgumentError('The $label must remain under $allowedRoot.');
    }
  }
}

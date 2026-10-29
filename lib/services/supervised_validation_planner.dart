import 'dart:convert';

import '../models/candidate_closure.dart';
import '../utils/command_validator.dart';
import 'supervised_validation_policy.dart';

typedef SupervisedModelCall = Future<String> Function(String prompt);

class SupervisedValidationProposal {
  final SupervisedValidationAction action;
  final String rationale;
  final String expectedEvidence;
  final String remoteCommand;
  final bool useAuthorizedHop;

  const SupervisedValidationProposal({
    required this.action,
    required this.rationale,
    required this.expectedEvidence,
    required this.remoteCommand,
    required this.useAuthorizedHop,
  });
}

class SupervisedValidationPlanner {
  final SupervisedModelCall askModel;

  const SupervisedValidationPlanner({required this.askModel});

  Future<SupervisedValidationProposal> proposeNext({
    required SupervisedValidationAuthorization authorization,
    required List<String> priorSanitizedEvents,
  }) async {
    final prompt = _prompt(authorization, priorSanitizedEvents);
    final response = await askModel(prompt);
    return parseProposal(response, authorization);
  }

  static SupervisedValidationProposal parseProposal(
    String response,
    SupervisedValidationAuthorization authorization,
  ) {
    final start = response.indexOf('{');
    final end = response.lastIndexOf('}');
    if (start < 0 || end <= start) {
      throw const FormatException(
        'The AI response did not contain one JSON action.',
      );
    }
    late Map<String, dynamic> data;
    try {
      data = Map<String, dynamic>.from(
        jsonDecode(response.substring(start, end + 1)) as Map,
      );
    } catch (_) {
      throw const FormatException('The AI action JSON was malformed.');
    }

    String requiredText(String key, {int maxLength = 1000}) {
      final value = ClosureSanitizer.text(data[key], maxLength: maxLength);
      if (value.isEmpty) throw FormatException('$key is required.');
      return value;
    }

    bool flag(String key) => data[key] == true;
    final actionId = requiredText('action_id', maxLength: 120);
    final rationale = requiredText('rationale');
    final expectedEvidence = requiredText('expected_evidence');
    final remoteCommand = requiredText('remote_command', maxLength: 1000);
    final secretPattern = RegExp(
      r'(?:password|passwd|token|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*\S+',
      caseSensitive: false,
    );
    if (secretPattern.hasMatch(response)) {
      throw const FormatException(
        'AI proposals must never contain secret material.',
      );
    }
    if (RegExp(r'[;&|`\n\r]|\$\(|\$\{|<\(|>\(').hasMatch(remoteCommand)) {
      throw const FormatException('Shell composition is not permitted.');
    }
    final validation = CommandValidator.validateMandatoryPolicy(remoteCommand);
    if (!validation.isValid || validation.shouldHardBlock) {
      throw FormatException(validation.reason);
    }

    final useHop = flag('use_authorized_hop');
    final cleanupRaw = data['cleanup_actions'];
    final cleanupActions = cleanupRaw is List
        ? ClosureSanitizer.list(cleanupRaw)
        : const <String>[];
    return SupervisedValidationProposal(
      rationale: rationale,
      expectedEvidence: expectedEvidence,
      remoteCommand: remoteCommand,
      useAuthorizedHop: useHop,
      action: SupervisedValidationAction(
        actionId: actionId,
        exactAction: remoteCommand,
        sourceAddress: authorization.sourceAddress,
        destinationAddress: authorization.destinationAddress,
        hopCount: useHop ? 1 : 0,
        opensRemoteSession: true,
        changesState: flag('changes_state'),
        reversible: flag('reversible'),
        destructive: flag('destructive'),
        readsSecrets: flag('reads_secrets'),
        bypassesMfa: flag('bypasses_mfa'),
        createsPersistence: flag('creates_persistence'),
        startsListener: flag('starts_listener'),
        escalatesPrivileges: flag('escalates_privileges'),
        cleanupActions: cleanupActions,
        cleanupVerification: ClosureSanitizer.text(
          data['cleanup_verification'],
          maxLength: 1000,
        ),
      ),
    );
  }

  static String _prompt(
    SupervisedValidationAuthorization authorization,
    List<String> priorSanitizedEvents,
  ) =>
      '''You are planning exactly one next action for a human-supervised, AI-operated validation session.
The human must approve the exact action before execution. Do not imply approval.
Authorized source: ${authorization.sourceAddress}
Authorized destination: ${authorization.destinationAddress}
Maximum hop count: ${authorization.maximumHopCount}
Authorization reference: ${ClosureSanitizer.text(authorization.engagementReference, maxLength: 300)}

Never request or emit credentials, passwords, hashes, tokens, cookies, keys, MFA values, or session secrets.
Never propose destructive actions, persistence, credential dumping, MFA bypass, external callbacks/listeners, shell composition, unbounded tunnels, or movement beyond the exact authorized pair and one hop.
Prefer read-only identity, hostname, network-context, service-status, and access-boundary checks. Allowed remote command families are: hostname, whoami, id, uname, pwd, ip addr show, ip route show, ipconfig, systeminfo, bounded ss/netstat, and systemctl is-active. The only permitted state change is a temporary marker at /tmp/llmtary-safe-<bounded-id>, created with touch and removed with rm -f. If that marker is used, mark changes_state=true and supply the exact remove command in cleanup_actions plus cleanup_verification. The deterministic policy may still reject it.
Return one JSON object only with: action_id, rationale, expected_evidence, remote_command, use_authorized_hop, changes_state, reversible, destructive, reads_secrets, bypasses_mfa, creates_persistence, starts_listener, escalates_privileges, cleanup_actions, cleanup_verification.

Prior sanitized events:
${priorSanitizedEvents.take(20).map((event) => ClosureSanitizer.text(event, maxLength: 1000)).join('\n')}''';
}

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/safe_capability_mapper.dart';

void main() {
  test('maps password attacks to policy and exposure analysis', () {
    final guidance = SafeCapabilityMapper.guidanceFor(
      'Password spraying weakness',
      'No lockout controls detected',
    );

    expect(guidance, contains('PASSWORD SECURITY — SAFE EQUIVALENT'));
    expect(guidance, contains('account and lockout policy'));
    expect(guidance, contains('Never guess, spray, brute-force, or crack'));
  });

  test('maps payload and shell findings to one-shot proof only', () {
    final guidance = SafeCapabilityMapper.guidanceFor(
      'Remote code execution permits reverse shell payload',
      'Potential command injection',
    );

    expect(guidance, contains('PAYLOADS AND SHELLS — SAFE EQUIVALENT'));
    expect(guidance, contains('one-shot harmless marker'));
    expect(guidance, contains('Never deploy a payload or establish a shell'));
  });

  test('maps privilege escalation to configuration evidence and handoff', () {
    final guidance = SafeCapabilityMapper.guidanceFor(
      'Linux privilege escalation',
      'Potential sudo misconfiguration',
    );

    expect(guidance, contains('PRIVILEGE ESCALATION — SAFE EQUIVALENT'));
    expect(guidance, contains('read-only configuration evidence'));
    expect(guidance, contains('Never elevate privileges'));
  });

  test('maps credential dumping to control and exposure validation', () {
    final guidance = SafeCapabilityMapper.guidanceFor(
      'Credential dumping opportunity',
      'LSASS protections unknown',
    );

    expect(guidance, contains('CREDENTIAL DUMPING — SAFE EQUIVALENT'));
    expect(guidance, contains('protection-state metadata'));
    expect(guidance, contains('Never read credential stores'));
  });

  test('maps tunneling and pivoting to reachability path modeling', () {
    final guidance = SafeCapabilityMapper.guidanceFor(
      'Internal network pivot via SSH tunnel',
      'Multiple network segments',
    );

    expect(guidance, contains('TUNNELING AND PIVOTING — SAFE EQUIVALENT'));
    expect(guidance, contains('existing route and reachability metadata'));
    expect(guidance, contains('Never create a tunnel or proxy'));
  });

  test('maps lateral movement to non-authenticating attack-path analysis', () {
    final guidance = SafeCapabilityMapper.guidanceFor(
      'Active Directory lateral movement',
      'SMB and WinRM are exposed',
    );

    expect(guidance, contains('LATERAL MOVEMENT — SAFE EQUIVALENT'));
    expect(guidance, contains('service exposure and trust relationships'));
    expect(guidance, contains('Never authenticate to another host'));
  });

  test('combines applicable domains without emitting raw input', () {
    final guidance = SafeCapabilityMapper.guidanceFor(
      'Privilege escalation and lateral movement',
      'password=[REDACTED]',
    );

    expect(guidance, contains('PRIVILEGE ESCALATION — SAFE EQUIVALENT'));
    expect(guidance, contains('LATERAL MOVEMENT — SAFE EQUIVALENT'));
    expect(guidance, isNot(contains('password=[REDACTED]')));
  });
}

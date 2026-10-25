/// Maps offensive competency domains to bounded, non-destructive evidence work.
///
/// This mapper never returns the supplied finding text. It uses the text only
/// for local classification, preventing descriptions or secrets from being
/// copied into the static safety guidance sent to a model.
class SafeCapabilityMapper {
  static String guidanceFor(String title, String description) {
    final text = '$title $description'.toLowerCase();
    final sections = <String>[];

    if (_containsAny(text, const [
      'password attack',
      'password spray',
      'brute force',
      'bruteforce',
      'password crack',
      'weak password',
      'lockout',
    ])) {
      sections.add(_passwordSecurity);
    }

    if (_containsAny(text, const [
      'payload',
      'reverse shell',
      'bind shell',
      'web shell',
      'remote code execution',
      'command injection',
      ' rce',
    ])) {
      sections.add(_payloadsAndShells);
    }

    if (_containsAny(text, const [
      'privilege escalation',
      'priv esc',
      'privesc',
      'sudo misconfiguration',
      'suid',
      'token impersonation',
    ])) {
      sections.add(_privilegeEscalation);
    }

    if (_containsAny(text, const [
      'credential dump',
      'credential harvest',
      'lsass',
      'sam database',
      'secretsdump',
      'mimikatz',
    ])) {
      sections.add(_credentialDumping);
    }

    if (_containsAny(text, const [
      'tunnel',
      'pivot',
      'port forward',
      'proxychains',
      'chisel',
    ])) {
      sections.add(_tunnelingAndPivoting);
    }

    if (_containsAny(text, const [
      'lateral movement',
      'pass-the-hash',
      'pass the hash',
      'winrm',
      'remote service execution',
    ])) {
      sections.add(_lateralMovement);
    }

    if (sections.isEmpty) return '';

    return '''
## CONTROLLED NON-DESTRUCTIVE OFFENSIVE-CAPABILITY EQUIVALENTS:
${sections.join('\n\n')}

For these domains, report three separate facts: (1) what read-only evidence was observed, (2) what attack path that evidence could enable, and (3) which prohibited human-led action would be required for full impact validation. If the safe equivalent cannot establish the claim, conclude UNDETERMINED with `[blocked_by_safety_policy]`; never convert theoretical impact into a confirmed finding.
'''.trim();
  }

  static bool _containsAny(String text, List<String> terms) =>
      terms.any(text.contains);

  static const _passwordSecurity = '''
### PASSWORD SECURITY — SAFE EQUIVALENT
- Inspect account and lockout policy, authentication controls, MFA coverage, password-policy metadata, rate-limit behavior, and evidence of default/example credentials in public configuration.
- Validate only with operator-provided authenticated state and read-only requests.
- Never guess, spray, brute-force, or crack passwords or hashes.''';

  static const _payloadsAndShells = '''
### PAYLOADS AND SHELLS — SAFE EQUIVALENT
- Verify prerequisites, affected code paths, framework check results, and—only where policy permits—a one-shot harmless marker such as `id`, `whoami`, or `hostname`; stop immediately after proof.
- Document the access level a successful payload or shell could provide without creating a session.
- Never deploy a payload or establish a shell, listener, callback, or interactive session.''';

  static const _privilegeEscalation = '''
### PRIVILEGE ESCALATION — SAFE EQUIVALENT
- Collect only read-only configuration evidence already exposed to the approved context, such as effective identity, advertised permissions, service configuration, ACL metadata, patch state, and public policy settings.
- Model the prerequisite-to-impact path and identify the exact human validation handoff.
- Never elevate privileges, alter permissions, execute privileged helpers, or access protected data.''';

  static const _credentialDumping = '''
### CREDENTIAL DUMPING — SAFE EQUIVALENT
- Evaluate protection-state metadata, exposed backup/configuration indicators, credential-store hardening, process protection, and least-privilege boundaries without reading secret material.
- Report the class and potential blast radius of credentials that could be exposed, never their values.
- Never read credential stores, process memory, password databases, hashes, tokens, cookies, or private keys.''';

  static const _tunnelingAndPivoting = '''
### TUNNELING AND PIVOTING — SAFE EQUIVALENT
- Use existing route and reachability metadata, firewall/ACL evidence, service exposure, network-interface metadata, and approved architecture information to model reachable segments.
- Describe the hypothetical pivot path and its prerequisites without crossing a trust boundary.
- Never create a tunnel or proxy, add routes, forward ports, or send traffic through a compromised host.''';

  static const _lateralMovement = '''
### LATERAL MOVEMENT — SAFE EQUIVALENT
- Analyze service exposure and trust relationships, SMB signing, remote-management posture, delegation/ACL metadata, segmentation, and operator-authorized directory metadata.
- Build a non-executed attack path with prerequisites, likely destination, detection opportunities, and a human validation handoff.
- Never authenticate to another host, replay credentials, execute remote services, relay authentication, or move between systems.''';
}

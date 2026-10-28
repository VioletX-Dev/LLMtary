import '../models/vulnerability.dart';

enum ClaimFamily {
  httpHeaders,
  cookies,
  hsts,
  tls,
  dnsRecursion,
  dnsZoneTransfer,
  ntpMode6,
  rdpNla,
  smbCveExposure,
  emailPolicy,
  ldap,
  webDav,
  configurationExposure,
  ssrf,
  accountSecurity,
  icsObservation,
  commandExecution,
  generic,
}

enum EvidenceOutcome { supportsClaim, rejectsClaim, insufficient }

class EvidenceObservation {
  final String methodId;
  final String output;
  final int exitCode;
  const EvidenceObservation({
    required this.methodId,
    required this.output,
    required this.exitCode,
  });
}

class EvidenceContract {
  final ClaimFamily family;
  final List<String> prerequisites;
  final List<String> safeMethodIds;
  final List<String> prohibitedMethods;
  final EvidenceOutcome Function(EvidenceObservation) evaluator;

  const EvidenceContract({
    required this.family,
    required this.prerequisites,
    required this.safeMethodIds,
    required this.prohibitedMethods,
    required this.evaluator,
  });

  EvidenceOutcome evaluate(EvidenceObservation observation) =>
      evaluator(observation);
}

class EvidenceContractRegistry {
  const EvidenceContractRegistry._();

  static EvidenceContract forCandidate(Vulnerability candidate) {
    final text =
        '${candidate.problem} ${candidate.description} ${candidate.vulnerabilityType}'
            .toLowerCase();
    if (text.contains('x-frame-options') || text.contains('security header')) {
      return _httpHeader;
    }
    if (text.contains('cookie') ||
        text.contains('httponly') ||
        text.contains('secure flag')) {
      return _cookie;
    }
    if (text.contains('hsts') || text.contains('strict-transport-security')) {
      return _hsts;
    }
    if (text.contains('tls') ||
        text.contains('ssl') ||
        text.contains('cipher')) {
      return _tls;
    }
    if (text.contains('dns') && text.contains('recursion')) {
      return _dnsRecursion;
    }
    if (text.contains('zone transfer') || text.contains('axfr')) {
      return _dnsAxfr;
    }
    if (text.contains('ntp') ||
        text.contains('mode 6') ||
        text.contains('readvar')) {
      return _ntp;
    }
    if (text.contains('rdp') ||
        text.contains('nla') ||
        text.contains('credssp')) {
      return _rdp;
    }
    if (text.contains('smb') ||
        text.contains('eternalblue') ||
        text.contains('ms17-010')) {
      return _smb;
    }
    if (text.contains('smtp') ||
        text.contains('spf') ||
        text.contains('dmarc')) {
      return _email;
    }
    if (text.contains('ldap')) return _ldap;
    if (text.contains('webdav')) return _webDav;
    if (text.contains('configuration file') ||
        text.contains('.env') ||
        text.contains('config exposure')) {
      return _config;
    }
    if (text.contains('ssrf') || text.contains('webhook')) return _ssrf;
    if (text.contains('lockout') ||
        text.contains('enumeration') ||
        text.contains('password policy')) {
      return _account;
    }
    if (text.contains('command injection') ||
        text.contains('remote code execution') ||
        RegExp(r'\brce\b').hasMatch(text)) {
      return _commandExecution;
    }
    if (text.contains('industrial control') ||
        text.contains('ics') ||
        text.contains('modbus')) {
      return _ics;
    }
    return _generic;
  }

  static EvidenceOutcome _direct(
    EvidenceObservation o,
    String method,
    List<String> rejectMarkers,
  ) {
    if (o.methodId != method || o.exitCode != 0 || o.output.trim().isEmpty) {
      return EvidenceOutcome.insufficient;
    }
    final lower = o.output.toLowerCase();
    return rejectMarkers.any(lower.contains)
        ? EvidenceOutcome.rejectsClaim
        : EvidenceOutcome.supportsClaim;
  }

  static final _httpHeader = EvidenceContract(
    family: ClaimFamily.httpHeaders,
    prerequisites: const [
      'reachable HTTP endpoint',
      'effective URL after redirects',
    ],
    safeMethodIds: const [
      'http-response-headers',
      'http-response-headers-repeat',
    ],
    prohibitedMethods: const ['generic reachability as proof'],
    evaluator: (o) {
      if (!o.methodId.startsWith('http-response-headers') ||
          o.exitCode != 0 ||
          !o.output.toUpperCase().contains('HTTP/')) {
        return EvidenceOutcome.insufficient;
      }
      final lower = o.output.toLowerCase();
      return lower.contains('x-frame-options:') ||
              lower.contains('content-security-policy:')
          ? EvidenceOutcome.rejectsClaim
          : EvidenceOutcome.supportsClaim;
    },
  );
  static final _cookie = EvidenceContract(
    family: ClaimFamily.cookies,
    prerequisites: const ['HTTP response that sets the affected cookie'],
    safeMethodIds: const [
      'http-cookie-response',
      'http-cookie-response-repeat',
    ],
    prohibitedMethods: const ['session hijacking', 'cookie reuse'],
    evaluator: (o) =>
        _direct(o, 'http-cookie-response', const ['; secure', '; httponly']),
  );
  static final _hsts = EvidenceContract(
    family: ClaimFamily.hsts,
    prerequisites: const ['reachable HTTPS endpoint'],
    safeMethodIds: const ['https-hsts-header', 'https-hsts-header-repeat'],
    prohibitedMethods: const ['traffic interception'],
    evaluator: (o) =>
        _direct(o, 'https-hsts-header', const ['strict-transport-security:']),
  );
  static final _tls = EvidenceContract(
    family: ClaimFamily.tls,
    prerequisites: const ['target port', 'SNI when required'],
    safeMethodIds: const ['tls-protocol-negotiation', 'tls-cipher-negotiation'],
    prohibitedMethods: const ['failed handshake as proof'],
    evaluator: (o) {
      if (!o.methodId.startsWith('tls-') || o.exitCode != 0) {
        return EvidenceOutcome.insufficient;
      }
      final lower = o.output.toLowerCase();
      if (lower.contains('handshake failure') ||
          lower.contains('no cipher match')) {
        return EvidenceOutcome.rejectsClaim;
      }
      return lower.contains('protocol') && lower.contains('cipher')
          ? EvidenceOutcome.supportsClaim
          : EvidenceOutcome.insufficient;
    },
  );
  static final _dnsRecursion = EvidenceContract(
    family: ClaimFamily.dnsRecursion,
    prerequisites: const [
      'resolver address',
      'query for non-authoritative external name',
      'source trust context',
    ],
    safeMethodIds: const ['dns-external-recursion-query'],
    prohibitedMethods: const ['high-volume DNS queries'],
    evaluator: (o) => _direct(o, 'dns-external-recursion-query', const [
      'recursion requested but not available',
      'refused',
    ]),
  );
  static final _dnsAxfr = EvidenceContract(
    family: ClaimFamily.dnsZoneTransfer,
    prerequisites: const [
      'authoritative zone name',
      'in-scope authoritative server',
    ],
    safeMethodIds: const ['dns-axfr-single-query'],
    prohibitedMethods: const ['third-party provider testing without scope'],
    evaluator: (o) => _direct(o, 'dns-axfr-single-query', const [
      'transfer failed',
      'refused',
      'not authoritative',
    ]),
  );
  static final _ntp = EvidenceContract(
    family: ClaimFamily.ntpMode6,
    prerequisites: const ['reachable UDP/123'],
    safeMethodIds: const ['ntp-mode6-readvar'],
    prohibitedMethods: const ['amplification or flooding'],
    evaluator: (o) => _direct(o, 'ntp-mode6-readvar', const [
      'permission denied',
      'timed out',
    ]),
  );
  static final _rdp = EvidenceContract(
    family: ClaimFamily.rdpNla,
    prerequisites: const ['reachable RDP endpoint'],
    safeMethodIds: const ['rdp-security-negotiation'],
    prohibitedMethods: const ['credential guessing', 'interactive session'],
    evaluator: (o) => _direct(o, 'rdp-security-negotiation', const [
      'nla required',
      'credssp required',
    ]),
  );
  static final _smb = EvidenceContract(
    family: ClaimFamily.smbCveExposure,
    prerequisites: const [
      'reachable SMB endpoint',
      'claim-specific safe check',
    ],
    safeMethodIds: const ['smb-protocol-metadata', 'smb-safe-cve-check'],
    prohibitedMethods: const [
      'payload deployment',
      'interactive shell',
      'credential relay',
    ],
    evaluator: (o) => o.methodId == 'smb-safe-cve-check' && o.exitCode == 0
        ? (o.output.toLowerCase().contains('not vulnerable')
              ? EvidenceOutcome.rejectsClaim
              : EvidenceOutcome.supportsClaim)
        : EvidenceOutcome.insufficient,
  );
  static final _email = EvidenceContract(
    family: ClaimFamily.emailPolicy,
    prerequisites: const ['client-owned domain'],
    safeMethodIds: const ['dns-email-policy-query', 'smtp-capability-banner'],
    prohibitedMethods: const ['email flooding', 'credential testing'],
    evaluator: (o) =>
        _direct(o, 'dns-email-policy-query', const ['v=spf1', 'v=dmarc1']),
  );
  static final _ldap = EvidenceContract(
    family: ClaimFamily.ldap,
    prerequisites: const [
      'reachable directory endpoint',
      'approved bind context when required',
    ],
    safeMethodIds: const ['ldap-rootdse-read', 'ldap-approved-bind-metadata'],
    prohibitedMethods: const ['directory dumping', 'password guessing'],
    evaluator: (o) => _direct(o, 'ldap-rootdse-read', const [
      'invalid credentials',
      'stronger auth required',
    ]),
  );
  static final _webDav = EvidenceContract(
    family: ClaimFamily.webDav,
    prerequisites: const ['exact HTTP endpoint'],
    safeMethodIds: const ['webdav-options', 'webdav-readonly-propfind'],
    prohibitedMethods: const ['file upload', 'resource modification'],
    evaluator: (o) => _direct(o, 'webdav-options', const [
      '405 method not allowed',
      '403 forbidden',
    ]),
  );
  static final _config = EvidenceContract(
    family: ClaimFamily.configurationExposure,
    prerequisites: const ['exact candidate path'],
    safeMethodIds: const ['http-benign-config-read'],
    prohibitedMethods: const ['reading secrets or private keys'],
    evaluator: (o) => _direct(o, 'http-benign-config-read', const [
      '404 not found',
      '403 forbidden',
    ]),
  );
  static final _ssrf = EvidenceContract(
    family: ClaimFamily.ssrf,
    prerequisites: const [
      'exact input location',
      'approved controlled callback',
      'authorization',
    ],
    safeMethodIds: const ['ssrf-controlled-callback-once'],
    prohibitedMethods: const [
      'cloud metadata access',
      'internal port scanning',
    ],
    evaluator: (o) => _direct(o, 'ssrf-controlled-callback-once', const [
      'no callback observed',
    ]),
  );
  static final _account = EvidenceContract(
    family: ClaimFamily.accountSecurity,
    prerequisites: const [
      'approved test account',
      'authentication endpoint',
      'maximum attempt count',
      'testing window',
    ],
    safeMethodIds: const [
      'account-policy-review',
      'bounded-approved-login-sequence',
    ],
    prohibitedMethods: const [
      'brute force',
      'password spraying',
      'unapproved account lockout',
    ],
    evaluator: (o) =>
        o.methodId == 'bounded-approved-login-sequence' && o.exitCode == 0
        ? (o.output.toLowerCase().contains('locked')
              ? EvidenceOutcome.rejectsClaim
              : EvidenceOutcome.supportsClaim)
        : EvidenceOutcome.insufficient,
  );
  static final _ics = EvidenceContract(
    family: ClaimFamily.icsObservation,
    prerequisites: const ['explicit ICS scope and safety approval'],
    safeMethodIds: const ['ics-passive-identification'],
    prohibitedMethods: const [
      'state-changing protocol command',
      'load or availability testing',
    ],
    evaluator: (_) => EvidenceOutcome.insufficient,
  );
  static final _commandExecution = EvidenceContract(
    family: ClaimFamily.commandExecution,
    prerequisites: const [
      'exact in-scope input location',
      'explicit active-testing authorization',
      'exact-command operator approval',
    ],
    safeMethodIds: const ['one-shot-benign-marker'],
    prohibitedMethods: const [
      'interactive or reverse shell',
      'payload deployment',
      'listener or callback',
      'persistence',
      'privilege elevation',
    ],
    evaluator: (o) =>
        o.methodId == 'one-shot-benign-marker' &&
            o.exitCode == 0 &&
            RegExp(r'LLMTARY_SAFE_MARKER_[A-Za-z0-9_-]+').hasMatch(o.output)
        ? EvidenceOutcome.supportsClaim
        : EvidenceOutcome.insufficient,
  );
  static final _generic = EvidenceContract(
    family: ClaimFamily.generic,
    prerequisites: const [
      'specific testable claim',
      'claim-relevant target context',
    ],
    safeMethodIds: const ['claim-specific-metadata', 'safe-framework-check'],
    prohibitedMethods: const [
      'automatic exploitation',
      'generic reachability as proof',
      'payload deployment',
    ],
    evaluator: (_) => EvidenceOutcome.insufficient,
  );
}

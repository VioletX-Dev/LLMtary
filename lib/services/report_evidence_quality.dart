import '../models/command_log.dart';
import '../models/vulnerability.dart';

class ReportEvidenceDecision {
  final bool reportable;
  final String reason;
  final CommandLog? proofLog;

  const ReportEvidenceDecision({
    required this.reportable,
    required this.reason,
    this.proofLog,
  });
}

/// Deterministic last-mile evidence gate for client-facing reports.
///
/// Assessment status alone is not enough to make a claim reportable. A final
/// finding must also have a traceable evidence source that actually supports
/// the claim. Generic or merely recent command output is never selected.
class ReportEvidenceQuality {
  static const _syntheticCommands = {
    'analysis conclusion',
    'initial evidence analysis',
  };

  static ReportEvidenceDecision evaluate(
    Vulnerability vulnerability,
    List<CommandLog> commandLogs, {
    bool hasVisualEvidence = false,
  }) {
    if (vulnerability.status != VulnerabilityStatus.confirmed) {
      return const ReportEvidenceDecision(
        reportable: false,
        reason: 'Inconclusive — not a verified vulnerability.',
      );
    }

    if (vulnerability.confidence.trim().toUpperCase() == 'LOW') {
      return const ReportEvidenceDecision(
        reportable: false,
        reason: 'Confirmed status is not reportable with low-confidence evidence.',
      );
    }

    final command = vulnerability.proofCommand?.trim() ?? '';
    final normalizedCommand = _normalizeCommand(command);
    final isInitialEvidence = normalizedCommand == 'initial evidence analysis';
    final isSynthetic = _syntheticCommands.contains(normalizedCommand);
    final proofLog = isSynthetic || normalizedCommand.isEmpty
        ? null
        : _matchingProofLog(vulnerability, normalizedCommand, commandLogs);

    final combinedEvidence = [
      vulnerability.evidence,
      if (proofLog != null) proofLog.output,
    ].join('\n').toLowerCase();

    if (_isAccountLockoutClaim(vulnerability)) {
      if (!_hasDirectAccountLockoutPolicyEvidence(combinedEvidence)) {
        return const ReportEvidenceDecision(
          reportable: false,
          reason:
              'No direct account-lockout policy evidence was captured; failed logins or unrelated scans cannot establish this control is absent.',
        );
      }
    }

    if (hasVisualEvidence) {
      return const ReportEvidenceDecision(
        reportable: true,
        reason: 'Verified by finding-specific visual evidence with recorded provenance.',
      );
    }

    if (proofLog != null) {
      if (proofLog.exitCode != 0 || proofLog.output.trim().isEmpty) {
        return const ReportEvidenceDecision(
          reportable: false,
          reason: 'The explicit verification command did not produce successful evidence.',
        );
      }
      if (_isTlsClaim(vulnerability) && _isFailedTlsNegotiation(proofLog.output)) {
        return const ReportEvidenceDecision(
          reportable: false,
          reason:
              'A failed TLS negotiation does not prove a TLS configuration vulnerability.',
        );
      }
      final relevanceRejection = _evidenceRelevanceRejection(
        vulnerability,
        proofLog.command,
        proofLog.output,
      );
      if (relevanceRejection != null) {
        return ReportEvidenceDecision(
          reportable: false,
          reason: relevanceRejection,
        );
      }
      return ReportEvidenceDecision(
        reportable: true,
        reason: 'Verified by an explicitly linked command and bounded output.',
        proofLog: proofLog,
      );
    }

    if (isInitialEvidence && _isDirectInitialEvidence(vulnerability)) {
      return const ReportEvidenceDecision(
        reportable: true,
        reason: 'Verified by direct, finding-specific initial evidence.',
      );
    }

    return const ReportEvidenceDecision(
      reportable: false,
      reason:
          'No explicit finding-specific proof was captured; generic command history is not evidence.',
    );
  }

  static CommandLog? _matchingProofLog(
    Vulnerability vulnerability,
    String normalizedProofCommand,
    List<CommandLog> logs,
  ) {
    final matches = logs.where((log) {
      if (vulnerability.id == null || log.vulnerabilityId != vulnerability.id) {
        return false;
      }
      return _normalizeCommand(log.command) == normalizedProofCommand;
    }).toList()
      ..sort((a, b) => b.timestamp.compareTo(a.timestamp));
    return matches.isEmpty ? null : matches.first;
  }

  static String _normalizeCommand(String command) {
    var result = command.trim();
    if (result.toUpperCase().startsWith('PROOF:')) {
      result = result.substring('PROOF:'.length).trim();
    }
    return result.replaceAll(RegExp(r'\s+'), ' ').toLowerCase();
  }

  static bool _isAccountLockoutClaim(Vulnerability vulnerability) {
    final text = '${vulnerability.problem} ${vulnerability.vulnerabilityType}'.toLowerCase();
    return text.contains('account lockout') || text.contains('lockout/rate limiting');
  }

  static bool _hasDirectAccountLockoutPolicyEvidence(String evidence) {
    if (_isAbsenceOnly(evidence)) return false;
    final hasThreshold = RegExp(r'lockout threshold\s*[:=]\s*\d+').hasMatch(evidence);
    final hasDuration = RegExp(r'lockout duration\s*[:=]\s*\d+').hasMatch(evidence);
    final hasPolicySource = evidence.contains('net accounts') ||
        evidence.contains('password policy') ||
        evidence.contains('domain policy') ||
        evidence.contains('account policy');
    return hasThreshold && hasDuration && hasPolicySource;
  }

  static bool _isTlsClaim(Vulnerability vulnerability) {
    final text = '${vulnerability.problem} ${vulnerability.vulnerabilityType}'.toLowerCase();
    return text.contains('tls') || text.contains('ssl');
  }

  static bool _isFailedTlsNegotiation(String output) {
    final text = output.toLowerCase();
    return text.contains('handshake has read 0 bytes') ||
        text.contains('cipher is (none)') ||
        text.contains('unexpected eof while reading') ||
        text.contains('no peer certificate available');
  }

  static String? _evidenceRelevanceRejection(
    Vulnerability vulnerability,
    String command,
    String output,
  ) {
    final claim = '${vulnerability.problem} ${vulnerability.vulnerabilityType}'
        .toLowerCase();
    final description = vulnerability.description.toLowerCase();
    final normalizedCommand = command.toLowerCase();
    final normalizedOutput = output.toLowerCase();
    final isNmap = RegExp(r'(^|\s|/)nmap(\s|$)').hasMatch(normalizedCommand);
    final exploitClass = claim.contains('rce') ||
        claim.contains('remote code') ||
        claim.contains('injection') ||
        claim.contains('auth bypass') ||
        claim.contains('authentication bypass') ||
        claim.contains('account enumeration') ||
        claim.contains('account lockout') ||
        claim.contains('webhook');
    if (isNmap && exploitClass) {
      return 'Network service discovery is contextual reconnaissance and cannot confirm this exploit-class claim.';
    }

    final isHeaderOrCookieClaim =
        claim.contains('header') || claim.contains('cookie');
    final isHttpResponseTool = normalizedCommand.contains('curl ') ||
        RegExp(r'(^|\s|/)nikto(\s|$)').hasMatch(normalizedCommand) ||
        normalizedCommand.contains('wget ') ||
        RegExp(r'(^|\s|/)httpx(\s|$)').hasMatch(normalizedCommand);
    if (isHeaderOrCookieClaim && !isHttpResponseTool) {
      return 'This HTTP control requires a captured HTTP response; service discovery output is not finding-specific evidence.';
    }

    final isDig = RegExp(r'(^|\s|/)dig(\s|$)').hasMatch(normalizedCommand);
    if (isDig && !claim.contains('dns') && !claim.contains('domain')) {
      return 'DNS query output is not relevant evidence for this finding type.';
    }
    final claimsExternalDnsExposure = isDig &&
        (description.contains('from outside') ||
            description.contains('external attacker') ||
            description.contains('externally exploitable'));
    final hasExternalVantageProvenance =
        normalizedOutput.contains('source vantage: external') ||
            normalizedOutput.contains('test vantage: external') ||
            normalizedOutput.contains('external vantage verified');
    if (claimsExternalDnsExposure && !hasExternalVantageProvenance) {
      return 'The DNS response proves recursion from the assessment network, not exposure from an external vantage.';
    }

    final isTlsTool = normalizedCommand.contains('openssl s_client') ||
        normalizedCommand.contains('testssl') ||
        normalizedCommand.contains('sslscan');
    if (isTlsTool && !_isTlsClaim(vulnerability)) {
      return 'TLS probe output is not relevant evidence for this finding type.';
    }
    return null;
  }

  static bool _isDirectInitialEvidence(Vulnerability vulnerability) {
    final evidence = vulnerability.evidence.trim().toLowerCase();
    if (evidence.isEmpty || _isAbsenceOnly(evidence)) return false;

    final claim = '${vulnerability.problem} ${vulnerability.vulnerabilityType}'.toLowerCase();
    if (claim.contains('header') || claim.contains('cookie')) {
      return evidence.contains('http response') ||
          evidence.contains('response headers') ||
          evidence.contains('nikto');
    }
    if (claim.contains('ntp')) {
      return evidence.contains('query') && evidence.contains('returned');
    }
    return evidence.contains('returned') ||
        evidence.contains('demonstrated') ||
        evidence.contains('observed') ||
        evidence.contains('responded') ||
        evidence.contains('successful');
  }

  static bool _isAbsenceOnly(String evidence) {
    return evidence.contains('no evidence of') ||
        evidence.contains('does not indicate') ||
        evidence.contains('not indicate') ||
        evidence.contains('potentially') ||
        evidence.contains('suggesting that') ||
        evidence.contains('could allow');
  }
}

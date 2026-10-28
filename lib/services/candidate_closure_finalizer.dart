import '../models/candidate_closure.dart';
import '../models/command_log.dart';
import '../models/vulnerability.dart';
import 'evidence_contract_registry.dart';
import 'legacy_closure_mapper.dart';
import 'report_evidence_quality.dart';

/// Converts execution results into defensible candidate closure records.
/// Legacy status labels are never sufficient by themselves for verified
/// findings or negatives: direct, linked and claim-relevant evidence is
/// required.
class CandidateClosureFinalizer {
  const CandidateClosureFinalizer._();

  static CandidateClosure finalize(
    Vulnerability candidate,
    List<CommandLog> commandLogs, {
    DateTime? now,
    bool hasVisualEvidence = false,
    int? projectId,
  }) {
    final timestamp = (now ?? DateTime.now()).toUtc();
    final effectiveProjectId = projectId ?? candidate.projectId ?? 0;
    final relevantLogs = commandLogs
        .where(
          (log) => candidate.id != null && log.vulnerabilityId == candidate.id,
        )
        .toList(growable: false);
    final contract = EvidenceContractRegistry.forCandidate(candidate);
    final observations = <_ClassifiedObservation>[];
    for (final log in relevantLogs) {
      final methodId = _SafeMethodClassifier.classify(
        log.command,
        contract.family,
      );
      if (methodId == null || !contract.safeMethodIds.contains(methodId)) {
        continue;
      }
      observations.add(
        _ClassifiedObservation(
          methodId: methodId,
          outcome: contract.evaluate(
            EvidenceObservation(
              methodId: methodId,
              output: log.output,
              exitCode: log.exitCode,
            ),
          ),
        ),
      );
    }

    if (candidate.status == VulnerabilityStatus.confirmed) {
      final decision = ReportEvidenceQuality.evaluate(
        candidate,
        relevantLogs,
        hasVisualEvidence: hasVisualEvidence,
      );
      if (decision.reportable) {
        return _verified(
          candidate,
          timestamp,
          CandidateDisposition.verifiedFinding,
          ClosureReasonCode.directEvidenceVerified,
          decision.reason,
          observations,
          effectiveProjectId,
        );
      }
      return _unsupported(
        candidate,
        timestamp,
        decision.reason,
        observations,
        effectiveProjectId,
      );
    }

    if (candidate.status == VulnerabilityStatus.notVulnerable) {
      if (observations.any(
        (observation) => observation.outcome == EvidenceOutcome.rejectsClaim,
      )) {
        return _verified(
          candidate,
          timestamp,
          CandidateDisposition.verifiedNegative,
          ClosureReasonCode.rejectingEvidenceVerified,
          'A linked claim-specific observation rejected the hypothesis.',
          observations,
          effectiveProjectId,
        );
      }
      return _unsupported(
        candidate,
        timestamp,
        'The negative status lacks linked claim-specific rejecting evidence.',
        observations,
        effectiveProjectId,
      );
    }

    final mapped = LegacyClosureMapper.map(
      candidate,
      now: timestamp,
      projectId: effectiveProjectId,
    );
    return mapped.copyWith(
      attemptedMethods: observations
          .map((value) => value.methodId)
          .toSet()
          .toList(),
      successfulObservations: _summaries(
        observations,
        EvidenceOutcome.supportsClaim,
      ),
      failedObservations: _summaries(
        observations,
        EvidenceOutcome.insufficient,
      ),
      requestsUsed: relevantLogs.length,
      toolsUsed: observations.map((value) => value.methodId).toSet().length,
    );
  }

  static CandidateClosure _verified(
    Vulnerability candidate,
    DateTime timestamp,
    CandidateDisposition disposition,
    ClosureReasonCode reasonCode,
    String explanation,
    List<_ClassifiedObservation> observations,
    int projectId,
  ) => CandidateClosure(
    vulnerabilityId: candidate.id ?? 0,
    projectId: projectId,
    disposition: disposition,
    reasonCode: reasonCode,
    explanation: explanation,
    attemptedMethods: observations
        .map((value) => value.methodId)
        .toSet()
        .toList(),
    successfulObservations: disposition == CandidateDisposition.verifiedFinding
        ? _summaries(observations, EvidenceOutcome.supportsClaim)
        : _summaries(observations, EvidenceOutcome.rejectsClaim),
    failedObservations: _summaries(observations, EvidenceOutcome.insufficient),
    requestsUsed: observations.length,
    toolsUsed: observations.map((value) => value.methodId).toSet().length,
    stoppingReason: reasonCode.name,
    startedAt: candidate.confirmedAt?.toUtc() ?? timestamp,
    updatedAt: timestamp,
  );

  static CandidateClosure _unsupported(
    Vulnerability candidate,
    DateTime timestamp,
    String explanation,
    List<_ClassifiedObservation> observations,
    int projectId,
  ) => CandidateClosure(
    vulnerabilityId: candidate.id ?? 0,
    projectId: projectId,
    disposition: CandidateDisposition.pendingCustomerClarification,
    reasonCode: ClosureReasonCode.customerClarificationRequired,
    explanation: explanation,
    attemptedMethods: observations
        .map((value) => value.methodId)
        .toSet()
        .toList(),
    successfulObservations: _summaries(
      observations,
      EvidenceOutcome.supportsClaim,
    ),
    failedObservations: _summaries(observations, EvidenceOutcome.insufficient),
    remainingPrerequisites: const ['finding-specific evidence review'],
    nextAction:
        'Review or requeue the candidate for a claim-specific bounded verification method.',
    owner: WorkOwner.operator,
    requestsUsed: observations.length,
    toolsUsed: observations.map((value) => value.methodId).toSet().length,
    stoppingReason: 'evidence_contract_not_satisfied',
    startedAt: candidate.confirmedAt?.toUtc() ?? timestamp,
    updatedAt: timestamp,
  );

  static List<String> _summaries(
    List<_ClassifiedObservation> observations,
    EvidenceOutcome outcome,
  ) => observations
      .where((value) => value.outcome == outcome)
      .map((value) => '${value.methodId}: ${value.outcome.name}')
      .toSet()
      .toList(growable: false);
}

class _ClassifiedObservation {
  final String methodId;
  final EvidenceOutcome outcome;
  const _ClassifiedObservation({required this.methodId, required this.outcome});
}

class _SafeMethodClassifier {
  const _SafeMethodClassifier._();

  static String? classify(String command, ClaimFamily family) {
    final original = command.trim();
    final value = original.toLowerCase();
    if (value.isEmpty) return null;
    final isCurl = RegExp(r'(^|\s|/)curl(\s|$)').hasMatch(value);
    final requestsHeaders =
        RegExp(r'(^|\s)-(?:I|D)(?:\s|$)').hasMatch(original) ||
        value.contains(' --head');
    switch (family) {
      case ClaimFamily.httpHeaders:
        return isCurl && requestsHeaders ? 'http-response-headers' : null;
      case ClaimFamily.cookies:
        return isCurl ? 'http-cookie-response' : null;
      case ClaimFamily.hsts:
        return isCurl && value.contains('https://')
            ? 'https-hsts-header'
            : null;
      case ClaimFamily.tls:
        return value.contains('openssl s_client') ||
                value.contains('testssl') ||
                value.contains('sslscan')
            ? 'tls-protocol-negotiation'
            : null;
      case ClaimFamily.dnsRecursion:
        return RegExp(r'(^|\s|/)dig(\s|$)').hasMatch(value)
            ? 'dns-external-recursion-query'
            : null;
      case ClaimFamily.dnsZoneTransfer:
        return RegExp(r'(^|\s|/)dig(\s|$)').hasMatch(value) &&
                value.contains('axfr')
            ? 'dns-axfr-single-query'
            : null;
      case ClaimFamily.ntpMode6:
        return value.contains('ntpq') || value.contains('ntp-info')
            ? 'ntp-mode6-readvar'
            : null;
      case ClaimFamily.rdpNla:
        return value.contains('rdp-enum-encryption') ||
                value.contains('rdp-sec-check')
            ? 'rdp-security-negotiation'
            : null;
      case ClaimFamily.smbCveExposure:
        return value.contains('smb-vuln') ||
                value.contains('smb2-security-mode')
            ? 'smb-safe-cve-check'
            : null;
      case ClaimFamily.emailPolicy:
        return RegExp(r'(^|\s|/)dig(\s|$)').hasMatch(value) &&
                value.contains(' txt')
            ? 'dns-email-policy-query'
            : null;
      case ClaimFamily.ldap:
        return RegExp(r'(^|\s|/)ldapsearch(\s|$)').hasMatch(value)
            ? 'ldap-rootdse-read'
            : null;
      case ClaimFamily.webDav:
        return isCurl && value.contains('options') ? 'webdav-options' : null;
      case ClaimFamily.configurationExposure:
        return isCurl ? 'http-benign-config-read' : null;
      case ClaimFamily.ssrf:
      case ClaimFamily.accountSecurity:
      case ClaimFamily.icsObservation:
        return null;
      case ClaimFamily.commandExecution:
        final isBoundedHttpRequest = RegExp(
          r'^(?:timeout\s+\d+\s+)?curl\s',
        ).hasMatch(value);
        return isBoundedHttpRequest && value.contains('llmtary_safe_marker_')
            ? 'one-shot-benign-marker'
            : null;
      case ClaimFamily.generic:
        return null;
    }
  }
}

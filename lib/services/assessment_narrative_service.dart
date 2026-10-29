import 'dart:convert';

import '../models/command_log.dart';
import '../models/target.dart';
import '../models/vulnerability.dart';
import 'cloud_assist_service.dart';

class AssessmentTimelineEntry {
  final DateTime timestamp;
  final String phase;
  final String target;
  final String finding;
  final String action;
  final String rationale;
  final String observation;
  final String verification;
  final String result;
  final String disposition;
  final String sourceType;

  const AssessmentTimelineEntry({
    required this.timestamp,
    required this.phase,
    required this.target,
    required this.finding,
    this.action = '',
    this.rationale = '',
    this.observation = '',
    this.verification = '',
    this.result = '',
    this.disposition = '',
    required this.sourceType,
  });
}

class AssessmentNarrativeData {
  final List<AssessmentTimelineEntry> entries;
  final String prompt;

  const AssessmentNarrativeData({required this.entries, required this.prompt});
}

/// Builds report narrative inputs only from persisted assessment evidence.
///
/// The generated prose is advisory presentation. [entries] is the authoritative,
/// deterministic ledger and is always rendered alongside it in exported reports.
class AssessmentNarrativeService {
  const AssessmentNarrativeService._();

  static AssessmentNarrativeData build({
    required List<Target> targets,
    required List<Vulnerability> vulnerabilities,
    required List<CommandLog> commandLogs,
    required List<Map<String, dynamic>> sessionEvents,
    Iterable<String> sensitiveValues = const <String>[],
  }) {
    final targetById = <int, Target>{
      for (final target in targets)
        if (target.id != null) target.id!: target,
    };
    final vulnById = <int, Vulnerability>{
      for (final vulnerability in vulnerabilities)
        if (vulnerability.id != null) vulnerability.id!: vulnerability,
    };
    final entries = <AssessmentTimelineEntry>[];

    String clean(Object? value, {int maxLength = 1400}) {
      var text = CloudAssistService.redactSecrets(
        value?.toString() ?? '',
        sensitiveValues,
      ).replaceAll(RegExp(r'\x1B\[[0-?]*[ -/]*[@-~]'), '');
      text = text.replaceAll('\u0000', '').trim();
      if (text.length > maxLength) {
        text = '${text.substring(0, maxLength)}… [bounded excerpt]';
      }
      return text;
    }

    String targetLabel(int? targetId, Vulnerability? vulnerability) {
      return clean(
        targetById[targetId]?.address ??
            vulnerability?.targetAddress ??
            'Unknown',
        maxLength: 300,
      );
    }

    for (final row in sessionEvents) {
      final eventType = row['event_type']?.toString() ?? '';
      if (eventType != 'assessment_decision' &&
          eventType != 'assessment_started' &&
          eventType != 'assessment_completed' &&
          eventType != 'assessment_failed' &&
          eventType != 'candidate_plan_created' &&
          eventType != 'candidate_requeued' &&
          eventType != 'candidate_prerequisite_satisfied' &&
          eventType != 'candidate_closure_finalized' &&
          eventType != 'supervised_validation_event') {
        continue;
      }
      final timestamp = DateTime.tryParse(row['timestamp']?.toString() ?? '');
      if (timestamp == null) continue;
      Map<String, dynamic> metadata = const {};
      try {
        final raw = row['metadata'];
        if (raw is Map) {
          metadata = Map<String, dynamic>.from(raw);
        } else if (raw is String && raw.isNotEmpty) {
          metadata = Map<String, dynamic>.from(jsonDecode(raw) as Map);
        }
      } catch (_) {
        metadata = const {};
      }
      if (eventType == 'supervised_validation_event') {
        final evidence = metadata['evidence_references'];
        final evidenceText = evidence is List
            ? evidence.map((value) => clean(value, maxLength: 500)).join(', ')
            : clean(evidence, maxLength: 1000);
        entries.add(
          AssessmentTimelineEntry(
            timestamp: timestamp,
            phase: 'HUMAN-SUPERVISED AI VALIDATION',
            target: clean(
              metadata['destination_address'] ?? 'Unknown',
              maxLength: 300,
            ),
            finding: clean(metadata['finding'], maxLength: 500),
            action: [
              clean(metadata['event'], maxLength: 100),
              clean(metadata['exact_action'], maxLength: 1000),
              clean(metadata['rationale']),
            ].where((value) => value.isNotEmpty).join(' — '),
            rationale: [
              'AI-operated action observed by ${clean(metadata['observing_operator'], maxLength: 200)}',
              'Authorization ${clean(metadata['engagement_reference'], maxLength: 200)}',
              'Source ${clean(metadata['source_address'], maxLength: 300)}',
            ].where((value) => value.isNotEmpty).join(' — '),
            observation: clean(metadata['detail']),
            verification: [
              clean(metadata['expected_evidence']),
              evidenceText,
            ].where((value) => value.isNotEmpty).join(' — Evidence: '),
            result: clean(metadata['event'], maxLength: 100),
            disposition: clean(metadata['disposition'], maxLength: 300),
            sourceType: eventType,
          ),
        );
        continue;
      }
      final vulnerabilityId = _asInt(metadata['vulnerability_id']);
      final vulnerability = vulnById[vulnerabilityId];
      final targetId = _asInt(row['targetId']) ?? vulnerability?.targetId;
      final status = clean(metadata['status'], maxLength: 100).toUpperCase();
      final technique = clean(metadata['technique_family'], maxLength: 300);
      final purpose = clean(metadata['purpose']);
      final thought = clean(metadata['thought']);
      final adaptation = clean(metadata['adaptation']);
      final hypothesis = clean(metadata['hypothesis']);
      final startingEvidence = clean(metadata['starting_evidence']);
      final reason = clean(metadata['reason']);
      final evidenceGoal = clean(metadata['evidence_goal']);
      final expectedSuccess = clean(metadata['expected_success_output']);
      final expectedFailure = clean(metadata['expected_failure_output']);
      final terminalDisposition = clean(
        metadata['terminal_disposition'],
        maxLength: 200,
      );
      final reasonCode = clean(metadata['reason_code'], maxLength: 200);

      entries.add(
        AssessmentTimelineEntry(
          timestamp: timestamp,
          phase: clean(row['phase'], maxLength: 100),
          target: targetLabel(targetId, vulnerability),
          finding: clean(
            vulnerability?.problem ?? metadata['finding'],
            maxLength: 500,
          ),
          action: [
            hypothesis,
            technique,
            purpose,
          ].where((value) => value.isNotEmpty).join(' — '),
          rationale: [
            thought,
            adaptation,
          ].where((value) => value.isNotEmpty).join(' Adaptation: '),
          observation: startingEvidence,
          verification: [
            evidenceGoal,
            expectedSuccess,
            expectedFailure,
          ].where((value) => value.isNotEmpty).join(' — '),
          result: eventType == 'assessment_failed' ? reason : '',
          disposition: eventType == 'candidate_closure_finalized'
              ? [
                  terminalDisposition,
                  reasonCode,
                  reason,
                ].where((value) => value.isNotEmpty).join(' — ')
              : eventType == 'assessment_completed'
              ? [status, reason].where((value) => value.isNotEmpty).join(' — ')
              : '',
          sourceType: eventType,
        ),
      );
    }

    for (final log in commandLogs) {
      final vulnerability = log.vulnerabilityId == null
          ? null
          : vulnById[log.vulnerabilityId];
      entries.add(
        AssessmentTimelineEntry(
          timestamp: log.timestamp,
          phase: 'EXECUTION',
          target: targetLabel(log.targetId, vulnerability),
          finding: clean(vulnerability?.problem ?? '', maxLength: 500),
          action: clean(log.command, maxLength: 800),
          observation: clean(log.output),
          verification: log.exitCode == 0
              ? 'Command completed; interpret the observed response in context.'
              : 'Command did not complete successfully; this is not proof of absence.',
          result: 'Exit code ${log.exitCode}',
          sourceType: 'command_log',
        ),
      );
    }

    final latestSourceTimestamp = entries.fold<DateTime?>(
      null,
      (latest, entry) => latest == null || entry.timestamp.isAfter(latest)
          ? entry.timestamp
          : latest,
    );
    var dispositionOffset = 0;
    for (final vulnerability in vulnerabilities) {
      if (vulnerability.status == VulnerabilityStatus.pending) continue;
      dispositionOffset++;
      final status = vulnerability.status.name
          .replaceAllMapped(RegExp(r'([A-Z])'), (match) => '_${match.group(1)}')
          .toUpperCase();
      final timestamp =
          vulnerability.confirmedAt ??
          (latestSourceTimestamp ?? DateTime.now().toUtc()).add(
            Duration(microseconds: dispositionOffset),
          );
      entries.add(
        AssessmentTimelineEntry(
          timestamp: timestamp,
          phase: 'FINAL DISPOSITION',
          target: targetLabel(vulnerability.targetId, vulnerability),
          finding: clean(vulnerability.problem, maxLength: 500),
          observation: clean(vulnerability.evidence),
          verification: clean(vulnerability.proofOutput),
          result: clean(vulnerability.statusReason),
          disposition: status,
          sourceType: 'finding_disposition',
        ),
      );
    }

    entries.sort((a, b) => a.timestamp.compareTo(b.timestamp));
    final prompt = _buildPrompt(entries);
    return AssessmentNarrativeData(
      entries: List.unmodifiable(entries),
      prompt: prompt,
    );
  }

  static int? _asInt(Object? value) {
    if (value is int) return value;
    return int.tryParse(value?.toString() ?? '');
  }

  static String _buildPrompt(List<AssessmentTimelineEntry> entries) {
    final ledger = entries
        .asMap()
        .entries
        .map((indexed) {
          final entry = indexed.value;
          return '''EVENT ${indexed.key + 1}
Timestamp: ${entry.timestamp.toUtc().toIso8601String()}
Phase: ${entry.phase}
Target: ${entry.target}
Finding: ${entry.finding}
Action/technique: ${entry.action}
Rationale/adaptation: ${entry.rationale}
Observed evidence: ${entry.observation}
Independent verification/evidence goal: ${entry.verification}
Result: ${entry.result}
Final disposition: ${entry.disposition}
Source: ${entry.sourceType}''';
        })
        .join('\n\n');

    return '''Write a complete, chronological penetration-testing narrative from the authoritative ledger below.

Hard requirements:
- Do not invent actions or evidence. Every factual claim must be supported by a ledger event.
- Explain the initial hypothesis, why each safe technique was selected, what happened, and how the next attempt adapted to the prior result.
- Include successful, failed, blocked, skipped, and inconclusive approaches; do not silently omit negative evidence.
- Explicitly distinguish these four categories: Observed evidence; Modeled potential impact; Prohibited human-led validation; Final confirmed, not-confirmed, or inconclusive conclusion.
- A command exit code alone is not proof. Describe only what the bounded output supports.
- Treat CONFIRMED as verified only when the ledger supplies direct or independently corroborated evidence.
- Preserve UNDETERMINED and policy/authentication blocks as inconclusive. Never recast them as confirmed or safe.
- Do not reproduce credentials, authorization headers, cookies, tokens, private keys, or authentication material.
- End each tested finding with the evidence chain and the exact reason for its final classification.

AUTHORITATIVE ASSESSMENT LEDGER:
$ledger''';
  }
}

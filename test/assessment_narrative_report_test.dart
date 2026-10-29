import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/command_log.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/models/target.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/assessment_narrative_service.dart';
import 'package:llmtary/services/report_generator.dart';

void main() {
  final project = Project(
    id: 7,
    name: 'Narrative Test',
    folderPath: '/assessment',
    createdAt: DateTime.utc(2026, 10, 1),
    lastOpenedAt: DateTime.utc(2026, 10, 2),
  );
  final target = Target(
    id: 11,
    projectId: 7,
    address: '192.0.2.10',
    status: TargetStatus.complete,
    analysisComplete: true,
    executionComplete: true,
  );
  final finding = Vulnerability(
    id: 31,
    projectId: 7,
    targetId: 11,
    targetAddress: '192.0.2.10',
    problem: 'Exposed diagnostic endpoint',
    description: 'A diagnostic endpoint was identified.',
    severity: 'MEDIUM',
    confidence: 'HIGH',
    evidence: 'A bounded request returned diagnostic metadata.',
    recommendation: 'Restrict the endpoint.',
    status: VulnerabilityStatus.confirmed,
    statusReason: 'Two independent read-only responses corroborated exposure.',
  );
  final logs = <CommandLog>[
    CommandLog(
      timestamp: DateTime.utc(2026, 10, 2, 12, 2),
      command: 'curl -I http://192.0.2.10/diagnostics',
      output: 'HTTP/1.1 200 OK\nAuthorization: Bearer should-not-leak',
      exitCode: 0,
      projectId: 7,
      targetId: 11,
      vulnerabilityId: 31,
    ),
  ];
  final events = <Map<String, dynamic>>[
    {
      'targetId': 11,
      'event_type': 'assessment_decision',
      'phase': 'VERIFICATION',
      'timestamp': '2026-10-02T12:01:00.000Z',
      'metadata':
          '{"vulnerability_id":31,"thought":"Validate the endpoint before classifying it.","technique_family":"HTTP metadata","purpose":"Determine whether the endpoint is exposed","evidence_goal":"A bounded 200 response","adaptation":"Use HEAD first to minimize data transfer"}',
    },
    {
      'targetId': 11,
      'event_type': 'supervised_validation_event',
      'phase': 'HUMAN-SUPERVISED AI VALIDATION',
      'timestamp': '2026-10-02T12:02:30.000Z',
      'metadata':
          '{"event":"actionCompleted","engagement_reference":"ENG-7","observing_operator":"operator-1","source_address":"192.0.2.5","destination_address":"192.0.2.10","finding":"Diagnostic endpoint exposed","action_id":"action-1","exact_action":"hostname","rationale":"Validate the authorized remote boundary","expected_evidence":"Remote identity and hostname","detail":"Read-only identity proof completed","evidence_references":["evidence/action-1.png"]}',
    },
    {
      'targetId': 11,
      'event_type': 'assessment_completed',
      'phase': 'CONFIRMATION',
      'timestamp': '2026-10-02T12:03:00.000Z',
      'metadata':
          '{"vulnerability_id":31,"status":"confirmed","reason":"Two independent read-only responses corroborated exposure."}',
    },
  ];

  test('builds a chronological evidence-grounded assessment ledger', () {
    final narrative = AssessmentNarrativeService.build(
      targets: [target],
      vulnerabilities: [finding],
      commandLogs: logs,
      sessionEvents: events,
    );

    expect(narrative.entries, hasLength(5));
    expect(narrative.entries.first.timestamp, DateTime.utc(2026, 10, 2, 12, 1));
    final supervised = narrative.entries.singleWhere(
      (entry) => entry.sourceType == 'supervised_validation_event',
    );
    expect(supervised.phase, 'HUMAN-SUPERVISED AI VALIDATION');
    expect(
      supervised.action,
      contains('Validate the authorized remote boundary'),
    );
    expect(supervised.action, contains('hostname'));
    expect(supervised.finding, 'Diagnostic endpoint exposed');
    expect(
      supervised.observation,
      contains('Read-only identity proof completed'),
    );
    expect(supervised.verification, contains('evidence/action-1.png'));
    expect(
      narrative.entries.first.rationale,
      contains('Validate the endpoint'),
    );
    expect(
      narrative.entries[1].action,
      contains('curl -I http://192.0.2.10/diagnostics'),
    );
    expect(narrative.entries[1].observation, contains('HTTP/1.1 200 OK'));
    expect(
      narrative.entries[1].observation,
      isNot(contains('should-not-leak')),
    );
    expect(narrative.entries.last.disposition, contains('CONFIRMED'));
    expect(narrative.prompt, contains('Do not invent actions or evidence'));
    expect(narrative.prompt, contains('Observed evidence'));
    expect(narrative.prompt, contains('Modeled potential impact'));
    expect(narrative.prompt, contains('Prohibited human-led validation'));
  });

  test('renders narrative and deterministic timeline in HTML and Markdown', () {
    final narrative = AssessmentNarrativeService.build(
      targets: [target],
      vulnerabilities: [finding],
      commandLogs: logs,
      sessionEvents: events,
    );
    const prose =
        'Testing began with a low-impact HTTP metadata hypothesis and concluded only after corroboration.';

    final html = ReportGenerator.generateHtml(
      project: project,
      targets: [target],
      vulnerabilities: [finding],
      assessmentNarrative: prose,
      assessmentTimeline: narrative.entries,
    );
    final markdown = ReportGenerator.generateMarkdown(
      project: project,
      targets: [target],
      vulnerabilities: [finding],
      assessmentNarrative: prose,
      assessmentTimeline: narrative.entries,
    );

    for (final report in [html, markdown]) {
      expect(report, contains('Testing Timeline and Assessment Narrative'));
      expect(report, contains(prose));
      expect(report, contains('HTTP metadata'));
      expect(report, contains('CONFIRMED'));
      expect(report, isNot(contains('should-not-leak')));
    }
  });
}

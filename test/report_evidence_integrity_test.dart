import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/command_log.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/models/vulnerability.dart';
import 'package:llmtary/services/report_evidence_quality.dart';
import 'package:llmtary/services/report_generator.dart';

Vulnerability finding({
  required int id,
  required String problem,
  required VulnerabilityStatus status,
  String confidence = 'HIGH',
  String evidence = 'Direct response demonstrated the condition.',
  String? proofCommand,
  String type = 'Config Weakness',
  String description = 'Test description.',
}) =>
    Vulnerability(
      id: id,
      projectId: 1,
      targetId: 1,
      targetAddress: '192.0.2.10',
      problem: problem,
      description: description,
      severity: 'HIGH',
      confidence: confidence,
      evidence: evidence,
      recommendation: 'Apply the appropriate control.',
      vulnerabilityType: type,
      proofCommand: proofCommand,
      status: status,
    );

CommandLog logFor(
  int vulnerabilityId, {
  required String command,
  required String output,
  int exitCode = 0,
}) =>
    CommandLog(
      timestamp: DateTime.utc(2026, 10, 26),
      command: command,
      output: output,
      exitCode: exitCode,
      projectId: 1,
      targetId: 1,
      vulnerabilityId: vulnerabilityId,
    );

void main() {
  final project = Project(
    id: 1,
    name: 'Evidence Integrity',
    folderPath: '/assessment',
    createdAt: DateTime.utc(2026, 10, 1),
    lastOpenedAt: DateTime.utc(2026, 10, 2),
  );

  test('non-confirmed records are never report-ready by default', () {
    final candidate = finding(
      id: 70,
      problem: 'Potential issue',
      status: VulnerabilityStatus.undetermined,
      evidence: 'A scanner suggested a condition.',
    );

    expect(candidate.reportReady, isFalse);
  });

  test('unrelated latest command is never promoted to proof', () {
    final candidate = finding(
      id: 10,
      problem: 'Missing Account Lockout Protections',
      status: VulnerabilityStatus.undetermined,
      confidence: 'LOW',
      evidence: 'The device data does not indicate any account lockout policy.',
      type: 'Authentication:Missing Lockout/Rate Limiting',
    );
    final nmap = logFor(
      10,
      command: 'nmap -p 445 192.0.2.10',
      output: '445/tcp filtered microsoft-ds',
    );

    final decision = ReportEvidenceQuality.evaluate(candidate, [nmap]);
    final html = ReportGenerator.generateHtml(
      project: project,
      targets: const [],
      vulnerabilities: [candidate],
      commandLogs: [nmap],
      confirmedOnly: false,
    );

    expect(decision.reportable, isFalse);
    expect(decision.proofLog, isNull);
    expect(html, isNot(contains('Verified Finding-Specific Evidence')));
    expect(html, isNot(contains('445/tcp filtered microsoft-ds')));
    expect(html, contains('Assessment Candidates and Negative Results'));
    expect(html, contains('Inconclusive — not a verified vulnerability'));
    expect(html, contains('Total Confirmed Findings</label><p>0</p>'));
  });

  test('confirmed finding requires explicit relevant proof', () {
    final confirmed = finding(
      id: 20,
      problem: 'Missing X-Frame-Options Header',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'curl -sI http://192.0.2.10/',
      evidence: 'The bounded HTTP response omitted X-Frame-Options.',
    );
    final proof = logFor(
      20,
      command: 'curl -sI http://192.0.2.10/',
      output: 'HTTP/1.1 200 OK\nServer: example',
    );

    final decision = ReportEvidenceQuality.evaluate(confirmed, [proof]);

    expect(decision.reportable, isTrue);
    expect(decision.proofLog, same(proof));
  });

  test('low confidence does not override direct finding-specific proof', () {
    final confirmed = finding(
      id: 21,
      problem: 'Missing X-Frame-Options Header',
      status: VulnerabilityStatus.confirmed,
      confidence: 'LOW',
      proofCommand: 'curl -sI http://192.0.2.10/',
      evidence: 'The bounded HTTP response omitted X-Frame-Options.',
    );
    final proof = logFor(
      21,
      command: 'curl -sI http://192.0.2.10/',
      output: 'HTTP/1.1 200 OK\nServer: example',
    );

    final decision = ReportEvidenceQuality.evaluate(confirmed, [proof]);

    expect(decision.reportable, isTrue);
    expect(decision.proofLog, same(proof));
  });

  test('analysis conclusion cannot substitute for observed proof', () {
    final lockout = finding(
      id: 30,
      problem: 'Missing Account Lockout Protections',
      status: VulnerabilityStatus.confirmed,
      confidence: 'LOW',
      proofCommand: 'Analysis Conclusion',
      evidence: 'No evidence of an account lockout threshold or duration.',
      type: 'Authentication:Missing Lockout/Rate Limiting',
    );
    final summary = logFor(
      30,
      command: 'Analysis Conclusion',
      output: 'Conclusion: CONFIRMED because invalid credentials continued.',
    );

    final decision = ReportEvidenceQuality.evaluate(lockout, [summary]);

    expect(decision.reportable, isFalse);
    expect(decision.reason, contains('account-lockout policy'));
    expect(decision.proofLog, isNull);
  });

  test('failed TLS negotiation cannot prove a TLS misconfiguration', () {
    final tls = finding(
      id: 40,
      problem: 'TLS/SSL Configuration Issues on port 443',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'openssl s_client -connect 192.0.2.10:443',
      type: 'SSL/TLS',
    );
    final failedHandshake = logFor(
      40,
      command: 'openssl s_client -connect 192.0.2.10:443',
      output: 'unexpected eof while reading\nno peer certificate available\nSSL handshake has read 0 bytes\nCipher is (NONE)',
    );

    final decision = ReportEvidenceQuality.evaluate(tls, [failedHandshake]);

    expect(decision.reportable, isFalse);
    expect(decision.reason, contains('failed TLS negotiation'));
  });

  test('service discovery cannot confirm an exploit-class claim', () {
    final rce = finding(
      id: 45,
      problem: 'Potential Remote Code Execution',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'nmap -p 445 192.0.2.10',
      type: 'RCE',
    );
    final portScan = logFor(
      45,
      command: 'nmap -p 445 192.0.2.10',
      output: '445/tcp open microsoft-ds',
    );

    final decision = ReportEvidenceQuality.evaluate(rce, [portScan]);

    expect(decision.reportable, isFalse);
    expect(decision.reason, contains('service discovery'));
  });

  test('service discovery cannot confirm a missing HTTP header', () {
    final header = finding(
      id: 46,
      problem: 'Missing X-Frame-Options Header',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'nmap -p 80 192.0.2.10',
      type: 'Config Weakness',
    );
    final portScan = logFor(
      46,
      command: 'nmap -p 80 192.0.2.10',
      output: '80/tcp open http',
    );

    final decision = ReportEvidenceQuality.evaluate(header, [portScan]);

    expect(decision.reportable, isFalse);
    expect(decision.reason, contains('HTTP response'));
  });

  test('internal DNS query cannot prove external recursion exposure', () {
    final dns = finding(
      id: 47,
      problem: 'DNS Recursion Enabled',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'dig +short @192.0.2.10 example.com',
      type: 'Info Disclosure',
      description:
          'The service can be queried from outside and used by external attackers.',
    );
    final query = logFor(
      47,
      command: 'dig +short @192.0.2.10 example.com',
      output: '192.0.2.20',
    );

    final decision = ReportEvidenceQuality.evaluate(dns, [query]);

    expect(decision.reportable, isFalse);
    expect(decision.reason, contains('external vantage'));
  });

  test('stored narrative cannot override deterministic risk totals', () {
    final staleProject = Project(
      id: 1,
      name: 'Evidence Integrity',
      folderPath: '/assessment',
      createdAt: DateTime.utc(2026, 10, 1),
      lastOpenedAt: DateTime.utc(2026, 10, 2),
      executiveSummary: 'Fifty-six critical vulnerabilities require immediate remediation.',
      conclusion: 'Every candidate was proven exploitable.',
    );
    final candidate = finding(
      id: 60,
      problem: 'Potential RCE',
      status: VulnerabilityStatus.undetermined,
    );

    final html = ReportGenerator.generateHtml(
      project: staleProject,
      targets: const [],
      vulnerabilities: [candidate],
      confirmedOnly: false,
    );

    expect(html, contains('No evidence-qualified vulnerabilities were identified'));
    expect(html, isNot(contains('Fifty-six critical vulnerabilities')));
    expect(html, isNot(contains('Every candidate was proven exploitable')));
  });

  test('risk totals include only evidence-qualified confirmed findings', () {
    final valid = finding(
      id: 50,
      problem: 'Missing X-Frame-Options Header',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'curl -sI http://192.0.2.10/',
    );
    final invalid = finding(
      id: 51,
      problem: 'Missing Account Lockout Protections',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'Analysis Conclusion',
      evidence: 'No evidence of account lockout settings.',
      type: 'Authentication:Missing Lockout/Rate Limiting',
    );
    final pending = finding(
      id: 52,
      problem: 'Potential RCE',
      status: VulnerabilityStatus.undetermined,
    );
    final logs = [
      logFor(
        50,
        command: 'curl -sI http://192.0.2.10/',
        output: 'HTTP/1.1 200 OK\nServer: example',
      ),
      logFor(
        51,
        command: 'Analysis Conclusion',
        output: 'CONFIRMED',
      ),
    ];

    final html = ReportGenerator.generateHtml(
      project: project,
      targets: const [],
      vulnerabilities: [valid, invalid, pending],
      commandLogs: logs,
      confirmedOnly: false,
    );

    expect(html, contains('Total Confirmed Findings</label><p>1</p>'));
    expect(html, contains('Evidence Quality Exceptions'));
    expect(html, contains('Missing Account Lockout Protections'));
    expect(html, contains('Potential RCE'));
    expect(
      RegExp('Verified Finding-Specific Evidence').allMatches(html),
      hasLength(1),
    );
  });

  test('confirmed evidence exceptions remain visible in confirmed-only reports', () {
    final invalid = finding(
      id: 60,
      problem: 'Missing Account Lockout Protections',
      status: VulnerabilityStatus.confirmed,
      proofCommand: 'Analysis Conclusion',
    );

    final html = ReportGenerator.generateHtml(
      project: project,
      targets: const [],
      vulnerabilities: [invalid],
      commandLogs: [
        logFor(
          60,
          command: 'Analysis Conclusion',
          output: 'CONFIRMED',
        ),
      ],
    );

    expect(html, contains('Total Confirmed Findings</label><p>0</p>'));
    expect(html, contains('Evidence Quality Exceptions'));
    expect(html, contains('Missing Account Lockout Protections'));

    final csv = ReportGenerator.generateCsv(
      vulnerabilities: [invalid],
      commandLogs: [
        logFor(
          60,
          command: 'Analysis Conclusion',
          output: 'CONFIRMED',
        ),
      ],
      confirmedOnly: true,
    );
    expect(csv, contains('EVIDENCE QUALITY EXCEPTION'));
    expect(csv, contains('Missing Account Lockout Protections'));
  });
}

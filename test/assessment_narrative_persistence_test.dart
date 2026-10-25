import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('assessment reasoning is persisted and consumed by report generation', () {
    final executor = File('lib/services/exploit_executor.dart').readAsStringSync();
    final reportTab = File('lib/screens/tabs/result_report_tab.dart').readAsStringSync();

    expect(executor, contains("eventType: 'assessment_started'"));
    expect(executor, contains("eventType: 'assessment_decision'"));
    expect(executor, contains("eventType: 'assessment_completed'"));
    expect(executor, contains("eventType: 'assessment_failed'"));
    expect(executor, contains('DatabaseHelper.insertSessionEvent('));
    expect(executor, contains("'expected_success_output'"));
    expect(executor, contains("'expected_failure_output'"));

    expect(reportTab, contains('DatabaseHelper.getSessionEvents('));
    expect(reportTab, contains('AssessmentNarrativeService.build('));
    expect(reportTab, contains('assessmentTimeline: assessmentData.entries'));
  });

  test('report narrative is fail-safe when generated prose is unavailable', () {
    final reportTab = File('lib/screens/tabs/result_report_tab.dart').readAsStringSync();
    final generator = File('lib/services/report_generator.dart').readAsStringSync();

    expect(
      reportTab,
      contains('The deterministic timeline is still exported when prose generation fails.'),
    );
    expect(generator, contains('The ledger remains authoritative'));
    expect(generator, contains('Chronological Evidence Ledger'));
  });
}

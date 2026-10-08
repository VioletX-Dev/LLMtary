import 'dart:io';

import 'package:flutter_test/flutter_test.dart';

void main() {
  test('proof workflow exposes retest and spot-test actions', () {
    final table = File(
      'lib/widgets/vulnerability_table.dart',
    ).readAsStringSync();
    final tab = File(
      'lib/screens/tabs/proof_exploit_tab.dart',
    ).readAsStringSync();
    final main = File('lib/screens/main_screen.dart').readAsStringSync();
    final porter = File('lib/services/project_porter.dart').readAsStringSync();

    expect(table, contains('Retest finding'));
    expect(table, contains('SPOT TEST'));
    expect(tab, contains('onRetestFinding'));
    expect(tab, contains('onRunSpotTest'));
    expect(main, contains('_retestFinding'));
    expect(main, contains('_runTargetedSpotTest'));
    expect(main, contains('ScopeValidator.validate'));
    expect(main, contains('forceActiveTesting: true'));
    expect(main, contains('insertValidationRun'));
    expect(main, contains('updateValidationRun'));
    expect(porter, contains("'validation_runs': validationEntries"));
    expect(porter, contains("manifest['validation_runs']"));
  });
}

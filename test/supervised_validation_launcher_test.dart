import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/widgets/supervised_validation_launcher.dart';

void main() {
  testWidgets('launcher requires exactly one selected saved finding', (tester) async {
    var opened = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SupervisedValidationLauncher(
            selectedFindingCount: 0,
            selectedFindingSaved: false,
            onOpen: () => opened++,
          ),
        ),
      ),
    );
    expect(find.text('SUPERVISED AI VALIDATION'), findsOneWidget);
    await tester.tap(find.text('SUPERVISED AI VALIDATION'));
    expect(opened, 0);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: SupervisedValidationLauncher(
            selectedFindingCount: 1,
            selectedFindingSaved: true,
            onOpen: () => opened++,
          ),
        ),
      ),
    );
    await tester.tap(find.text('SUPERVISED AI VALIDATION'));
    expect(opened, 1);
  });
}

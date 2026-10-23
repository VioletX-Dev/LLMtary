import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/test_budget_mode.dart';
import 'package:llmtary/widgets/test_budget_dialog.dart';

void main() {
  testWidgets('budget dialog collects an API dollar cap', (tester) async {
    BudgetConfiguration? result;
    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (context) => Scaffold(
          body: TextButton(
            onPressed: () async {
              result = await showTestBudgetDialog(
                context,
                defaultMode: TestBudgetMode.apiCost,
              );
            },
            child: const Text('OPEN'),
          ),
        ),
      ),
    ));

    await tester.tap(find.text('OPEN'));
    await tester.pumpAndSettle();
    expect(find.text('API model — estimated USD'), findsOneWidget);
    await tester.enterText(find.byType(TextField), '15.50');
    await tester.tap(find.text('SAVE BUDGET'));
    await tester.pumpAndSettle();

    expect(result?.mode, TestBudgetMode.apiCost);
    expect(result?.limit, 15.5);
  });

  testWidgets('budget dialog collects a local runtime limit', (tester) async {
    BudgetConfiguration? result;
    await tester.pumpWidget(MaterialApp(
      home: Builder(
        builder: (context) => Scaffold(
          body: TextButton(
            onPressed: () async {
              result = await showTestBudgetDialog(
                context,
                defaultMode: TestBudgetMode.localRuntime,
              );
            },
            child: const Text('OPEN'),
          ),
        ),
      ),
    ));

    await tester.tap(find.text('OPEN'));
    await tester.pumpAndSettle();
    expect(find.text('Local model — runtime'), findsOneWidget);
    await tester.enterText(find.byType(TextField), '90');
    await tester.tap(find.text('SAVE BUDGET'));
    await tester.pumpAndSettle();

    expect(result?.mode, TestBudgetMode.localRuntime);
    expect(result?.limit, 90);
  });
}

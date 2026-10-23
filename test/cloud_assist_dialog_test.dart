import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/llm_provider.dart';
import 'package:llmtary/widgets/cloud_assist_dialog.dart';

void main() {
  testWidgets('cloud assist dialog defaults to disabled local-only mode', (
    tester,
  ) async {
    CloudAssistConfiguration? result;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => Scaffold(
            body: TextButton(
              onPressed: () async {
                result = await showCloudAssistDialog(context);
              },
              child: const Text('OPEN'),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('OPEN'));
    await tester.pumpAndSettle();
    expect(find.text('OPTIONAL CLOUD ASSIST'), findsOneWidget);
    expect(
      find.textContaining('Local completion never depends on cloud'),
      findsOneWidget,
    );
    await tester.tap(find.text('SAVE'));
    await tester.pumpAndSettle();

    expect(result?.enabled, isFalse);
    expect(result?.findingReview, isFalse);
    expect(result?.reportReview, isFalse);
    expect(result?.budgetUsd, 0);
  });

  testWidgets('cloud assist dialog collects provider, phases, and USD cap', (
    tester,
  ) async {
    CloudAssistConfiguration? result;
    await tester.pumpWidget(
      MaterialApp(
        home: Builder(
          builder: (context) => Scaffold(
            body: TextButton(
              onPressed: () async {
                result = await showCloudAssistDialog(context);
              },
              child: const Text('OPEN'),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('OPEN'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Enable optional cloud assistance'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('ChatGPT (OpenAI)'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Claude (Anthropic)').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Final finding confirmation'));
    await tester.tap(find.text('Final report review'));
    await tester.enterText(find.byType(TextField), '8.50');
    await tester.tap(find.text('SAVE'));
    await tester.pumpAndSettle();

    expect(result?.enabled, isTrue);
    expect(result?.provider, LLMProvider.claude);
    expect(result?.findingReview, isTrue);
    expect(result?.reportReview, isTrue);
    expect(result?.budgetUsd, 8.5);
  });
}

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/target.dart';
import 'package:llmtary/widgets/targeted_test_dialog.dart';

void main() {
  testWidgets(
    'spot test dialog restricts target and explains safety boundary',
    (tester) async {
      final targets = [
        Target(id: 7, projectId: 3, address: 'app.example.com'),
        Target(
          id: 8,
          projectId: 3,
          address: 'excluded.example.com',
          status: TargetStatus.excluded,
        ),
      ];

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: TargetedTestDialog(targets: targets)),
        ),
      );

      expect(find.text('TARGETED SPOT TEST'), findsOneWidget);
      expect(find.text('app.example.com'), findsOneWidget);
      expect(find.text('excluded.example.com'), findsNothing);
      expect(find.text('Test objective'), findsOneWidget);
      expect(find.text('Parameters'), findsOneWidget);
      expect(find.text('Expected secure result'), findsOneWidget);
      expect(find.text('Additional safety constraints'), findsOneWidget);
      expect(
        find.textContaining('cannot expand project scope'),
        findsOneWidget,
      );
      expect(find.textContaining('Do not enter passwords'), findsOneWidget);
      expect(find.text('RUN SPOT TEST'), findsOneWidget);
    },
  );
}

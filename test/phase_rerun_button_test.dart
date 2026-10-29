import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/widgets/phase_rerun_button.dart';

void main() {
  testWidgets('phase rerun button exposes exact phase and invokes callback', (
    tester,
  ) async {
    var pressed = 0;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: PhaseRerunButton(
            phaseLabel: 'VULN / HUNT',
            onPressed: () => pressed++,
          ),
        ),
      ),
    );

    expect(find.text('RE-RUN VULN / HUNT'), findsOneWidget);
    await tester.tap(find.byKey(const Key('rerun-vuln-hunt')));
    expect(pressed, 1);
  });

  testWidgets('phase rerun button is disabled while another phase is active', (
    tester,
  ) async {
    var pressed = false;
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: PhaseRerunButton(
            phaseLabel: 'PROOF / EXPLOIT',
            enabled: false,
            onPressed: () => pressed = true,
          ),
        ),
      ),
    );

    await tester.tap(find.byKey(const Key('rerun-proof-exploit')));
    expect(pressed, isFalse);
  });
}

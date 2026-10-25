import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/widgets/command_approval_widget.dart';

void main() {
  testWidgets('approval choices render without overflow at appliance resolution',
      (tester) async {
    await tester.binding.setSurfaceSize(const Size(1366, 768));
    addTearDown(() => tester.binding.setSurfaceSize(null));

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: CommandApprovalWidget(
            command: 'nmap -sV -p 443 192.0.2.10',
            onAllowOnce: () {},
            onAlwaysAllow: () {},
            onAlwaysAllowTool: () {},
            onDeny: () {},
          ),
        ),
      ),
    );

    expect(find.text('ALLOW ONCE'), findsOneWidget);
    expect(find.text('ALWAYS ALLOW EXACT COMMAND'), findsOneWidget);
    expect(find.text('ALWAYS ALLOW TOOL'), findsOneWidget);
    expect(find.text('NO'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

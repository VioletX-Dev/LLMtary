import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/widgets/ollama_ssh_tunnel_dialog.dart';

void main() {
  testWidgets('RunPod tunnel dialog exposes one-step SSH connection fields', (
    tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: OllamaSshTunnelDialog())),
    );
    await tester.pump();

    expect(find.text('Connect RunPod Ollama'), findsOneWidget);
    expect(find.byKey(const Key('runpod-ssh-command')), findsOneWidget);
    expect(find.byKey(const Key('runpod-host')), findsOneWidget);
    expect(find.byKey(const Key('runpod-ssh-port')), findsOneWidget);
    expect(find.byKey(const Key('runpod-user')), findsOneWidget);
    expect(find.byKey(const Key('runpod-key-path')), findsOneWidget);
    expect(find.byKey(const Key('runpod-local-port')), findsOneWidget);
    expect(find.byKey(const Key('connect-runpod-ollama')), findsOneWidget);
    expect(find.text('LLMtary SSH command'), findsOneWidget);
    expect(find.byKey(const Key('llmtary-ssh-command-output')), findsOneWidget);
    expect(find.byKey(const Key('copy-llmtary-ssh-command')), findsOneWidget);
    expect(find.text('CONNECT & VERIFY'), findsOneWidget);
    expect(
      find.textContaining(
        'Stopping the SSH tunnel does not stop the RunPod pod',
      ),
      findsOneWidget,
    );
  });
}

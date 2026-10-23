import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/llm_provider.dart';
import 'package:llmtary/models/llm_settings.dart';
import 'package:llmtary/services/llm_service.dart';
import 'package:llmtary/widgets/app_state.dart';

void main() {
  test(
    'prompt log shows an in-flight request and replaces it with response',
    () {
      final state = AppState();

      state.addPromptLog('monitor me', LLMService.pendingResponseMarker);

      expect(state.promptLogs, hasLength(1));
      expect(state.promptLogs.single.prompt, 'monitor me');
      expect(
        state.promptLogs.single.response,
        LLMService.pendingResponseMarker,
      );

      state.addPromptLog('monitor me', 'completed response');

      expect(state.promptLogs, hasLength(1));
      expect(state.promptLogs.single.response, 'completed response');
    },
  );

  test('prompt log replaces an in-flight request with a safe failure', () {
    final state = AppState();

    state.addPromptLog('monitor failure', LLMService.pendingResponseMarker);
    state.addPromptLog(
      'monitor failure',
      LLMService.failedResponseMarker(const FormatException()),
    );

    expect(state.promptLogs, hasLength(1));
    expect(
      state.promptLogs.single.response,
      '⚠ Request failed (FormatException)',
    );
  });

  test(
    'LLM service emits pending and failure callbacks around dispatch',
    () async {
      final events = <String>[];
      final service = LLMService(
        enforceProjectBudget: false,
        onPromptResponse: (prompt, response) => events.add(response),
      );
      final settings = LLMSettings(
        provider: LLMProvider.none,
        modelName: '',
        temperature: 0,
        maxTokens: 100,
        timeoutSeconds: 5,
      );

      await expectLater(
        service.sendMessage(settings, 'dispatch failure'),
        throwsA(anything),
      );

      expect(events, hasLength(2));
      expect(events.first, LLMService.pendingResponseMarker);
      expect(events.last, startsWith('⚠ Request failed ('));
    },
  );
}

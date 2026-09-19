import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/openai_request_builder.dart';

void main() {
  const messages = <Map<String, String>>[
    {'role': 'user', 'content': 'Return JSON.'},
  ];

  test('GPT-5 uses modern token parameter and omits temperature', () {
    final body = buildOpenAIChatRequest(
      model: 'gpt-5.4',
      messages: messages,
      temperature: 0.22,
      maxTokens: 4096,
    );

    expect(body['max_completion_tokens'], 4096);
    expect(body.containsKey('max_tokens'), isFalse);
    expect(body.containsKey('temperature'), isFalse);
    expect(body['response_format'], {'type': 'json_object'});
    expect(body['store'], isFalse);
  });

  test('GPT-5 aliases and future major versions use modern parameters', () {
    for (final model in [
      'gpt-5',
      'gpt-5-chat-latest',
      'gpt-5.1',
      'ft:gpt-5.2:violetx:assessment',
      'gpt-6-preview',
    ]) {
      final body = buildOpenAIChatRequest(
        model: model,
        messages: messages,
        temperature: 0.22,
        maxTokens: 4096,
      );

      expect(body['max_completion_tokens'], 4096, reason: model);
      expect(body.containsKey('max_tokens'), isFalse, reason: model);
      expect(body.containsKey('temperature'), isFalse, reason: model);
    }
  });

  test('o-series reasoning models use modern compatibility parameters', () {
    for (final model in [
      'o1',
      'o1-preview',
      'o1-mini',
      'o3',
      'o3-mini',
      'o4-mini',
    ]) {
      final body = buildOpenAIChatRequest(
        model: model,
        messages: messages,
        temperature: 0.22,
        maxTokens: 8192,
      );

      expect(body['max_completion_tokens'], 8192, reason: model);
      expect(body.containsKey('max_tokens'), isFalse, reason: model);
      expect(body.containsKey('temperature'), isFalse, reason: model);
    }
  });

  test('legacy GPT models retain max_tokens and temperature', () {
    final body = buildOpenAIChatRequest(
      model: 'gpt-4o',
      messages: messages,
      temperature: 0.22,
      maxTokens: 4096,
    );

    expect(body['max_tokens'], 4096);
    expect(body.containsKey('max_completion_tokens'), isFalse);
    expect(body['temperature'], 0.22);
    expect(body['response_format'], {'type': 'json_object'});
  });
}

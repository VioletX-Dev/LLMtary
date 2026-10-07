import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/llm_service.dart';

void main() {
  const messages = <Map<String, String>>[
    {'role': 'user', 'content': 'Reply with OK.'},
  ];

  test('GPT-5 request uses reasoning-model compatible parameters', () {
    final body = LLMService.buildChatGPTRequestBody(
      modelName: 'gpt-5.6-sol',
      messages: messages,
      temperature: 0.7,
      maxTokens: 4096,
    );

    expect(body['max_completion_tokens'], 4096);
    expect(body.containsKey('max_tokens'), isFalse);
    expect(body.containsKey('temperature'), isFalse);
    expect(body['store'], isFalse);
  });

  test('GPT-4 request retains legacy sampling parameters', () {
    final body = LLMService.buildChatGPTRequestBody(
      modelName: 'gpt-4o',
      messages: messages,
      temperature: 0.7,
      maxTokens: 4096,
    );

    expect(body['max_tokens'], 4096);
    expect(body.containsKey('max_completion_tokens'), isFalse);
    expect(body['temperature'], 0.7);
  });
}

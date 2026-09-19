/// Builds a Chat Completions request compatible with both legacy and modern
/// OpenAI model families.
///
/// GPT-5+ and o-series models reject the legacy `max_tokens` parameter and may
/// reject non-default sampling parameters such as `temperature`. Older GPT
/// models retain the request shape used by LLMtary before v1.0.9.
Map<String, dynamic> buildOpenAIChatRequest({
  required String model,
  required List<Map<String, String>> messages,
  required double temperature,
  required int maxTokens,
}) {
  final modernModel = _usesModernOpenAIParameters(model);
  final body = <String, dynamic>{
    'model': model,
    'messages': messages,
    'store': false,
  };

  if (modernModel) {
    body['max_completion_tokens'] = maxTokens;
  } else {
    body['temperature'] = temperature;
    body['max_tokens'] = maxTokens;
  }

  if (_supportsJsonResponseFormat(model)) {
    body['response_format'] = {'type': 'json_object'};
  }

  return body;
}

bool _usesModernOpenAIParameters(String model) {
  final normalized = model.trim().toLowerCase();
  final gptVersion = RegExp(r'(?:^|:)gpt-(\d+)').firstMatch(normalized);
  final majorVersion = int.tryParse(gptVersion?.group(1) ?? '');
  if (majorVersion != null && majorVersion >= 5) return true;
  return RegExp(r'(?:^|:)o\d+(?:[.-]|$)').hasMatch(normalized);
}

bool _supportsJsonResponseFormat(String model) {
  final normalized = model.trim().toLowerCase();
  if (normalized.contains('gpt-4o') || normalized.contains('gpt-4-turbo')) {
    return true;
  }
  final gptVersion = RegExp(r'(?:^|:)gpt-(\d+)').firstMatch(normalized);
  final majorVersion = int.tryParse(gptVersion?.group(1) ?? '');
  return majorVersion != null && majorVersion >= 5;
}

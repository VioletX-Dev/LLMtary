import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/llm_provider.dart';
import 'package:llmtary/models/llm_settings.dart';
import 'package:llmtary/models/project.dart';
import 'package:llmtary/services/llm_service.dart';
import 'package:llmtary/services/test_budget.dart';

void main() {
  tearDown(TestBudgetRuntime.clear);

  Project localProject() => Project(
    id: 1,
    name: 'local-model-test',
    folderPath: '/tmp/local-model-test',
    createdAt: DateTime.now(),
    lastOpenedAt: DateTime.now(),
    budgetMode: TestBudgetMode.localRuntime,
    budgetLimit: 5,
  );

  test(
    'LLMtary connects to RunPod Ollama through the documented SSH tunnel',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final generateSeen = Completer<void>();
      server.listen((request) async {
        request.response.headers.contentType = ContentType.json;
        if (request.method == 'GET' && request.uri.path == '/api/tags') {
          request.response.write(
            jsonEncode({
              'models': [
                {'name': 'qwen2.5:32b'},
              ],
            }),
          );
        } else if (request.method == 'POST' &&
            request.uri.path == '/api/generate') {
          final payload = jsonDecode(await utf8.decoder.bind(request).join());
          expect(payload['model'], 'qwen2.5:32b');
          request.response.write(
            jsonEncode({
              'response': '{"status":"connected"}',
              'prompt_eval_count': 12,
              'eval_count': 6,
            }),
          );
          generateSeen.complete();
        } else {
          request.response.statusCode = HttpStatus.notFound;
        }
        await request.response.close();
      });
      TestBudgetRuntime.configure(
        ProjectBudgetSession(project: localProject()),
      );

      final settings = LLMSettings(
        provider: LLMProvider.ollama,
        baseUrl: 'http://127.0.0.1:${server.port}',
        modelName: 'qwen2.5:32b',
        timeoutSeconds: 10,
      );
      final service = LLMService();

      expect(
        await service.fetchAvailableModels(settings),
        contains('qwen2.5:32b'),
      );
      final response = await service.sendMessage(
        settings,
        'connectivity check',
        useSystemPrompt: false,
      );

      expect(response, '{"status":"connected"}');
      await generateSeen.future;
      await server.close(force: true);
    },
  );

  test(
    'LLMtary connects to an LM Studio OpenAI-compatible local model',
    () async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      final requestSeen = Completer<void>();
      server.listen((request) async {
        expect(request.uri.path, '/v1/chat/completions');
        final payload = jsonDecode(await utf8.decoder.bind(request).join());
        expect(payload['model'], 'local-test');
        request.response.headers.contentType = ContentType.json;
        request.response.write(
          jsonEncode({
            'choices': [
              {
                'message': {'content': '{"status":"connected"}'},
              },
            ],
            'usage': {'prompt_tokens': 12, 'completion_tokens': 6},
          }),
        );
        await request.response.close();
        requestSeen.complete();
      });
      TestBudgetRuntime.configure(
        ProjectBudgetSession(project: localProject()),
      );

      final response = await LLMService().sendMessage(
        LLMSettings(
          provider: LLMProvider.lmStudio,
          baseUrl: 'http://127.0.0.1:${server.port}/v1',
          modelName: 'local-test',
          timeoutSeconds: 10,
        ),
        'connectivity check',
        useSystemPrompt: false,
      );

      expect(response, '{"status":"connected"}');
      await requestSeen.future;
      await server.close(force: true);
    },
  );
}

import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../models/browser_test.dart';
import 'attack_trace_recorder.dart';

class BrowserExecutionResult {
  final BrowserActionRecord record;
  final BrowserDriverObservation observation;

  const BrowserExecutionResult({required this.record, required this.observation});
}

class BrowserTestingService {
  static const _sensitiveHeaders = {
    'authorization',
    'proxy-authorization',
    'cookie',
    'set-cookie',
  };

  final BrowserDriver driver;
  final AttackTraceRecorder? attackTraceRecorder;
  final int? attackTraceId;

  BrowserTestingService(
    this.driver, {
    this.attackTraceRecorder,
    this.attackTraceId,
  }) {
    if (attackTraceRecorder != null && (attackTraceId == null || attackTraceId! <= 0)) {
      throw ArgumentError.value(
        attackTraceId,
        'attackTraceId',
        'A persisted trace id is required when trace recording is enabled',
      );
    }
  }

  Future<BrowserActionRecord> execute(BrowserActionRequest request) async =>
      (await executeDetailed(request)).record;

  Future<BrowserExecutionResult> executeDetailed(
    BrowserActionRequest request,
  ) async {
    final observation = await driver.perform(request);
    final exchanges = observation.networkExchanges
        .map(
          (exchange) => BrowserNetworkExchange(
            method: exchange.method,
            url: _sanitizeUrl(exchange.url),
            statusCode: exchange.statusCode,
            requestHeaders: _sanitizeHeaders(exchange.requestHeaders),
            responseHeaders: _sanitizeHeaders(exchange.responseHeaders),
          ),
        )
        .toList(growable: false);
    final evidenceId = observation.screenshotEvidenceArtifactId;
    final record = BrowserActionRecord(
      kind: request.kind,
      action: _actionDescription(request),
      roleId: request.roleId,
      finalUrl: _sanitizeUrl(observation.url),
      statusCode: observation.statusCode,
      domSha256: sha256
          .convert(utf8.encode(observation.domSnapshot))
          .toString(),
      networkExchanges: exchanges,
      evidenceArtifactIds: evidenceId == null ? const [] : [evidenceId],
    );

    if (attackTraceRecorder != null) {
      final createdAt = DateTime.now().toUtc();
      await attackTraceRecorder!.recordBrowserAction(
        traceId: attackTraceId!,
        stepKey: 'browser:${createdAt.microsecondsSinceEpoch}',
        record: record,
        createdAt: createdAt,
      );
    }

    return BrowserExecutionResult(record: record, observation: observation);
  }

  String _actionDescription(BrowserActionRequest request) =>
      switch (request.kind) {
        BrowserActionKind.navigate => 'navigate ${_sanitizeUrl(request.url)}',
        BrowserActionKind.click => 'click ${request.selector}',
        BrowserActionKind.fill => 'fill ${request.selector}',
        BrowserActionKind.submit => 'submit ${request.selector}',
        BrowserActionKind.switchRole => 'switch role ${request.roleId}',
        BrowserActionKind.captureState => 'capture state',
      };

  Map<String, String> _sanitizeHeaders(Map<String, String> headers) {
    final sanitized = <String, String>{};
    for (final entry in headers.entries) {
      if (_sensitiveHeaders.contains(entry.key.toLowerCase())) continue;
      sanitized[entry.key.toLowerCase()] = entry.value;
    }
    return Map.unmodifiable(sanitized);
  }

  String _sanitizeUrl(String value) {
    final uri = Uri.tryParse(value);
    if (uri == null || !uri.hasQuery) return value;
    final names = uri.queryParametersAll.keys.toList()..sort();
    return uri
        .replace(
          queryParameters: {for (final name in names) name: '[REDACTED]'},
        )
        .toString();
  }
}

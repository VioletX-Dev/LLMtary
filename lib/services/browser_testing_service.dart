import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../models/browser_test.dart';

class BrowserTestingService {
  static const _sensitiveHeaders = {
    'authorization',
    'proxy-authorization',
    'cookie',
    'set-cookie',
  };

  final BrowserDriver driver;

  const BrowserTestingService(this.driver);

  Future<BrowserActionRecord> execute(BrowserActionRequest request) async {
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
    return BrowserActionRecord(
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

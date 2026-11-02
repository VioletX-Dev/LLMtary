import 'dart:async';
import 'dart:convert';
import 'dart:io';

import '../models/browser_test.dart';

abstract interface class CdpTransport {
  Stream<Map<String, dynamic>> get events;

  Future<Map<String, dynamic>> send(
    String method, [
    Map<String, dynamic> params = const {},
  ]);

  Future<void> close();
}

class WebSocketCdpTransport implements CdpTransport {
  final WebSocket _socket;
  final _events = StreamController<Map<String, dynamic>>.broadcast();
  final _pending = <int, Completer<Map<String, dynamic>>>{};
  var _nextId = 1;

  WebSocketCdpTransport._(this._socket) {
    _socket.listen(
      _receive,
      onError: _failPending,
      onDone: () => _failPending(StateError('CDP connection closed.')),
    );
  }

  static Future<WebSocketCdpTransport> connect(Uri webSocketUrl) async =>
      WebSocketCdpTransport._(await WebSocket.connect(webSocketUrl.toString()));

  @override
  Stream<Map<String, dynamic>> get events => _events.stream;

  void _receive(dynamic message) {
    final decoded = jsonDecode(message as String);
    if (decoded is! Map) return;
    final payload = decoded.cast<String, dynamic>();
    final id = payload['id'];
    if (id is int) {
      final completer = _pending.remove(id);
      if (completer == null) return;
      final error = payload['error'];
      if (error != null) {
        completer.completeError(StateError('CDP command failed: $error'));
      } else {
        completer.complete(
          (payload['result'] as Map?)?.cast<String, dynamic>() ?? const {},
        );
      }
      return;
    }
    _events.add(payload);
  }

  void _failPending(Object error) {
    for (final completer in _pending.values) {
      if (!completer.isCompleted) completer.completeError(error);
    }
    _pending.clear();
  }

  @override
  Future<Map<String, dynamic>> send(
    String method, [
    Map<String, dynamic> params = const {},
  ]) {
    final id = _nextId++;
    final completer = Completer<Map<String, dynamic>>();
    _pending[id] = completer;
    _socket.add(jsonEncode({'id': id, 'method': method, 'params': params}));
    return completer.future;
  }

  @override
  Future<void> close() async {
    await _socket.close();
    await _events.close();
  }
}

typedef BrowserScreenshotSink = Future<int?> Function(List<int> pngBytes);

class CdpBrowserDriver implements BrowserDriver {
  final CdpTransport transport;
  final Duration navigationTimeout;
  final BrowserScreenshotSink? screenshotSink;
  var _initialized = false;

  CdpBrowserDriver(
    this.transport, {
    this.navigationTimeout = const Duration(seconds: 30),
    this.screenshotSink,
  });

  @override
  Future<BrowserDriverObservation> perform(BrowserActionRequest request) async {
    await _initialize();
    final requests = <String, Map<String, dynamic>>{};
    final exchanges = <BrowserNetworkExchange>[];
    final load = Completer<void>();
    var documentStatus = 0;
    final subscription = transport.events.listen((event) {
      final method = event['method'];
      final params =
          (event['params'] as Map?)?.cast<String, dynamic>() ?? const {};
      if (method == 'Page.loadEventFired' && !load.isCompleted) {
        load.complete();
      } else if (method == 'Network.requestWillBeSent') {
        final request = (params['request'] as Map?)?.cast<String, dynamic>();
        final requestId = params['requestId']?.toString();
        if (request != null && requestId != null) requests[requestId] = request;
      } else if (method == 'Network.responseReceived') {
        final response = (params['response'] as Map?)?.cast<String, dynamic>();
        final requestId = params['requestId']?.toString();
        if (response == null || requestId == null) return;
        final original = requests[requestId] ?? const <String, dynamic>{};
        final status = (response['status'] as num?)?.toInt() ?? 0;
        if (params['type'] == 'Document') documentStatus = status;
        exchanges.add(
          BrowserNetworkExchange(
            method: original['method']?.toString() ?? '',
            url:
                response['url']?.toString() ??
                original['url']?.toString() ??
                '',
            statusCode: status,
            requestHeaders: _stringMap(original['headers']),
            responseHeaders: _stringMap(response['headers']),
          ),
        );
      }
    });

    try {
      await _performAction(request);
      if (request.kind == BrowserActionKind.navigate ||
          request.kind == BrowserActionKind.submit) {
        await load.future.timeout(navigationTimeout);
      }
      final dom = await _evaluate('document.documentElement.outerHTML');
      final url = await _evaluate('location.href');
      int? evidenceId;
      if (screenshotSink != null) {
        final screenshot = await transport.send('Page.captureScreenshot', {
          'format': 'png',
          'captureBeyondViewport': true,
        });
        final data = screenshot['data']?.toString();
        if (data != null && data.isNotEmpty) {
          evidenceId = await screenshotSink!(base64Decode(data));
        }
      }
      return BrowserDriverObservation(
        url: url,
        statusCode: documentStatus,
        domSnapshot: dom,
        networkExchanges: List.unmodifiable(exchanges),
        screenshotEvidenceArtifactId: evidenceId,
      );
    } finally {
      await subscription.cancel();
    }
  }

  Future<void> _initialize() async {
    if (_initialized) return;
    await transport.send('Page.enable');
    await transport.send('Network.enable');
    await transport.send('Runtime.enable');
    _initialized = true;
  }

  Future<void> _performAction(BrowserActionRequest request) async {
    switch (request.kind) {
      case BrowserActionKind.navigate:
        final uri = Uri.tryParse(request.url);
        if (uri == null || !{'http', 'https'}.contains(uri.scheme)) {
          throw ArgumentError.value(request.url, 'url', 'HTTP(S) URL required');
        }
        await transport.send('Page.navigate', {'url': request.url});
      case BrowserActionKind.click:
        await _evaluate(_elementScript(request.selector, 'element.click();'));
      case BrowserActionKind.fill:
        await _evaluate(
          _elementScript(
            request.selector,
            'element.value = ${jsonEncode(request.value)};'
            "element.dispatchEvent(new Event('input', {bubbles:true}));"
            "element.dispatchEvent(new Event('change', {bubbles:true}));",
          ),
        );
      case BrowserActionKind.submit:
        await _evaluate(
          _elementScript(
            request.selector,
            'if (element.requestSubmit) { element.requestSubmit(); } '
            'else if (element.form?.requestSubmit) { element.form.requestSubmit(); } '
            'else { element.click(); }',
          ),
        );
      case BrowserActionKind.switchRole:
        if (request.roleId.trim().isEmpty) {
          throw ArgumentError.value(request.roleId, 'roleId');
        }
        await transport.send('Network.clearBrowserCookies');
        await transport.send('Network.clearBrowserCache');
      case BrowserActionKind.captureState:
        break;
    }
  }

  String _elementScript(String selector, String action) {
    if (selector.trim().isEmpty) {
      throw ArgumentError.value(selector, 'selector');
    }
    return '''(() => {
      const element = document.querySelector(${jsonEncode(selector)});
      if (!element) throw new Error('Element not found');
      $action
      return true;
    })()''';
  }

  Future<String> _evaluate(String expression) async {
    final response = await transport.send('Runtime.evaluate', {
      'expression': expression,
      'returnByValue': true,
      'awaitPromise': true,
    });
    final result = (response['result'] as Map?)?.cast<String, dynamic>();
    final exception = response['exceptionDetails'];
    if (exception != null) throw StateError('Browser action failed.');
    return result?['value']?.toString() ?? '';
  }

  static Map<String, String> _stringMap(Object? value) {
    if (value is! Map) return const {};
    return value.map((key, item) => MapEntry(key.toString(), item.toString()));
  }
}

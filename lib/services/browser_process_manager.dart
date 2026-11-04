import 'dart:async';
import 'dart:convert';
import 'dart:io';

typedef ProcessStarter =
    Future<Process> Function(
      String executable,
      List<String> arguments, {
      Map<String, String>? environment,
      bool runInShell,
    });

class BrowserEndpoint {
  final int port;
  final Uri websocketUri;

  const BrowserEndpoint({required this.port, required this.websocketUri});
}

typedef BrowserEndpointResolver =
    Future<BrowserEndpoint> Function(Directory profileDirectory);

abstract interface class BrowserProcessLauncher {
  Future<BrowserProcess> startChromium({
    required String executable,
    List<String> extraArgs = const [],
    Map<String, String>? environment,
  });
}

class BrowserProcess {
  final Process process;
  final int debugPort;
  final Uri websocketUri;
  final Directory profileDirectory;

  BrowserProcess({
    required this.process,
    required this.debugPort,
    required this.websocketUri,
    required this.profileDirectory,
  });

  Future<void> kill() async {
    try {
      process.kill(ProcessSignal.sigterm);
      await process.exitCode.timeout(const Duration(seconds: 5));
    } catch (_) {
      try {
        process.kill(ProcessSignal.sigkill);
      } catch (_) {}
    }
    try {
      if (await profileDirectory.exists()) {
        await profileDirectory.delete(recursive: true);
      }
    } catch (_) {}
  }
}

class BrowserProcessManager implements BrowserProcessLauncher {
  final ProcessStarter _starter;
  final BrowserEndpointResolver _endpointResolver;

  BrowserProcessManager({
    ProcessStarter? starter,
    BrowserEndpointResolver? endpointResolver,
    Duration endpointReadyTimeout = const Duration(seconds: 30),
  }) : _starter =
           starter ??
           ((
             String executable,
             List<String> arguments, {
             Map<String, String>? environment,
             bool runInShell = false,
           }) {
             return Process.start(
               executable,
               arguments,
               environment: environment,
               runInShell: runInShell,
             );
           }),
       _endpointResolver =
           endpointResolver ??
           ((profile) =>
               _resolveBrowserEndpoint(profile, endpointReadyTimeout));

  /// Starts a headless Chromium process bound to loopback-only remote debugging
  /// on an ephemeral port. Returns a BrowserProcess with the opened Process
  /// and a websocket Uri for CDP. No shell invocation or command-line
  /// concatenation is performed.
  @override
  Future<BrowserProcess> startChromium({
    required String executable,
    List<String> extraArgs = const [],
    Map<String, String>? environment,
  }) async {
    if (!executable.startsWith('/') ||
        executable.contains('\u0000') ||
        executable.contains('\n') ||
        executable.contains('\r')) {
      throw ArgumentError.value(
        executable,
        'executable',
        'Chromium executable must be a trusted absolute path',
      );
    }
    const protectedPrefixes = <String>[
      '--remote-debugging-address',
      '--remote-debugging-port',
      '--user-data-dir',
      '--profile-directory',
      '--load-extension',
      '--disable-web-security',
    ];
    for (final argument in extraArgs) {
      if (argument.contains('\u0000') ||
          argument.contains('\n') ||
          argument.contains('\r') ||
          protectedPrefixes.any(argument.startsWith)) {
        throw ArgumentError.value(
          argument,
          'extraArgs',
          'Protected or malformed Chromium argument',
        );
      }
    }

    final profileDirectory = await Directory.systemTemp.createTemp(
      'llmtary-browser-profile-',
    );

    final args = <String>[
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--remote-debugging-port=0',
      '--remote-debugging-address=127.0.0.1',
      '--user-data-dir=${profileDirectory.path}',
      '--disable-dev-shm-usage',
      '--disable-extensions',
      '--disable-background-networking',
      ...extraArgs,
    ];

    late final Process process;
    try {
      process = await _starter(
        executable,
        args,
        environment: environment,
        runInShell: false,
      );
    } catch (_) {
      await profileDirectory.delete(recursive: true);
      rethrow;
    }

    late final BrowserEndpoint endpoint;
    try {
      endpoint = await _endpointResolver(profileDirectory);
      final ws = endpoint.websocketUri;
      final loopbackHost =
          ws.host == '127.0.0.1' || ws.host == 'localhost' || ws.host == '::1';
      if (endpoint.port <= 0 ||
          ws.scheme != 'ws' ||
          !loopbackHost ||
          ws.port != endpoint.port ||
          !ws.path.startsWith('/devtools/page/')) {
        throw StateError('Chromium returned an invalid page CDP endpoint');
      }
    } catch (_) {
      process.kill(ProcessSignal.sigkill);
      await profileDirectory.delete(recursive: true);
      rethrow;
    }

    return BrowserProcess(
      process: process,
      debugPort: endpoint.port,
      websocketUri: endpoint.websocketUri,
      profileDirectory: profileDirectory,
    );
  }

  static Future<BrowserEndpoint> _resolveBrowserEndpoint(
    Directory profileDirectory,
    Duration timeout,
  ) async {
    final client = HttpClient()..connectionTimeout = const Duration(seconds: 1);
    final activePortFile = File(
      '${profileDirectory.path}${Platform.pathSeparator}DevToolsActivePort',
    );
    try {
      final deadline = DateTime.now().toUtc().add(timeout);
      var delay = const Duration(milliseconds: 100);
      while (DateTime.now().toUtc().isBefore(deadline)) {
        try {
          if (!await activePortFile.exists()) {
            throw StateError('DevToolsActivePort is not ready');
          }
          final lines = await activePortFile.readAsLines();
          final port = lines.isEmpty ? null : int.tryParse(lines.first.trim());
          if (port == null || port <= 0) {
            throw const FormatException('Invalid DevToolsActivePort');
          }
          final request = await client.getUrl(
            Uri.parse('http://127.0.0.1:$port/json/list'),
          );
          final response = await request.close();
          if (response.statusCode == HttpStatus.ok) {
            final body = await response.transform(utf8.decoder).join();
            final decoded = jsonDecode(body);
            if (decoded is List) {
              for (final target in decoded.whereType<Map>()) {
                if (target['type'] != 'page') continue;
                final endpoint = Uri.tryParse(
                  target['webSocketDebuggerUrl']?.toString() ?? '',
                );
                if (endpoint != null) {
                  return BrowserEndpoint(port: port, websocketUri: endpoint);
                }
              }
            }
          } else {
            await response.drain<void>();
          }
        } catch (_) {
          // Chromium may not have opened its loopback endpoint yet.
        }
        await Future<void>.delayed(delay);
        final nextMilliseconds = delay.inMilliseconds * 2;
        delay = Duration(
          milliseconds: nextMilliseconds > 1000 ? 1000 : nextMilliseconds,
        );
      }
      throw TimeoutException('Chromium CDP page endpoint did not become ready');
    } finally {
      client.close(force: true);
    }
  }
}

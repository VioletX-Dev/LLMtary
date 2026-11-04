import 'dart:async';
import 'dart:io';

typedef ProcessStarter = Future<Process> Function(
  String executable,
  List<String> arguments, {
  Map<String, String>? environment,
  bool runInShell,
});

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

  BrowserProcessManager({ProcessStarter? starter}) : _starter = starter ??
      ((String executable, List<String> arguments, {Map<String, String>? environment, bool runInShell = false}) {
    return Process.start(executable, arguments, environment: environment, runInShell: runInShell);
  });

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

    // Reserve an ephemeral loopback port
    final socket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final port = socket.port;
    await socket.close();
    final profileDirectory = await Directory.systemTemp.createTemp(
      'llmtary-browser-profile-',
    );

    final args = <String>[
      '--headless=new',
      '--disable-gpu',
      '--no-first-run',
      '--no-default-browser-check',
      '--remote-debugging-port=$port',
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

    // Construct a websocket URL that Chromium exposes for the given port.
    final ws = Uri.parse('ws://127.0.0.1:$port/devtools/browser');

    return BrowserProcess(
      process: process,
      debugPort: port,
      websocketUri: ws,
      profileDirectory: profileDirectory,
    );
  }
}

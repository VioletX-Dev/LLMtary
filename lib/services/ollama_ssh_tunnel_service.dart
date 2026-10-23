import 'dart:async';
import 'dart:convert';
import 'dart:io';

class OllamaSshTunnelConfig {
  final String host;
  final int sshPort;
  final String user;
  final String identityFile;
  final int localPort;
  final int remotePort;

  const OllamaSshTunnelConfig({
    required this.host,
    required this.sshPort,
    required this.user,
    required this.identityFile,
    this.localPort = 11434,
    this.remotePort = 11434,
  });

  String get baseUrl => 'http://127.0.0.1:$localPort';

  /// Paste-ready command shown by RunPod setup output and accepted by LLMtary.
  String toSshCommand() {
    String quote(String value) {
      if (!value.contains(RegExp(r'[\s"\\]'))) return value;
      final escaped = value.replaceAll('\\', '\\\\').replaceAll('"', '\\"');
      return '"$escaped"';
    }

    return 'ssh -i ${quote(identityFile)} -p $sshPort $user@$host';
  }

  String? validate() {
    if (host.trim().isEmpty || host.contains(RegExp(r'\s'))) {
      return 'Enter the RunPod SSH host or IP address.';
    }
    if (sshPort < 1 || sshPort > 65535) {
      return 'SSH port must be between 1 and 65535.';
    }
    if (!RegExp(r'^[A-Za-z0-9._-]+$').hasMatch(user)) {
      return 'SSH user may only contain letters, numbers, dot, underscore, and hyphen.';
    }
    if (identityFile.trim().isEmpty) {
      return 'Select the SSH private-key file.';
    }
    if (localPort < 1 ||
        localPort > 65535 ||
        remotePort < 1 ||
        remotePort > 65535) {
      return 'Tunnel port must be between 1 and 65535.';
    }
    return null;
  }

  Map<String, dynamic> toJson() => {
    'host': host,
    'sshPort': sshPort,
    'user': user,
    'identityFile': identityFile,
    'localPort': localPort,
    'remotePort': remotePort,
  };

  factory OllamaSshTunnelConfig.fromJson(Map<String, dynamic> json) =>
      OllamaSshTunnelConfig(
        host: json['host'] as String? ?? '',
        sshPort: (json['sshPort'] as num?)?.toInt() ?? 22,
        user: json['user'] as String? ?? 'root',
        identityFile: json['identityFile'] as String? ?? '',
        localPort: (json['localPort'] as num?)?.toInt() ?? 11434,
        remotePort: (json['remotePort'] as num?)?.toInt() ?? 11434,
      );

  factory OllamaSshTunnelConfig.fromSshCommand(String command) {
    final tokens = RegExp("[^\\s\"']+|\"[^\"]*\"|'[^']*'")
        .allMatches(command.trim())
        .map((match) => match.group(0)!.trim())
        .where((token) => token.isNotEmpty)
        .map(
          (token) =>
              (token.startsWith('"') && token.endsWith('"')) ||
                  (token.startsWith("'") && token.endsWith("'"))
              ? token.substring(1, token.length - 1)
              : token,
        )
        .toList();
    if (tokens.isEmpty ||
        !(tokens.first == 'ssh' || tokens.first.endsWith('/ssh'))) {
      throw const FormatException('Paste a valid ssh command.');
    }

    var port = 22;
    var identityFile = '';
    String? destination;
    for (var i = 1; i < tokens.length; i++) {
      final token = tokens[i];
      if ((token == '-p' || token == '-i') && i + 1 < tokens.length) {
        final value = tokens[++i];
        if (token == '-p') {
          port = int.tryParse(value) ?? 0;
        } else {
          identityFile = value;
        }
      } else if (!token.startsWith('-') && token.contains('@')) {
        destination = token;
      }
    }
    if (destination == null) {
      throw const FormatException('SSH command must contain user@host.');
    }
    final separator = destination.indexOf('@');
    return OllamaSshTunnelConfig(
      host: destination.substring(separator + 1),
      sshPort: port,
      user: destination.substring(0, separator),
      identityFile: identityFile,
    );
  }

  String encode() => jsonEncode(toJson());

  factory OllamaSshTunnelConfig.decode(String value) =>
      OllamaSshTunnelConfig.fromJson(jsonDecode(value) as Map<String, dynamic>);
}

enum OllamaSshTunnelStatus { disconnected, connecting, connected, error }

class OllamaSshTunnelService {
  OllamaSshTunnelService._();

  static final OllamaSshTunnelService instance = OllamaSshTunnelService._();

  Process? _process;
  OllamaSshTunnelStatus _status = OllamaSshTunnelStatus.disconnected;
  String? _lastError;

  OllamaSshTunnelStatus get status => _status;
  String? get lastError => _lastError;
  bool get isConnected => _status == OllamaSshTunnelStatus.connected;

  static List<String> buildArguments(OllamaSshTunnelConfig config) => [
    '-N',
    '-T',
    '-o',
    'BatchMode=yes',
    '-o',
    'ExitOnForwardFailure=yes',
    '-o',
    'ServerAliveInterval=30',
    '-o',
    'ServerAliveCountMax=3',
    '-o',
    'StrictHostKeyChecking=accept-new',
    '-p',
    '${config.sshPort}',
    '-i',
    config.identityFile,
    '-L',
    '${config.localPort}:127.0.0.1:${config.remotePort}',
    '${config.user}@${config.host}',
  ];

  Future<List<String>> connect(OllamaSshTunnelConfig config) async {
    final validationError = config.validate();
    if (validationError != null) throw ArgumentError(validationError);
    final key = File(config.identityFile);
    if (!await key.exists()) {
      throw ArgumentError('SSH private-key file was not found.');
    }

    await disconnect();
    _status = OllamaSshTunnelStatus.connecting;
    _lastError = null;

    try {
      final process = await Process.start(
        'ssh',
        buildArguments(config),
        mode: ProcessStartMode.normal,
      );
      _process = process;
      unawaited(process.stdout.drain<void>());
      final stderrBuffer = StringBuffer();
      process.stderr.transform(utf8.decoder).listen((chunk) {
        if (stderrBuffer.length < 4000) stderrBuffer.write(chunk);
      });
      unawaited(
        process.exitCode.then((code) {
          if (identical(_process, process)) {
            _process = null;
            if (_status != OllamaSshTunnelStatus.disconnected) {
              _status = OllamaSshTunnelStatus.error;
              _lastError = stderrBuffer.toString().trim().isEmpty
                  ? 'SSH tunnel closed with exit code $code.'
                  : stderrBuffer.toString().trim();
            }
          }
        }),
      );

      final models = await _waitForOllama(config.baseUrl);
      _status = OllamaSshTunnelStatus.connected;
      return models;
    } catch (error) {
      _status = OllamaSshTunnelStatus.error;
      _lastError = error.toString();
      _process?.kill(ProcessSignal.sigterm);
      _process = null;
      rethrow;
    }
  }

  Future<void> disconnect() async {
    final process = _process;
    _process = null;
    _status = OllamaSshTunnelStatus.disconnected;
    _lastError = null;
    if (process == null) return;
    process.kill(ProcessSignal.sigterm);
    try {
      await process.exitCode.timeout(const Duration(seconds: 3));
    } on TimeoutException {
      process.kill(ProcessSignal.sigkill);
    }
  }

  Future<List<String>> _waitForOllama(String baseUrl) async {
    Object? lastError;
    for (var attempt = 0; attempt < 16; attempt++) {
      final process = _process;
      if (process == null) {
        throw StateError(
          _lastError ?? 'SSH tunnel closed before Ollama became reachable.',
        );
      }
      try {
        final client = HttpClient()
          ..connectionTimeout = const Duration(seconds: 2);
        try {
          final request = await client.getUrl(Uri.parse('$baseUrl/api/tags'));
          final response = await request.close().timeout(
            const Duration(seconds: 2),
          );
          final body = await utf8.decoder.bind(response).join();
          if (response.statusCode == HttpStatus.ok) {
            final data = jsonDecode(body) as Map<String, dynamic>;
            return (data['models'] as List<dynamic>? ?? const [])
                .map(
                  (model) => (model as Map<String, dynamic>)['name'] as String,
                )
                .toList();
          }
          lastError = 'Ollama returned HTTP ${response.statusCode}.';
        } finally {
          client.close(force: true);
        }
      } catch (error) {
        lastError = error;
      }
      await Future<void>.delayed(const Duration(milliseconds: 500));
    }
    throw StateError(
      'SSH connected, but Ollama did not answer at $baseUrl/api/tags: $lastError',
    );
  }
}

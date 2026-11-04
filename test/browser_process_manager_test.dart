import 'dart:io';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/browser_process_manager.dart';

class _FakeProcess implements Process {
  @override
  final int pid = 12345;

  @override
  Stream<List<int>> get stdout => const Stream.empty();

  @override
  Stream<List<int>> get stderr => const Stream.empty();

  @override
  IOSink get stdin => _FakeSink();

  @override
  Future<int> get exitCode async => 0;

  @override
  bool kill([ProcessSignal signal = ProcessSignal.sigterm]) => true;

  // unused
  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FakeSink implements IOSink {
  @override
  Encoding encoding = utf8;

  @override
  void add(List<int> data) {}

  @override
  void write(Object? obj) {}

  @override
  void writeln([Object? obj = '']) {}

  @override
  void writeAll(Iterable objects, [String separator = '']) {}

  @override
  void addError(error, [StackTrace? stackTrace]) {}

  @override
  Future addStream(Stream<List<int>> stream) => Future.value();

  @override
  Future close() => Future.value();

  @override
  Future get done => Future.value();

  @override
  void writeCharCode(int charCode) {}

  @override
  noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

void main() {
  test('startChromium uses loopback ephemeral port and safe args', () async {
    List<String>? capturedArgs;
    late String capturedExecutable;

    final manager = BrowserProcessManager(
      endpointResolver: (profileDirectory) async => BrowserEndpoint(
        port: 9222,
        websocketUri: Uri.parse('ws://127.0.0.1:9222/devtools/page/test-id'),
      ),
      starter:
          (
            String executable,
            List<String> arguments, {
            Map<String, String>? environment,
            bool runInShell = false,
          }) async {
            capturedExecutable = executable;
            capturedArgs = arguments;
            final remoteArg = arguments.firstWhere(
              (a) => a.startsWith('--remote-debugging-port='),
            );
            int.parse(remoteArg.split('=').last);
            return _FakeProcess();
          },
    );

    final proc = await manager.startChromium(
      executable: '/usr/bin/chromium',
      extraArgs: ['--foo=bar'],
    );

    expect(proc.debugPort, isNotNull);
    expect(proc.debugPort, greaterThan(0));
    expect(proc.websocketUri.host, '127.0.0.1');
    expect(proc.websocketUri.port, proc.debugPort);
    expect(proc.websocketUri.path, '/devtools/page/test-id');
    expect(capturedExecutable, '/usr/bin/chromium');
    expect(capturedArgs, isNotNull);
    expect(capturedArgs, contains('--remote-debugging-address=127.0.0.1'));
    expect(capturedArgs, contains('--remote-debugging-port=0'));
    expect(
      capturedArgs!.any((argument) => argument.startsWith('--user-data-dir=')),
      isTrue,
    );
    expect(capturedArgs, contains('--foo=bar'));
    expect(
      capturedArgs!.any((a) => a.contains(' ')),
      isFalse,
      reason: 'Arguments must not contain spaces (no shell concatenation)',
    );
  });

  test(
    'rejects unsafe executable paths and protected Chromium arguments',
    () async {
      final manager = BrowserProcessManager(
        endpointResolver: (profileDirectory) async => BrowserEndpoint(
          port: 9222,
          websocketUri: Uri.parse('ws://127.0.0.1:9222/devtools/page/test-id'),
        ),
        starter:
            (
              String executable,
              List<String> arguments, {
              Map<String, String>? environment,
              bool runInShell = false,
            }) async => _FakeProcess(),
      );

      expect(
        () => manager.startChromium(executable: 'chromium'),
        throwsArgumentError,
      );
      expect(
        () => manager.startChromium(
          executable: '/usr/bin/chromium',
          extraArgs: const ['--remote-debugging-address=0.0.0.0'],
        ),
        throwsArgumentError,
      );
      expect(
        () => manager.startChromium(
          executable: '/usr/bin/chromium',
          extraArgs: const ['--user-data-dir=/tmp/shared'],
        ),
        throwsArgumentError,
      );
      expect(
        () => manager.startChromium(
          executable: '/usr/bin/chromium',
          extraArgs: const ['--foo=bar\n--remote-debugging-address=0.0.0.0'],
        ),
        throwsArgumentError,
      );
    },
  );
}

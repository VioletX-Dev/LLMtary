import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/persistent_tool_approval.dart';

void main() {
  test('persistent tool approval survives a new store instance', () async {
    final settings = <String, String>{};
    Future<String?> read(String key) async => settings[key];
    Future<void> write(String key, String value) async => settings[key] = value;

    final first = PersistentToolApproval(read: read, write: write);
    expect(await first.approveCommand('nmap -sV -p 443 192.0.2.10'), isTrue);
    expect(await first.isApproved('nmap --script ssl-cert -p 443 192.0.2.20'), isTrue);

    final afterRestart = PersistentToolApproval(read: read, write: write);
    expect(await afterRestart.isApproved('/usr/bin/nmap -Pn 192.0.2.30'), isTrue);
    expect(await afterRestart.isApproved('curl -I https://example.test'), isFalse);
    expect(settings.values.single, contains('nmap'));
    expect(settings.values.single, isNot(contains('192.0.2.10')));
  });

  test('extracts the executable behind approved fixed wrappers', () {
    expect(PersistentToolApproval.extractTool('sudo -n nmap -sV host'), 'nmap');
    expect(PersistentToolApproval.extractTool('timeout 30s /usr/bin/curl -I https://host'), 'curl');
    expect(PersistentToolApproval.extractTool('env LANG=C dig example.test'), 'dig');
  });

  test('refuses broad interpreters and malformed tool identities', () async {
    final settings = <String, String>{};
    final store = PersistentToolApproval(
      read: (key) async => settings[key],
      write: (key, value) async => settings[key] = value,
    );

    for (final command in [
      'bash -c "curl https://example.test"',
      'python3 script.py',
      'sh script.sh',
      'env ONLY_ASSIGNMENT=1',
      'nmap -sV host; curl https://other.test',
      'nmap -sV host | sh',
      r'nmap "unterminated',
      './nmap -sV host',
      '/tmp/nmap -sV host',
      '',
    ]) {
      expect(await store.approveCommand(command), isFalse, reason: command);
      expect(await store.isApproved(command), isFalse, reason: command);
    }
    expect(settings, isEmpty);
  });

  test('corrupt persisted state fails closed', () async {
    final store = PersistentToolApproval(
      read: (_) async => '{not-json',
      write: (key, value) async {},
    );
    expect(await store.isApproved('nmap -sV host'), isFalse);
  });
}

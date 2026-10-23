import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/ollama_ssh_tunnel_service.dart';

void main() {
  test('RunPod SSH tunnel uses safe argument-list forwarding', () {
    const config = OllamaSshTunnelConfig(
      host: '203.0.113.10',
      sshPort: 22022,
      user: 'root',
      identityFile: '/home/llmtary/.ssh/runpod_ed25519',
      localPort: 11434,
      remotePort: 11434,
    );

    expect(config.validate(), isNull);
    expect(config.baseUrl, 'http://127.0.0.1:11434');
    expect(OllamaSshTunnelService.buildArguments(config), [
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
      '22022',
      '-i',
      '/home/llmtary/.ssh/runpod_ed25519',
      '-L',
      '11434:127.0.0.1:11434',
      'root@203.0.113.10',
    ]);
  });

  test('RunPod SSH command can be pasted into tunnel configuration', () {
    final config = OllamaSshTunnelConfig.fromSshCommand(
      'ssh root@203.0.113.10 -p 22022 -i "/home/llmtary/My Keys/runpod"',
    );

    expect(config.host, '203.0.113.10');
    expect(config.user, 'root');
    expect(config.sshPort, 22022);
    expect(config.identityFile, '/home/llmtary/My Keys/runpod');
    expect(
      config.toSshCommand(),
      'ssh -i "/home/llmtary/My Keys/runpod" -p 22022 root@203.0.113.10',
    );
  });

  test('RunPod SSH tunnel rejects malformed or incomplete input', () {
    expect(
      const OllamaSshTunnelConfig(
        host: '',
        sshPort: 22,
        user: 'root',
        identityFile: '/key',
      ).validate(),
      contains('host'),
    );
    expect(
      const OllamaSshTunnelConfig(
        host: 'pod.example.com',
        sshPort: 70000,
        user: 'root',
        identityFile: '/key',
      ).validate(),
      contains('port'),
    );
    expect(
      const OllamaSshTunnelConfig(
        host: 'pod.example.com',
        sshPort: 22,
        user: 'root user',
        identityFile: '/key',
      ).validate(),
      contains('user'),
    );
  });

  test('RunPod SSH tunnel configuration round-trips without key contents', () {
    const config = OllamaSshTunnelConfig(
      host: 'pod.example.com',
      sshPort: 22022,
      user: 'root',
      identityFile: '/home/llmtary/.ssh/runpod_ed25519',
    );

    final restored = OllamaSshTunnelConfig.fromJson(config.toJson());

    expect(restored.host, config.host);
    expect(restored.identityFile, config.identityFile);
    expect(config.toJson().keys, isNot(contains('privateKey')));
  });
}

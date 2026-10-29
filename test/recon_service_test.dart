import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/services/recon_service.dart';

/// Cross-platform validation tests for ReconService.
/// Tests command generation, nmap XML parsing, and graceful degradation.
void main() {
  group('ReconService command generation', () {
    test('buildNmapCommand generates valid nmap command', () {
      final cmd = ReconService.buildNmapCommand('10.0.0.1', '/tmp/out');
      expect(cmd, contains('nmap'));
      expect(cmd, contains('-sV'));
      expect(cmd, contains('-O'));
      expect(cmd, contains('-p-'));
      expect(cmd, contains('10.0.0.1'));
      expect(cmd, contains('/tmp/out/nmap_full.xml'));
    });

    test('buildUdpScanCommand targets high-value UDP ports', () {
      final cmd = ReconService.buildUdpScanCommand('10.0.0.1', '/tmp/out');
      expect(cmd, contains('-sU'));
      expect(cmd, contains('53,161,500,1194,4500'));
    });

    test('buildBannerGrabCommand uses openssl for TLS', () {
      final cmd = ReconService.buildBannerGrabCommand('10.0.0.1', 443, true);
      expect(cmd, contains('openssl'));
      expect(cmd, contains('443'));
    });

    test('buildBannerGrabCommand uses nc for non-TLS', () {
      final cmd = ReconService.buildBannerGrabCommand('10.0.0.1', 8080, false);
      expect(cmd, contains('nc'));
      expect(cmd, contains('8080'));
    });

    test('buildDnsCommands generates dig commands', () {
      final cmds = ReconService.buildDnsCommands('example.com', '/tmp/out');
      expect(cmds.length, 2);
      expect(cmds[0], contains('dig'));
      expect(cmds[0], contains('MX'));
      expect(cmds[0], contains('TXT'));
      expect(cmds[1], contains('AXFR'));
    });

    test('buildReverseDnsCommand generates dig -x', () {
      final cmd = ReconService.buildReverseDnsCommand('10.0.0.1');
      expect(cmd, contains('dig -x 10.0.0.1'));
    });

    test('buildWhatwebCommand falls back to curl', () {
      final cmd = ReconService.buildWhatwebCommand('10.0.0.1', 80, false);
      expect(cmd, contains('whatweb'));
      expect(cmd, contains('curl')); // fallback
    });

    test('buildWebProbeCommands checks high-value paths', () {
      final cmds = ReconService.buildWebProbeCommands(
        '10.0.0.1',
        80,
        false,
        '/tmp/out',
      );
      expect(cmds.length, greaterThan(5));
      expect(cmds.any((c) => c.contains('/robots.txt')), isTrue);
      expect(cmds.any((c) => c.contains('/swagger.json')), isTrue);
      expect(cmds.any((c) => c.contains('/graphql')), isTrue);
    });
  });

  group('Nmap XML parsing', () {
    test('parseNmapXml extracts open ports from valid XML', () {
      const xml = '''
<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/>
        <cpe>cpe:/a:apache:http_server:2.4.49</cpe>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
''';
      final ports = ReconService.parseNmapXml(xml);
      expect(ports.length, 2); // filtered port excluded
      expect(ports[0]['port'], 22);
      expect(ports[0]['service'], 'ssh');
      expect(ports[0]['product'], 'OpenSSH');
      expect(ports[0]['version'], '8.2p1');
      expect(ports[1]['port'], 80);
      expect(ports[1]['cpe'], 'cpe:/a:apache:http_server:2.4.49');
    });

    test('parseNmapXml handles empty XML gracefully', () {
      final ports = ReconService.parseNmapXml('');
      expect(ports, isEmpty);
    });

    test('parseNmapXml handles malformed XML gracefully', () {
      final ports = ReconService.parseNmapXml('<not valid xml');
      expect(ports, isEmpty);
    });

    test('parseNmapOs extracts OS match', () {
      const xml = '<osmatch name="Linux 5.4" accuracy="95"/>';
      final os = ReconService.parseNmapOs(xml);
      expect(os['os'], 'Linux 5.4');
      expect(os['accuracy'], '95');
    });

    test('parseNmapOs returns empty on no match', () {
      final os = ReconService.parseNmapOs('<host></host>');
      expect(os, isEmpty);
    });

    test('parseGrepableOpenHosts finds ping-blocked hosts with open ports', () {
      const output = '''
Host: 172.17.2.8 ()\tStatus: Up
Host: 172.17.2.8 ()\tPorts: 445/open/tcp//microsoft-ds///\tIgnored State: filtered (7)
Host: 172.17.2.9 ()\tStatus: Up
Host: 172.17.2.10 ()\tPorts: 445/open/tcp//microsoft-ds///\tIgnored State: filtered (7)
Host: 172.16.2.20 ()\tPorts: 1433/open/tcp//ms-sql-s///\tIgnored State: filtered (7)
''';

      expect(
        ReconService.parseGrepableOpenHosts(output),
        ['172.17.2.8', '172.17.2.10', '172.16.2.20'],
      );
    });

    test('mergeDiscoveredHosts adds TCP responders without duplicates', () {
      expect(
        ReconService.mergeDiscoveredHosts(
          ['172.16.2.5'],
          ['172.17.2.8', '172.16.2.5', '172.16.2.20'],
        ),
        ['172.16.2.5', '172.17.2.8', '172.16.2.20'],
      );
    });

    test('boundedFallbackNmapArgs limits retries and per-host runtime', () {
      final args = ReconService.boundedFallbackNmapArgs([
        '172.17.2.8',
        '172.17.2.8',
        '172.16.2.20',
      ]);

      expect(args, containsAllInOrder(['-n', '--max-retries', '1']));
      expect(args, containsAllInOrder(['--host-timeout', '15s']));
      expect(args.where((arg) => arg == '172.17.2.8').length, 1);
      expect(args.where((arg) => arg == '172.16.2.20').length, 1);
    });
  });

  group('OS and technology enrichment', () {
    test('extractOsFromBanners detects Ubuntu from SSH', () {
      final ports = [
        {
          'product': 'OpenSSH',
          'version': '8.2p1',
          'extra_info': 'Ubuntu Linux',
        },
      ];
      expect(ReconService.extractOsFromBanners(ports), contains('Ubuntu'));
    });

    test('extractOsFromBanners detects Windows from product', () {
      final ports = [
        {'product': 'Microsoft IIS httpd', 'version': '10.0', 'extra_info': ''},
      ];
      expect(ReconService.extractOsFromBanners(ports), contains('Windows'));
    });

    test('extractOsFromBanners returns empty when no OS signal', () {
      final ports = [
        {'product': 'nginx', 'version': '1.18', 'extra_info': ''},
      ];
      expect(ReconService.extractOsFromBanners(ports), isEmpty);
    });

    test('parseSmbBanner extracts OS and domain', () {
      const output =
          'OS: Windows 10 Pro 19041\nDomain: CORP\nSigning: disabled';
      final result = ReconService.parseSmbBanner(output);
      expect(result['os'], contains('Windows'));
      expect(result['domain'], 'CORP');
      expect(result['signing'], 'disabled');
    });

    test('parseCertHostnames extracts CN and SANs', () {
      const output =
          'subject=CN = www.example.com\nDNS:www.example.com, DNS:api.example.com, DNS:mail.example.com';
      final hostnames = ReconService.parseCertHostnames(output);
      expect(hostnames, contains('www.example.com'));
      expect(hostnames, contains('api.example.com'));
      expect(hostnames, contains('mail.example.com'));
    });

    test('extractEmailSecurityRecords finds SPF and DMARC', () {
      const txt = '''
example.com. TXT "v=spf1 include:spf.protection.outlook.com ~all"
_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
''';
      final records = ReconService.extractEmailSecurityRecords(txt);
      expect(records['spf'], contains('v=spf1'));
      expect(records['dmarc'], contains('v=DMARC1'));
    });
  });

  group('WAF detection', () {
    test('detectWafFromHeaders identifies Cloudflare', () {
      expect(ReconService.detectWafFromHeaders('cf-ray: abc123'), 'Cloudflare');
    });

    test('detectWafFromHeaders identifies Akamai', () {
      expect(
        ReconService.detectWafFromHeaders('X-Akamai-Transformed: 9'),
        'Akamai',
      );
    });

    test('detectWafFromHeaders returns null for no WAF', () {
      expect(ReconService.detectWafFromHeaders('Server: nginx'), isNull);
    });
  });

  group('ReconResult model', () {
    test('mergeInto enriches existing device JSON', () {
      final result = ReconResult(
        ip: '10.0.0.5',
        hostname: 'testhost',
        os: 'Linux',
        openPorts: [
          {'port': 22, 'service': 'ssh'},
        ],
        hostnames: ['testhost.local'],
      );
      final existing = <String, dynamic>{
        'device': <String, dynamic>{'ip_address': '10.0.0.5'},
        'open_ports': <dynamic>[
          <String, dynamic>{'port': 80, 'service': 'http'},
        ],
        'dns_findings': <dynamic>[],
      };
      final merged = result.mergeInto(existing);
      final ports = (merged['open_ports'] as List);
      expect(ports.length, 2);
      expect(merged['device']['os'], 'Linux');
      expect(merged['hostnames'], contains('testhost.local'));
    });

    test('toDeviceJson creates standalone JSON', () {
      final result = ReconResult(ip: '10.0.0.1', os: 'Windows');
      final json = result.toDeviceJson();
      expect(json['device']['ip_address'], '10.0.0.1');
      expect(json['device']['os'], 'Windows');
    });
  });

  group('Target input parsing', () {
    test('parseTargetInput handles CIDR /24', () {
      final targets = ReconService.parseTargetInput('192.168.1.0/24');
      expect(targets.length, 254);
      expect(targets.first, '192.168.1.1');
      expect(targets.last, '192.168.1.254');
    });

    test('parseTargetInput handles comma-separated', () {
      final targets = ReconService.parseTargetInput(
        '10.0.0.1, 10.0.0.2, 10.0.0.3',
      );
      expect(targets.length, 3);
    });

    test('parseTargetInput expands every CIDR in a multiline scope', () {
      final targets = ReconService.parseTargetInput(
        '172.17.2.0/24\n172.16.2.0/24',
      );

      expect(targets.length, 508);
      expect(targets.first, '172.17.2.1');
      expect(targets[253], '172.17.2.254');
      expect(targets[254], '172.16.2.1');
      expect(targets.last, '172.16.2.254');
      expect(targets, isNot(contains('172.17.2.0/24')));
      expect(targets, isNot(contains('172.16.2.0/24')));
    });

    test('parseTargetInput deduplicates explicit hosts already in CIDR scope', () {
      final targets = ReconService.parseTargetInput(
        '172.17.2.0/24\n'
        '172.16.2.0/24\n'
        '172.17.2.8\n'
        '172.17.2.10\n'
        '172.17.2.11\n'
        '172.16.2.5\n'
        '172.16.2.20',
      );

      expect(targets.length, 508);
      expect(targets.where((target) => target == '172.16.2.5').length, 1);
      expect(targets.where((target) => target == '172.17.2.8').length, 1);
    });

    test('parseTargetInput handles single target', () {
      final targets = ReconService.parseTargetInput('example.com');
      expect(targets, ['example.com']);
    });
  });

  group('Recon command output bounds', () {
    test(
      'prepareCommandOutput caps oversized output and preserves evidence',
      () {
        final oversized = '${'A' * 300000}TAIL-EVIDENCE';

        final bounded = ReconService.prepareCommandOutput(oversized);

        expect(
          bounded.length,
          lessThanOrEqualTo(ReconService.maxParsedOutputChars),
        );
        expect(bounded, startsWith('A' * 100));
        expect(bounded, contains('OUTPUT TRUNCATED'));
        expect(bounded, endsWith('TAIL-EVIDENCE'));
      },
    );

    test(
      'detectMissingTool ignores giant lines and finds bounded error lines',
      () {
        final output = '${'A' * 300000}\ncurl: command not found';

        expect(ReconService.detectMissingTool(output), 'curl');
      },
    );
  });
}

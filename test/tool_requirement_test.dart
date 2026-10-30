import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:llmtary/models/llm_provider.dart';
import 'package:llmtary/models/llm_settings.dart';
import 'package:llmtary/services/command_executor.dart';
import 'package:llmtary/services/llm_service.dart';

void main() {
  final settings = LLMSettings(
    provider: LLMProvider.none,
    modelName: '',
    temperature: 0,
    maxTokens: 100,
    timeoutSeconds: 5,
  );

  test(
    'Python standard-library modules are detected without a fake binary',
    () async {
      final exists = await CommandExecutor.checkToolExists(
        'urllib',
        settings,
        LLMService(enforceProjectBudget: false),
      );

      expect(exists, isTrue);
    },
  );

  test('managed apt packages use deterministic package mappings', () {
    expect(CommandExecutor.getManagedAptPackage('smbclient'), 'smbclient');
    expect(
      CommandExecutor.getManagedAptPackage('impacket'),
      'python3-impacket',
    );
    expect(
      CommandExecutor.getManagedAptPackage('requests'),
      'python3-requests',
    );
    expect(CommandExecutor.getManagedAptPackage('urllib'), isNull);
    expect(CommandExecutor.getManagedAptPackage('unknown-tool'), isNull);
    expect(
      CommandExecutor.getManagedAptPackage('rdesktop'),
      'freerdp3-x11',
    );
  });

  test('managed installer supports audited apt and source tools', () {
    expect(CommandExecutor.canUseManagedInstaller('tshark'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('ldapsearch'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('crackmapexec'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('netexec'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('searchsploit'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('exploitdb'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('evil-winrm'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('rdesktop'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('xfreerdp'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('xfreerdp3'), isTrue);
  });

  test('audited Evil-WinRM uses the managed installer', () {
    expect(
      CommandExecutor.shouldAttemptManagedInstall('apt-get', 'snmpwalk'),
      isTrue,
    );
    expect(
      CommandExecutor.shouldAttemptManagedInstall('apt-get', 'evil-winrm'),
      isTrue,
    );
    expect(
      CommandExecutor.getInstallDisplayCommand('apt-get', 'evil-winrm'),
      '/opt/LLMtary/libexec/llmtary-tool-installer evil-winrm',
    );
  });

  test('unknown tools remain blocked from root-managed installation', () {
    expect(CommandExecutor.canUseManagedInstaller('unreviewed-tool'), isFalse);
    expect(
      CommandExecutor.getInstallDisplayCommand('apt-get', 'unreviewed-tool'),
      'managed installer blocked: unreviewed-tool',
    );
  });

  test('Evil-WinRM installer pins and verifies the audited gem', () {
    final installer = File('linux/llmtary-tool-installer').readAsStringSync();
    expect(installer, contains("version='4.1'"));
    expect(
      installer,
      contains("sha256='0bfa3080129c664de4a70f01477742dddf7907ade5c502afae38269e28c4f991'"),
    );
    expect(installer, contains('/usr/bin/sha256sum -c -'));
    expect(installer, contains('/usr/sbin/runuser -u llmtary'));
    expect(installer, contains('libreadline-dev libncurses-dev'));
  });

  test('legacy RDP requirement resolves to maintained FreeRDP 3', () {
    expect(CommandExecutor.getToolBinary('rdesktop'), 'xfreerdp3');
    expect(CommandExecutor.getToolBinary('xfreerdp'), 'xfreerdp3');
    expect(CommandExecutor.getToolBinary('xfreerdp3'), 'xfreerdp3');
    expect(
      CommandExecutor.getInstallDisplayCommand('apt-get', 'rdesktop'),
      'apt-get install freerdp3-x11',
    );
    expect(
      CommandExecutor.getToolHints(['rdesktop']),
      contains('xfreerdp3 /v:TARGET'),
    );
  });

  test('source-managed tools are not misreported as apt packages', () {
    expect(CommandExecutor.getManagedAptPackage('crackmapexec'), isNull);
    expect(CommandExecutor.getManagedAptPackage('searchsploit'), isNull);
    expect(
      CommandExecutor.getInstallDisplayCommand('apt-get', 'crackmapexec'),
      '/opt/LLMtary/libexec/llmtary-tool-installer crackmapexec',
    );
    expect(
      CommandExecutor.getInstallDisplayCommand('apt-get', 'searchsploit'),
      '/opt/LLMtary/libexec/llmtary-tool-installer searchsploit',
    );
  });

  test('Linux managed appliances do not collect an administrator password', () {
    expect(Platform.isLinux, isTrue);
    expect(CommandExecutor.sessionAdministratorPasswordRequired, isFalse);
  });
}

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
  });

  test('managed installer supports audited apt and source tools', () {
    expect(CommandExecutor.canUseManagedInstaller('tshark'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('ldapsearch'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('crackmapexec'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('netexec'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('searchsploit'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('exploitdb'), isTrue);
    expect(CommandExecutor.canUseManagedInstaller('evil-winrm'), isFalse);
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

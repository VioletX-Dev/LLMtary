import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../constants/app_constants.dart';
import '../database/database_helper.dart';
import '../services/ollama_ssh_tunnel_service.dart';
import '../utils/file_dialog.dart';

class OllamaSshTunnelDialog extends StatefulWidget {
  final OllamaSshTunnelService service;

  const OllamaSshTunnelDialog({
    super.key,
    this.service = const _DefaultTunnelService(),
  });

  @override
  State<OllamaSshTunnelDialog> createState() => _OllamaSshTunnelDialogState();
}

// Keeps the public widget constructor const while delegating to the singleton.
class _DefaultTunnelService implements OllamaSshTunnelService {
  const _DefaultTunnelService();

  OllamaSshTunnelService get _delegate => OllamaSshTunnelService.instance;

  @override
  bool get isConnected => _delegate.isConnected;

  @override
  String? get lastError => _delegate.lastError;

  @override
  OllamaSshTunnelStatus get status => _delegate.status;

  @override
  Future<List<String>> connect(OllamaSshTunnelConfig config) =>
      _delegate.connect(config);

  @override
  Future<void> disconnect() => _delegate.disconnect();
}

class _OllamaSshTunnelDialogState extends State<OllamaSshTunnelDialog> {
  final _sshCommand = TextEditingController();
  final _host = TextEditingController();
  final _sshPort = TextEditingController(text: '22');
  final _user = TextEditingController(text: 'root');
  final _identityFile = TextEditingController();
  final _localPort = TextEditingController(text: '11434');
  bool _working = false;
  String? _message;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final saved = await DatabaseHelper.getSetting(SettingsKeys.ollamaSshTunnel);
    if (saved == null || !mounted) return;
    try {
      final config = OllamaSshTunnelConfig.decode(saved);
      _host.text = config.host;
      _sshPort.text = '${config.sshPort}';
      _user.text = config.user;
      _identityFile.text = config.identityFile;
      _localPort.text = '${config.localPort}';
      setState(() {});
    } catch (_) {
      // Ignore an obsolete or manually damaged saved tunnel configuration.
    }
  }

  @override
  void dispose() {
    _sshCommand.dispose();
    _host.dispose();
    _sshPort.dispose();
    _user.dispose();
    _identityFile.dispose();
    _localPort.dispose();
    super.dispose();
  }

  OllamaSshTunnelConfig _config() => OllamaSshTunnelConfig(
    host: _host.text.trim(),
    sshPort: int.tryParse(_sshPort.text.trim()) ?? 0,
    user: _user.text.trim(),
    identityFile: _identityFile.text.trim(),
    localPort: int.tryParse(_localPort.text.trim()) ?? 0,
  );

  Future<void> _pickKey() async {
    final result = await FileDialog.pickFiles(
      dialogTitle: 'Select RunPod SSH private key',
    );
    final path = result?.files.single.path;
    if (path != null && mounted) setState(() => _identityFile.text = path);
  }

  void _applySshCommand() {
    try {
      final config = OllamaSshTunnelConfig.fromSshCommand(_sshCommand.text);
      setState(() {
        _host.text = config.host;
        _sshPort.text = '${config.sshPort}';
        _user.text = config.user;
        if (config.identityFile.isNotEmpty) {
          _identityFile.text = config.identityFile;
        }
        _message = 'SSH command imported. Confirm the key path, then connect.';
      });
    } catch (error) {
      setState(() => _message = error.toString());
    }
  }

  Future<void> _connect() async {
    final config = _config();
    final validation = config.validate();
    if (validation != null) {
      setState(() => _message = validation);
      return;
    }
    setState(() {
      _working = true;
      _message = 'Opening SSH tunnel and checking Ollama...';
    });
    try {
      final models = await widget.service.connect(config);
      await DatabaseHelper.saveSetting(
        SettingsKeys.ollamaSshTunnel,
        config.encode(),
      );
      if (!mounted) return;
      setState(() {
        _working = false;
        _message = models.isEmpty
            ? 'Connected. Ollama answered, but no models are installed.'
            : 'Connected. Models: ${models.join(', ')}';
      });
      Navigator.of(context).pop(config);
    } catch (error) {
      if (!mounted) return;
      setState(() {
        _working = false;
        _message = error.toString();
      });
    }
  }

  Future<void> _disconnect() async {
    setState(() => _working = true);
    await widget.service.disconnect();
    if (!mounted) return;
    setState(() {
      _working = false;
      _message = 'SSH tunnel disconnected.';
    });
  }

  InputDecoration _decoration(String hint) => InputDecoration(
    hintText: hint,
    filled: true,
    fillColor: const Color(0xFF0A0E27),
    border: const OutlineInputBorder(),
  );

  @override
  Widget build(BuildContext context) {
    final currentConfig = _config();
    final generatedSshCommand =
        currentConfig.host.isNotEmpty && currentConfig.identityFile.isNotEmpty
        ? currentConfig.toSshCommand()
        : 'Enter or import the RunPod connection values to generate the exact SSH command.';
    return AlertDialog(
      backgroundColor: const Color(0xFF1A1F3A),
      title: const Row(
        children: [
          Icon(Icons.vpn_key, color: Color(0xFF00F5FF)),
          SizedBox(width: 8),
          Text('Connect RunPod Ollama', style: TextStyle(color: Colors.white)),
        ],
      ),
      content: SizedBox(
        width: 620,
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Paste the SSH values from RunPod’s Connect panel. LLMtary opens the encrypted tunnel and verifies /api/tags automatically.',
                style: TextStyle(color: Colors.white70),
              ),
              const SizedBox(height: 10),
              const Text(
                'TEARDOWN: Stopping the SSH tunnel does not stop the RunPod pod. When the test ends, disconnect here and stop or terminate the pod in RunPod to end GPU billing. Keep the network volume if you want the downloaded model to persist.',
                style: TextStyle(
                  color: Colors.orangeAccent,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                key: const Key('runpod-ssh-command'),
                controller: _sshCommand,
                style: const TextStyle(color: Colors.white),
                decoration: _decoration('Paste RunPod SSH command').copyWith(
                  suffixIcon: IconButton(
                    tooltip: 'Import SSH command',
                    onPressed: _working ? null : _applySshCommand,
                    icon: const Icon(Icons.content_paste_go),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(
                    flex: 3,
                    child: TextField(
                      key: const Key('runpod-host'),
                      controller: _host,
                      onChanged: (_) => setState(() {}),
                      style: const TextStyle(color: Colors.white),
                      decoration: _decoration('Pod IP or SSH host'),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      key: const Key('runpod-ssh-port'),
                      controller: _sshPort,
                      onChanged: (_) => setState(() {}),
                      keyboardType: TextInputType.number,
                      style: const TextStyle(color: Colors.white),
                      decoration: _decoration('SSH port'),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: TextField(
                      key: const Key('runpod-user'),
                      controller: _user,
                      onChanged: (_) => setState(() {}),
                      style: const TextStyle(color: Colors.white),
                      decoration: _decoration('User'),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              TextField(
                key: const Key('runpod-key-path'),
                controller: _identityFile,
                readOnly: true,
                style: const TextStyle(color: Colors.white),
                decoration: _decoration('SSH private-key file').copyWith(
                  suffixIcon: IconButton(
                    tooltip: 'Choose key file',
                    onPressed: _working ? null : _pickKey,
                    icon: const Icon(Icons.folder_open),
                  ),
                ),
              ),
              const SizedBox(height: 12),
              SizedBox(
                width: 180,
                child: TextField(
                  key: const Key('runpod-local-port'),
                  controller: _localPort,
                  keyboardType: TextInputType.number,
                  style: const TextStyle(color: Colors.white),
                  decoration: _decoration('Local port'),
                ),
              ),
              const SizedBox(height: 16),
              const Text(
                'LLMtary SSH command',
                style: TextStyle(
                  color: Color(0xFF00F5FF),
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 6),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: const Color(0xFF0A0E27),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: Colors.white12),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: SelectableText(
                        generatedSshCommand,
                        key: const Key('llmtary-ssh-command-output'),
                        style: const TextStyle(
                          color: Colors.white70,
                          fontFamily: 'monospace',
                          fontSize: 12,
                        ),
                      ),
                    ),
                    IconButton(
                      key: const Key('copy-llmtary-ssh-command'),
                      tooltip: 'Copy SSH command for LLMtary',
                      onPressed:
                          currentConfig.host.isEmpty || currentConfig.identityFile.isEmpty
                          ? null
                          : () async {
                              await Clipboard.setData(
                                ClipboardData(text: generatedSshCommand),
                              );
                              if (mounted) {
                                setState(() => _message =
                                    'SSH command copied. Paste it into LLMtary on the appliance that has this key path.');
                              }
                            },
                      icon: const Icon(Icons.copy, size: 18),
                    ),
                  ],
                ),
              ),
              if (_message != null) ...[
                const SizedBox(height: 12),
                SelectableText(
                  _message!,
                  style: TextStyle(
                    color: widget.service.isConnected
                        ? const Color(0xFF00FF88)
                        : Colors.orangeAccent,
                  ),
                ),
              ],
              if (_working) ...[
                const SizedBox(height: 12),
                const LinearProgressIndicator(color: Color(0xFF00F5FF)),
              ],
            ],
          ),
        ),
      ),
      actions: [
        if (widget.service.isConnected)
          TextButton(
            onPressed: _working ? null : _disconnect,
            child: const Text('DISCONNECT'),
          ),
        TextButton(
          onPressed: _working ? null : () => Navigator.of(context).pop(),
          child: const Text('CANCEL'),
        ),
        FilledButton.icon(
          key: const Key('connect-runpod-ollama'),
          onPressed: _working ? null : _connect,
          icon: const Icon(Icons.link),
          label: const Text('CONNECT & VERIFY'),
        ),
      ],
    );
  }
}
